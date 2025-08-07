from __future__ import annotations

import threading
import time
import random
import re
import logging
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ed25519  # For future signing; not used yet
import signal
from datetime import datetime
from typing import Optional, Tuple

# pyobjc imports with type: ignore to suppress Pylance errors
import objc  # type: ignore
from Foundation import NSObject, NSData, NSRunLoop, NSDate  # type: ignore
from CoreBluetooth import (CBCentralManager, CBPeripheral, CBPeripheralManager, CBManagerStatePoweredOn,  # type: ignore
                          CBUUID, CBMutableCharacteristic, CBMutableService, CBMutableDescriptor, CBCharacteristicPropertyRead,  # type: ignore
                          CBCharacteristicPropertyWrite, CBCharacteristicPropertyNotify, CBAttributePermissionsReadable,  # type: ignore
                          CBAttributePermissionsWriteable, CBATTErrorSuccess, CBAdvertisementDataServiceUUIDsKey, CBAdvertisementDataLocalNameKey)  # type: ignore
from PyObjCTools import AppHelper


# ----------------------------
# Logging
# ----------------------------

LOG_FORMAT = (
    "[%(asctime)s] "
    "[%(levelname)s] "
    "- %(message)s"
)
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)


# ----------------------------
# Constants / Helpers
# ----------------------------

UUID_RE = re.compile(br"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
HEXSET = set(b"0123456789abcdefABCDEF")

SERVICE_UUID_STR = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHAR_UUID_STR   = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
DESC_UUID_STR   = "00002902-0000-1000-8000-00805f9b34fb"

SERVICE_UUID = CBUUID.UUIDWithString_(SERVICE_UUID_STR)
CHAR_UUID    = CBUUID.UUIDWithString_(CHAR_UUID_STR)

MY_PEER_ID   = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))  # 16 hex chars
MY_NICKNAME  = b"MyMacPeer"  # Your nickname as bytes

BROADCAST_RECIPIENT = b'\xff' * 8  # SpecialRecipients.BROADCAST

connected_identifiers = set()  # To avoid multiple connections to the same peripheral


def peripheral_to_dict(peripheral):
    return {
        "ID": peripheral.identifier,
        "state": peripheral.state(),
        "name": peripheral.name() or "Unknown"
    }


def peripheral_to_str(peripheral: CBPeripheral):
    identifier = peripheral.identifier().UUIDString()
    state = peripheral.state()
    name = peripheral.name() or "Unknown"
    return f"<{identifier}, {state}, {name}>"


def _plausible_epoch_ms(ms: int) -> bool:
    """2015-01-01 .. 2035-01-01 in ms."""
    return 1420070400000 <= ms <= 2051222400000


def _read_len_prefixed_str(buf: bytes, pos: int, prefer_one_byte: bool = True, one_byte_max: int = 64) -> Tuple[str, int]:
    """Reads a UTF-8 string with either 1-byte or 2-byte big-endian length prefix."""
    if pos >= len(buf):
        raise ValueError("pos out of range")

    # Try 1-byte length if we prefer it and it looks plausible
    if prefer_one_byte:
        L1 = buf[pos]
        if L1 <= one_byte_max and pos + 1 + L1 <= len(buf):
            try:
                s = buf[pos + 1: pos + 1 + L1].decode('utf-8')
                return s, pos + 1 + L1
            except UnicodeDecodeError:
                pass  # fall through

    # Fallback: 2-byte length
    if pos + 2 <= len(buf):
        L2 = int.from_bytes(buf[pos:pos + 2], 'big')
        if pos + 2 + L2 <= len(buf):
            s = buf[pos + 2: pos + 2 + L2].decode('utf-8')
            return s, pos + 2 + L2

    raise ValueError(f"bad length-prefixed string at {pos}")


def _looks_hex_ascii(b: bytes) -> bool:
    return len(b) > 0 and all(ch in HEXSET for ch in b)


# ----------------------------
# Fragment reassembler
# ----------------------------

class FragmentReassembler:
    """
    Minimal handler for message fragments.
    Finds a 1-byte length (0x24) followed by a 36-char UUID, and returns the rest as inner payload.
    """
    def _find_inner_start(self, data: bytes) -> Optional[Tuple[int, str]]:
        for i in range(0, max(0, len(data) - 37)):
            L = data[i]
            if L == 36 and i + 1 + 36 <= len(data):
                candidate = data[i + 1: i + 1 + 36]
                if UUID_RE.fullmatch(candidate):
                    return (i + 1 + 36, candidate.decode())
        return None

    def add_fragment(self, frag_body: bytes) -> Tuple[Optional[bytes], Optional[str]]:
        """Returns (inner_payload, message_uuid) if found."""
        res = self._find_inner_start(frag_body)
        if not res:
            return (None, None)
        start_after_uuid, uuid_str = res
        # For now, we assume the rest of the body is the complete inner message payload
        return (frag_body[start_after_uuid:], uuid_str)


reassembler = FragmentReassembler()


# ----------------------------
# Packet
# ----------------------------

class BitchatPacket:
    def __init__(self, version=1, packet_type=1, senderID=b'\0' * 8, recipientID=BROADCAST_RECIPIENT,
                 timestamp=0, payload=b'', signature=b'', ttl=7):
        self.version    = version
        self.packet_type = packet_type
        self.senderID   = senderID
        self.recipientID = recipientID
        self.timestamp  = timestamp
        self.payload    = payload
        self.signature  = signature
        self.ttl        = ttl

    def to_binary(self):
        data = b''
        data += self.version.to_bytes(1, 'big')
        data += self.packet_type.to_bytes(1, 'big')
        data += self.senderID
        data += self.recipientID
        data += self.timestamp.to_bytes(8, 'big')
        data += self.ttl.to_bytes(1, 'big')
        data += len(self.payload).to_bytes(2, 'big')
        data += self.payload
        data += len(self.signature).to_bytes(2, 'big')
        data += self.signature
        return data

    @classmethod
    def from_binary(cls, data):
        try:
            pos = 0
            version = int.from_bytes(data[pos:pos + 1], 'big'); pos += 1
            packet_type = int.from_bytes(data[pos:pos + 1], 'big'); pos += 1
            logging.info(f"Parsing: version={version}, type={packet_type} at pos={pos}")

            senderID = data[pos:pos + 8]; pos += 8
            recipientID = data[pos:pos + 8]; pos += 8

            outer_header_field = data[pos:pos + 8]; pos += 8
            ts_guess = int.from_bytes(outer_header_field, 'big')

            if packet_type == 4:  # FRAGMENT
                logging.info("FRAGMENT packet detected. Passing to reassembler.")
                fragment_body = data[pos:]
                payload, uuid_str = reassembler.add_fragment(fragment_body)
                if payload is None:
                    logging.error("FRAGMENT: could not locate inner message payload.")
                    return None
                pkt_ts = ts_guess if _plausible_epoch_ms(ts_guess) else 0
                logging.info(f"FRAGMENT: Reassembled inner payload for message UUID: {uuid_str}")
                return cls(version, packet_type, senderID, recipientID, pkt_ts, payload, b"", ttl=0)

            # Non-fragment path
            ttl = int.from_bytes(data[pos:pos + 1], 'big'); pos += 1
            payload_len = int.from_bytes(data[pos:pos + 2], 'big'); pos += 2
            if pos + payload_len > len(data):
                logging.error("Parsing failed: payload_len exceeds data length")
                return None
            payload = data[pos:pos + payload_len]; pos += payload_len

            sig_len = int.from_bytes(data[pos:pos + 2], 'big'); pos += 2
            if pos + sig_len > len(data):
                logging.error("Parsing failed: sig_len exceeds data length")
                return None
            signature = data[pos:pos + sig_len]

            timestamp = ts_guess
            return cls(version, packet_type, senderID, recipientID, timestamp, payload, signature, ttl)

        except Exception as e:
            logging.error(f"Error in BitchatPacket.from_binary: {str(e)}")
            return None


# ----------------------------
# Message decoding (inner payload)
# ----------------------------

def decode_bitchat_message(payload: bytes) -> dict:
    """
    Decodes the observed message payload layout:
        sender(str, 1B len) →
        content(str, 2B len preferred) →
        optional senderPeerID (hex-ascii, 1B len 8..32) →
        optional binary block (1B len)
    Returns dict with keys present among: sender, content, senderPeerID.
    """
    pos = 0

    # 1) sender (compact)
    sender, pos = _read_len_prefixed_str(payload, pos, prefer_one_byte=True)

    # 2) content (prefer 2-byte; messages can be longer)
    content, pos = _read_len_prefixed_str(payload, pos, prefer_one_byte=False)

    # 3) optional senderPeerID (hex)
    senderPeerID = None
    if pos < len(payload):
        L = payload[pos]
        if 8 <= L <= 32 and pos + 1 + L <= len(payload):
            candidate = payload[pos + 1: pos + 1 + L]
            if _looks_hex_ascii(candidate):
                senderPeerID, pos = _read_len_prefixed_str(payload, pos, prefer_one_byte=True)

    # 4) optional binary block (e.g., signature/proof) — skip safely if present
    if pos < len(payload):
        L = payload[pos]
        if L >= 1 and pos + 1 + L <= len(payload):
            pos += 1 + L  # skip blob

    if pos != len(payload):
        logging.debug(f"Note: {len(payload) - pos} trailing bytes after message payload")

    result = {"sender": sender, "content": content}
    if senderPeerID:
        result["senderPeerID"] = senderPeerID
    return result


def log_decoded_message(payload: bytes, outer_timestamp_ms: Optional[int] = None):
    try:
        info = decode_bitchat_message(payload)
        logging.info("--- SUCCESSFULLY DECODED MESSAGE ---")
        logging.info(f"  Sender: {info.get('sender')}")
        logging.info(f"  Content: {info.get('content')}")
        spid = info.get('senderPeerID')
        if spid:
            logging.info(f"  Sender PeerID: {spid}")
        if outer_timestamp_ms and _plausible_epoch_ms(outer_timestamp_ms):
            logging.info(f"  Timestamp: {datetime.fromtimestamp(outer_timestamp_ms/1000)}")
        logging.info("------------------------------------")
    except Exception as e:
        logging.error(f"Error parsing MESSAGE payload: {str(e)}")
        logging.error(f"Failed on payload: {hexlify(payload).decode()}")


# ----------------------------
# Delegates
# ----------------------------

class PeripheralDelegate(NSObject):
    def init(self):
        self = objc.super(PeripheralDelegate, self).init()
        self.manager = CBPeripheralManager.alloc().initWithDelegate_queue_(self, None)
        self.characteristic = None
        return self

    def peripheralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            self.characteristic = CBMutableCharacteristic.alloc().initWithType_properties_value_permissions_(
                CHAR_UUID,
                CBCharacteristicPropertyRead | CBCharacteristicPropertyWrite | CBCharacteristicPropertyNotify,
                None,
                CBAttributePermissionsReadable | CBAttributePermissionsWriteable
            )
            descriptor = CBMutableDescriptor.alloc().initWithType_value_(CBUUID.UUIDWithString_(DESC_UUID_STR), None)
            self.characteristic.setDescriptors_([descriptor])
            service = CBMutableService.alloc().initWithType_primary_(SERVICE_UUID, True)
            service.setCharacteristics_([self.characteristic])
            manager.addService_(service)

    def peripheralManager_didAddService_error_(self, manager, service, error):
        if error:
            logging.error(f"Error adding service: {error.localizedDescription()}")
            return
        logging.info("Service added; starting advertising")
        adv_data = {CBAdvertisementDataLocalNameKey: "BitChatMac", CBAdvertisementDataServiceUUIDsKey: [SERVICE_UUID]}
        manager.startAdvertising_(adv_data)

    def peripheralManager_didReceiveWriteRequests_(self, manager, requests):
        try:
            for request in requests:
                data = request.value().bytes().tobytes()
                logging.info(f"Received write: {hexlify(data).decode()}")
                packet = BitchatPacket.from_binary(data)
                if packet:
                    hex_sender = hexlify(packet.senderID).decode()
                    logging.info(f"Parsed packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}")
                    if packet.packet_type == 1:  # ANNOUNCE
                        nickname = packet.payload.decode('utf-8', 'ignore')
                        logging.info(f"ANNOUNCE from peerID {hex_sender} with nickname {nickname}")
                    elif packet.packet_type == 2:  # MESSAGE
                        log_decoded_message(packet.payload, packet.timestamp)
                    elif packet.packet_type == 4:  # FRAGMENT (now with reassembled payload)
                        logging.info("Received FRAGMENT, parsing inner message...")
                        log_decoded_message(packet.payload, packet.timestamp)
                    elif packet.packet_type == 3:  # NOISE_IDENTITY_ANNOUNCE
                        logging.info("Received NOISE_IDENTITY_ANNOUNCE - (handshake logic not implemented)")
                    else:
                        logging.warning(f"Received unhandled packet type: {packet.packet_type}")
                else:
                    logging.error("Failed to parse received packet")
                manager.respondToRequest_withResult_(request, CBATTErrorSuccess)
                if self.characteristic:
                    manager.updateValue_forCharacteristic_onSubscribedCentrals_(
                        NSData.dataWithBytes_length_(data, len(data)), self.characteristic, None
                    )
        except Exception as e:
            logging.error(f"Error in write handler: {str(e)}")

    def peripheralManager_central_didSubscribeToCharacteristic_(self, manager, central, characteristic):
        logging.info("Central subscribed")


class CentralDelegate(NSObject):
    def init(self):
        self = objc.super(CentralDelegate, self).init()
        self.manager = CBCentralManager.alloc().initWithDelegate_queue_(self, None)
        self.peripheral = None
        self.characteristic = None
        self.known_peripherals = {}
        return self

    def centralManagerDidUpdateState_(self, manager):
        logging.info(f"Central manager state updated: {manager.state()}")
        if manager.state() == CBManagerStatePoweredOn:
            logging.info("Scanning for peripherals with services...")
            self.manager.scanForPeripheralsWithServices_options_([], None)
        else:
            logging.warning(f"Central state not powered on: {manager.state()}")

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, manager, peripheral, adv_data, rssi):
        identifier = peripheral.identifier().UUIDString()
        if identifier in connected_identifiers:
            return
        if identifier not in self.known_peripherals.keys():
            self.known_peripherals[identifier] = peripheral_to_dict(peripheral)
            self.known_peripherals[identifier]["state"] = "discovered"
            if self.known_peripherals[identifier]['name'] == "Blake iPhone":
                logging.info(f"{peripheral_to_str(peripheral)} - Discovered peripheral")

        if identifier in self.known_peripherals.keys() and self.known_peripherals[identifier]["state"] == "discovered":
            if SERVICE_UUID in adv_data.get(CBAdvertisementDataServiceUUIDsKey, []):
                logging.info(f"{peripheral_to_str(peripheral)} - Connecting to peripheral with services (RSSI: {rssi})")
                self.known_peripherals[identifier]["state"] = "connecting"
                self.peripheral = peripheral
                manager.connectPeripheral_options_(peripheral, None)

    def centralManager_didConnectPeripheral_(self, manager, peripheral):
        identifier = peripheral.identifier().UUIDString()
        if identifier in self.known_peripherals.keys() and self.known_peripherals[identifier]["state"] != "connected":
            logging.info(f"{peripheral_to_str(peripheral)} - Connected to peripheral")
            self.known_peripherals[identifier]["state"] = "connected"
            connected_identifiers.add(identifier)
            peripheral.setDelegate_(self)
            logging.info(f"{peripheral_to_str(peripheral)} - Discovering peripheral's services")
            peripheral.discoverServices_([])

    def centralManager_didFailToConnectPeripheral_error_(self, manager, peripheral, error):
        identifier = peripheral.identifier().UUIDString()
        logging.error(f"{peripheral_to_str(peripheral)} - Failed to connect to peripheral - Error: {error.localizedDescription() if error else 'Unknown error'}")
        self.known_peripherals[identifier]["state"] = "failed to connect"

    def centralManager_didDisconnectPeripheral_error_(self, manager, peripheral, error):
        identifier = peripheral.identifier().UUIDString()
        self.known_peripherals[identifier]["state"] = "disconnected"
        if identifier in connected_identifiers:
            connected_identifiers.remove(identifier)
        logging.info(f"{peripheral_to_str(peripheral)} - Disconnected from peripheral: {error.localizedDescription() if error else 'Unknown error'}")
        self.manager.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)

    def peripheral_didDiscoverServices_(self, peripheral, error):
        if error:
            logging.error(f"Error discovering services: {error.localizedDescription()}")
            return
        services = peripheral.services()
        if not services:
            logging.info("{peripheral_to_str(peripheral)} - No services discovered - disconnecting")
            peripheral.delegate().manager.cancelPeripheralConnection_(peripheral)
            return
        service_uuids = [s.UUID().UUIDString() for s in services]
        logging.info(f"{peripheral_to_str(peripheral)} - Discovered {len(services)} services: {service_uuids}")
        service = next((s for s in services if s.UUID() == SERVICE_UUID), None)
        if not service:
            logging.info(f"{peripheral_to_str(peripheral)} - BitChat service not found - disconnecting!")
            peripheral.delegate().manager.cancelPeripheralConnection_(peripheral)
            return
        logging.info(f"{peripheral_to_str(peripheral)} - BITCHAT SERVICE FOUND - Discovering service characteristics...")
        peripheral.discoverCharacteristics_forService_([CHAR_UUID], service)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        if error:
            logging.error(f"{peripheral_to_str(peripheral)} - Error discovering characteristics: {error.localizedDescription()}")
            return
        chars = service.characteristics()
        char_uuids = [c.UUID().UUIDString() for c in chars]
        logging.info(f"{peripheral_to_str(peripheral)} - Discovered {len(chars)} characteristics for service {service.UUID().UUIDString()}: {char_uuids}")
        if not chars:
            logging.info(f"{peripheral_to_str(peripheral)} - No service characteristics discovered")
            return
        self.characteristic = next((c for c in chars if c.UUID() == CHAR_UUID), None)
        if not self.characteristic:
            logging.info(f"{peripheral_to_str(peripheral)} - BitChat characteristic not found")
            return
        logging.info(f"{peripheral_to_str(peripheral)} - BITCHAT SERVICE CHARACTERISTIC FOUND")
        peripheral.setNotifyValue_forCharacteristic_(True, self.characteristic)

        # Send ANNOUNCE
        timestamp = int(time.time() * 1000)
        sender_id = bytes.fromhex(MY_PEER_ID)
        packet = BitchatPacket(packet_type=1, senderID=sender_id, recipientID=BROADCAST_RECIPIENT,
                               timestamp=timestamp, payload=MY_NICKNAME, ttl=7)
        announce_data = NSData.dataWithBytes_length_(packet.to_binary(), len(packet.to_binary()))
        peripheral.writeValue_forCharacteristic_type_(announce_data, self.characteristic, 1)  # With response
        logging.info(f"{peripheral_to_str(peripheral)} - Sent ANNOUNCE payload")

        # Send NOISE_IDENTITY_ANNOUNCE (stub)
        noise_payload = create_noise_identity_announcement()
        noise_packet = BitchatPacket(packet_type=3, senderID=sender_id, recipientID=BROADCAST_RECIPIENT,
                                     timestamp=timestamp, payload=noise_payload, ttl=7)
        noise_data = NSData.dataWithBytes_length_(noise_packet.to_binary(), len(noise_packet.to_binary()))
        peripheral.writeValue_forCharacteristic_type_(noise_data, self.characteristic, 1)
        logging.info(f"{peripheral_to_str(peripheral)} - Sent NOISE_IDENTITY_ANNOUNCE")

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
        try:
            if error:
                logging.error(f"{peripheral_to_str(peripheral)} - Error updating value: {error.localizedDescription()}")
                return

            received_bytes = characteristic.value().bytes().tobytes()
            logging.info(f"{peripheral_to_str(peripheral)} - Received data: {hexlify(received_bytes).decode()}")

            packet = BitchatPacket.from_binary(received_bytes)
            if not packet:
                logging.error(f"{peripheral_to_str(peripheral)} - Failed to parse received packet.")
                return

            hex_sender = hexlify(packet.senderID).decode()
            logging.info(f"{peripheral_to_str(peripheral)} - Parsed packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}")

            if packet.packet_type == 1:  # ANNOUNCE
                nickname = packet.payload.decode('utf-8', 'ignore')
                logging.info(f"{peripheral_to_str(peripheral)} - ANNOUNCE from peerID {hex_sender} with nickname {nickname}")

            elif packet.packet_type == 2:  # MESSAGE
                log_decoded_message(packet.payload, packet.timestamp)

            elif packet.packet_type == 4:  # FRAGMENT (reassembled)
                logging.info(f"{peripheral_to_str(peripheral)} - Received FRAGMENT, parsing inner message...")
                log_decoded_message(packet.payload, packet.timestamp)

            elif packet.packet_type == 3:  # NOISE_IDENTITY_ANNOUNCE
                logging.info(f"{peripheral_to_str(peripheral)} - Received NOISE_IDENTITY_ANNOUNCE - initiating handshake (stub)")

            else:
                logging.warning(f"Received unhandled packet type: {packet.packet_type}")

        except Exception as e:
            logging.error(f"{peripheral_to_str(peripheral)} - Error in update value handler: {str(e)}")


# ----------------------------
# Stubs / App loop
# ----------------------------

def create_noise_identity_announcement():
    # Stub implementation based on original
    static_key   = bytes(32)  # Stub Noise static public key
    signing_key  = bytes(32)  # Stub Ed25519 public key
    timestamp    = int(time.time() * 1000)
    signature    = bytes(64)  # Stub signature
    previous     = b''
    # Binary format: len(peerID) (2) + peerID + 32 static + 32 signing + len(nickname) (2) + nickname + 8 timestamp + len(previous) (2) + previous + 64 signature
    data = (
        len(MY_PEER_ID).to_bytes(2, 'big') + MY_PEER_ID.encode('utf-8') +
        static_key + signing_key +
        len(MY_NICKNAME).to_bytes(2, 'big') + MY_NICKNAME +
        timestamp.to_bytes(8, 'big') +
        len(previous).to_bytes(2, 'big') + previous +
        signature
    )
    return data


running = True

def signal_handler(sig, frame):
    global running
    running = False
    logging.info("Ctrl+C received, shutting down")
    AppHelper.stopEventLoop()

signal.signal(signal.SIGINT, signal_handler)


def main():
    # Start peripheral in thread
    peripheral_thread = threading.Thread(target=lambda: PeripheralDelegate.alloc().init())
    peripheral_thread.daemon = True
    peripheral_thread.start()

    # Start central in main with event loop
    central_delegate = CentralDelegate.alloc().init()
    AppHelper.runConsoleEventLoop(installInterrupt=True)


if __name__ == "__main__":
    main()
