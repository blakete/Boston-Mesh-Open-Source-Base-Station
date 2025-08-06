# mac_bitchat_ble.py
# BitChat BLE bridge for macOS (PyObjC) — matches current BinaryProtocol header & type IDs
# Requires: pip install pyobjc cryptography

from __future__ import annotations

import threading
import time
import random
import re
import logging
import signal
from binascii import hexlify
from datetime import datetime
from typing import Optional, Tuple

# PyObjC imports
import objc  # type: ignore
from Foundation import NSObject, NSData  # type: ignore
from CoreBluetooth import (  # type: ignore
    CBCentralManager, CBPeripheral, CBPeripheralManager,
    CBManagerStatePoweredOn,
    CBUUID, CBMutableCharacteristic, CBMutableService, CBMutableDescriptor,
    CBCharacteristicPropertyRead, CBCharacteristicPropertyWrite, CBCharacteristicPropertyNotify,
    CBAttributePermissionsReadable, CBAttributePermissionsWriteable,
    CBATTErrorSuccess,
    CBAdvertisementDataServiceUUIDsKey, CBAdvertisementDataLocalNameKey
)
from PyObjCTools import AppHelper

# ----------------------------
# Logging
# ----------------------------

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# ----------------------------
# BitChat constants (binary protocol & types)
# ----------------------------

# Service/Characteristic UUIDs (must match iOS app)
SERVICE_UUID_STR = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHAR_UUID_STR    = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
DESC_UUID_STR    = "00002902-0000-1000-8000-00805f9b34fb"

SERVICE_UUID = CBUUID.UUIDWithString_(SERVICE_UUID_STR)
CHAR_UUID    = CBUUID.UUIDWithString_(CHAR_UUID_STR)

# Special recipient: broadcast
BROADCAST_RECIPIENT = b"\xff" * 8

# Message types (must match Swift enum)
MT = {
    "announce": 0x01,
    "leave": 0x03,
    "message": 0x04,
    "fragmentStart": 0x05,
    "fragmentContinue": 0x06,
    "fragmentEnd": 0x07,
    "deliveryAck": 0x0A,
    "deliveryStatusRequest": 0x0B,
    "readReceipt": 0x0C,
    "noiseHandshakeInit": 0x10,
    "noiseHandshakeResp": 0x11,
    "noiseEncrypted": 0x12,
    "noiseIdentityAnnounce": 0x13,
    "versionHello": 0x20,
    "versionAck": 0x21,
    "protocolAck": 0x22,
    "protocolNack": 0x23,
    "systemValidation": 0x24,
    "handshakeRequest": 0x25,
}
def typename(t): return MT.get(t, f"UNKNOWN({t})")

# Packet flags bitmask
FLAG_HAS_RECIPIENT  = 0x01
FLAG_HAS_SIGNATURE  = 0x02
FLAG_COMPRESSED     = 0x04  # we won't use compression here

PROTOCOL_VERSION = 1
DEFAULT_TTL = 3

# Identity (ephemeral; 8-byte peerID expressed as 16 hex chars)
MY_PEER_ID_HEX = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))
MY_PEER_ID = bytes.fromhex(MY_PEER_ID_HEX)
MY_NICKNAME = "MyMacPeer"

logging.info(f"My PeerID: {MY_PEER_ID_HEX}  Nick: {MY_NICKNAME}")

# ----------------------------
# Helpers for binary building
# ----------------------------

def u8(x: int) -> bytes:
    return x.to_bytes(1, "big", signed=False)

def u16(x: int) -> bytes:
    return x.to_bytes(2, "big", signed=False)

def u64(x: int) -> bytes:
    return x.to_bytes(8, "big", signed=False)

def now_ms() -> int:
    return int(time.time() * 1000)

def enc_str(s: str) -> bytes:
    """Encode as 1-byte length + utf-8 (strings here are short)."""
    b = s.encode("utf-8")
    if len(b) > 255:
        # fall back to 2-byte length if ever needed
        return b"\xff" + u16(len(b)) + b
    return u8(len(b)) + b

def dec_str(buf: bytes, pos: int) -> Tuple[str, int]:
    if pos >= len(buf):
        raise ValueError("string pos OOB")
    L = buf[pos]
    if L != 0xFF:
        pos += 1
        end = pos + L
        if end > len(buf): raise ValueError("string len OOB")
        return buf[pos:end].decode("utf-8", "ignore"), end
    # 0xFF signals 2-byte len (our fallback)
    if pos + 3 > len(buf): raise ValueError("string len2 OOB")
    L2 = int.from_bytes(buf[pos+1:pos+3], "big")
    pos += 3
    end = pos + L2
    if end > len(buf): raise ValueError("string len2 OOB2")
    return buf[pos:end].decode("utf-8", "ignore"), end

# ----------------------------
# BinaryProtocol: BitchatPacket encode/decode
#   Header (13 bytes):
#     version(1), type(1), ttl(1), timestamp(8), flags(1), payloadLen(2)
#   Then:
#     senderID(8), [recipientID(8) if flags.hasRecipient], payload(payloadLen), [signature(64) if flags.hasSignature]
# ----------------------------
# Source: current whitepaper / code path in repo. :contentReference[oaicite:1]{index=1}
# ----------------------------

class BitchatPacket:
    def __init__(self, type_u8: int, payload: bytes, *,
                 ttl: int = DEFAULT_TTL,
                 sender_id: bytes = MY_PEER_ID,
                 recipient_id: Optional[bytes] = None,
                 signature: Optional[bytes] = None,
                 timestamp_ms: Optional[int] = None,
                 version: int = PROTOCOL_VERSION):
        self.version = version
        self.type = type_u8
        self.ttl = ttl & 0xFF
        self.timestamp = now_ms() if timestamp_ms is None else int(timestamp_ms)
        self.sender_id = sender_id[:8].ljust(8, b"\x00")
        self.recipient_id = recipient_id[:8] if recipient_id else None
        self.payload = payload or b""
        self.signature = signature if signature else None

    def to_bytes(self) -> bytes:
        flags = 0
        if self.recipient_id is not None:
            flags |= FLAG_HAS_RECIPIENT
        if self.signature is not None:
            flags |= FLAG_HAS_SIGNATURE

        # payload length excludes sender/recipient/signature — it’s only for payload field
        header = b"".join([
            u8(self.version),
            u8(self.type),
            u8(self.ttl),
            u64(self.timestamp),
            u8(flags),
            u16(len(self.payload)),
        ])

        body = [self.sender_id]
        if self.recipient_id is not None:
            body.append(self.recipient_id)
        body.append(self.payload)
        if self.signature is not None:
            # Ed25519 signature is 64 bytes if present
            if len(self.signature) != 64:
                raise ValueError("signature must be 64 bytes")
            body.append(self.signature)

        return header + b"".join(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["BitchatPacket"]:
        try:
            if len(data) < 13 + 8:
                return None
            pos = 0
            version = data[pos]; pos += 1
            type_u8 = data[pos]; pos += 1
            ttl = data[pos]; pos += 1
            timestamp = int.from_bytes(data[pos:pos+8], "big"); pos += 8
            flags = data[pos]; pos += 1
            payload_len = int.from_bytes(data[pos:pos+2], "big"); pos += 2

            # Sender
            if pos + 8 > len(data): return None
            sender_id = data[pos:pos+8]; pos += 8

            # Recipient
            recipient_id = None
            if flags & FLAG_HAS_RECIPIENT:
                if pos + 8 > len(data): return None
                recipient_id = data[pos:pos+8]; pos += 8

            # Payload
            if pos + payload_len > len(data): return None
            payload = data[pos:pos+payload_len]; pos += payload_len

            signature = None
            if flags & FLAG_HAS_SIGNATURE:
                if pos + 64 > len(data): return None
                signature = data[pos:pos+64]
                pos += 64

            pkt = cls(
                type_u8=type_u8,
                payload=payload,
                ttl=ttl,
                sender_id=sender_id,
                recipient_id=recipient_id,
                signature=signature,
                timestamp_ms=timestamp,
                version=version,
            )
            return pkt
        except Exception as e:
            logging.error(f"Decode error: {e}")
            return None

# ----------------------------
# Version negotiation payloads
# ----------------------------

def build_version_hello_payload(client_version: str = "mac_python/0.1",
                                platform: str = "macOS-Python",
                                capabilities: Optional[list[str]] = None) -> bytes:
    """
    Swift VersionHello.toBinaryData():
      flags(1) [bit0: hasCapabilities]
      versionCount(1) + versions...
      preferred(1)
      clientVersion(string)
      platform(string)
      if hasCapabilities: capCount(1) + cap strings...
    """
    flags = 0
    caps = capabilities or []
    if caps:
        flags |= 0x01

    supported = [PROTOCOL_VERSION]
    preferred = PROTOCOL_VERSION

    out = bytearray()
    out += u8(flags)
    out += u8(len(supported))
    for v in supported:
        out += u8(v)
    out += u8(preferred)
    out += enc_str(client_version)
    out += enc_str(platform)
    if caps:
        out += u8(len(caps))
        for c in caps:
            out += enc_str(c)
    return bytes(out)

def parse_version_ack_payload(data: bytes) -> dict:
    """
    Swift VersionAck.fromBinaryData():
      flags(1) [bit0 hasCapabilities, bit1 hasReason]
      agreed(1)
      serverVersion(str)
      platform(str)
      rejected(1)
      if caps: capCount(1) + caps
      if reason: reason(str)
    """
    try:
        pos = 0
        flags = data[pos]; pos += 1
        has_caps = (flags & 0x01) != 0
        has_reason = (flags & 0x02) != 0

        agreed = data[pos]; pos += 1
        server_version, pos = dec_str(data, pos)
        platform, pos = dec_str(data, pos)
        rejected = data[pos] != 0; pos += 1

        caps = []
        if has_caps:
            cap_count = data[pos]; pos += 1
            for _ in range(cap_count):
                s, pos = dec_str(data, pos)
                caps.append(s)

        reason = None
        if has_reason:
            reason, pos = dec_str(data, pos)

        return {
            "agreedVersion": agreed,
            "serverVersion": server_version,
            "platform": platform,
            "rejected": rejected,
            "capabilities": caps,
            "reason": reason
        }
    except Exception:
        return {}

# ----------------------------
# Minimal broadcast message payload (optional)
# ----------------------------

def build_announce_payload(nickname: str) -> bytes:
    # Swift treats announce payload as UTF-8 nickname bytes.
    return nickname.encode("utf-8")

# ----------------------------
# Pretty print helpers
# ----------------------------

def peer_hex(b8: bytes) -> str:
    return hexlify(b8).decode()

def pkt_type_name(t: int) -> str:
    for k, v in MT.items():
        if v == t: return k
    return f"0x{t:02x}"

# ----------------------------
# BLE Delegates
# ----------------------------

connected_identifiers = set()

def periph_to_str(p: CBPeripheral) -> str:
    ident = p.identifier().UUIDString()
    state = p.state()
    name = p.name() or "Unknown"
    return f"<{ident}, {state}, {name}>"

class PeripheralDelegate(NSObject):
    """Advertise a BitChat GATT service/characteristic so the phone can write to us."""
    def init(self):
        self = objc.super(PeripheralDelegate, self).init()
        self.manager = CBPeripheralManager.alloc().initWithDelegate_queue_(self, None)
        self.characteristic = None
        return self

    def peripheralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            char_props = CBCharacteristicPropertyRead | CBCharacteristicPropertyWrite | CBCharacteristicPropertyNotify
            perms = CBAttributePermissionsReadable | CBAttributePermissionsWriteable

            self.characteristic = CBMutableCharacteristic.alloc().initWithType_properties_value_permissions_(
                CBUUID.UUIDWithString_(CHAR_UUID_STR), char_props, None, perms
            )
            descriptor = CBMutableDescriptor.alloc().initWithType_value_(CBUUID.UUIDWithString_(DESC_UUID_STR), None)
            self.characteristic.setDescriptors_([descriptor])

            service = CBMutableService.alloc().initWithType_primary_(CBUUID.UUIDWithString_(SERVICE_UUID_STR), True)
            service.setCharacteristics_([self.characteristic])
            manager.addService_(service)

    def peripheralManager_didAddService_error_(self, manager, service, error):
        if error:
            logging.error(f"PeripheralManager addService error: {error.localizedDescription()}")
            return
        adv = {
            CBAdvertisementDataLocalNameKey: "BitChatMac",
            CBAdvertisementDataServiceUUIDsKey: [CBUUID.UUIDWithString_(SERVICE_UUID_STR)]
        }
        manager.startAdvertising_(adv)
        logging.info("Peripheral advertising started.")

    def peripheralManager_didReceiveWriteRequests_(self, manager, requests):
        for req in requests:
            try:
                raw = req.value().bytes().tobytes()
                pkt = BitchatPacket.from_bytes(raw)
                if pkt:
                    logging.info(f"[P] RX {pkt_type_name(pkt.type)} from {peer_hex(pkt.sender_id)} ttl={pkt.ttl} len={len(pkt.payload)}")
                else:
                    logging.info(f"[P] RX undecodable: {hexlify(raw).decode()[:120]}...")
                manager.respondToRequest_withResult_(req, CBATTErrorSuccess)

                # Echo to subscribers for debugging
                if self.characteristic:
                    manager.updateValue_forCharacteristic_onSubscribedCentrals_(
                        NSData.dataWithBytes_length_(raw, len(raw)), self.characteristic, None
                    )
            except Exception as e:
                logging.error(f"Peripheral write handler error: {e}")

    def peripheralManager_central_didSubscribeToCharacteristic_(self, manager, central, characteristic):
        logging.info("A central subscribed to our characteristic.")


class CentralDelegate(NSObject):
    """Connect to the iPhone peripheral and exchange BitChat packets that the app accepts."""
    def init(self):
        self = objc.super(CentralDelegate, self).init()
        self.mgr = CBCentralManager.alloc().initWithDelegate_queue_(self, None)
        self.peripheral = None
        self.char = None
        return self

    def centralManagerDidUpdateState_(self, manager):
        logging.info(f"Central manager state updated: {manager.state()}")
        if manager.state() == CBManagerStatePoweredOn:
            logging.info("Scanning for peripherals advertising BitChat service...")
            self.mgr.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, manager, peripheral, adv_data, rssi):
        name = peripheral.name() or "Unknown"
        ident = peripheral.identifier().UUIDString()
        if ident in connected_identifiers:
            return
        if SERVICE_UUID in adv_data.get(CBAdvertisementDataServiceUUIDsKey, []):
            logging.info(f"{periph_to_str(peripheral)} - Discovered (RSSI: {rssi})")
            self.peripheral = peripheral
            connected_identifiers.add(ident)
            self.mgr.connectPeripheral_options_(peripheral, None)

    def centralManager_didConnectPeripheral_(self, manager, peripheral):
        logging.info(f"{periph_to_str(peripheral)} - Connected")
        peripheral.setDelegate_(self)
        logging.info(f"{periph_to_str(peripheral)} - Discovering services")
        peripheral.discoverServices_([SERVICE_UUID])

    def centralManager_didFailToConnectPeripheral_error_(self, manager, peripheral, error):
        logging.error(f"{periph_to_str(peripheral)} - Failed to connect: {error.localizedDescription() if error else 'Unknown'}")

    def centralManager_didDisconnectPeripheral_error_(self, manager, peripheral, error):
        logging.info(f"{periph_to_str(peripheral)} - Disconnected: {error.localizedDescription() if error else 'Unknown'}")
        try:
            connected_identifiers.remove(peripheral.identifier().UUIDString())
        except KeyError:
            pass
        # Resume scanning to reconnect
        self.mgr.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)

    # ---- CBPeripheralDelegate ----

    def peripheral_didDiscoverServices_(self, peripheral, error):
        if error:
            logging.error(f"Service discovery error: {error.localizedDescription()}")
            return
        services = peripheral.services()
        if not services:
            logging.warning("No services found, disconnecting.")
            self.mgr.cancelPeripheralConnection_(peripheral)
            return
        svc = next((s for s in services if s.UUID() == SERVICE_UUID), None)
        if not svc:
            logging.warning("BitChat service not found, disconnecting.")
            self.mgr.cancelPeripheralConnection_(peripheral)
            return
        logging.info(f"{periph_to_str(peripheral)} - Discovered {len(services)} services")
        logging.info(f"{periph_to_str(peripheral)} - Discovering service characteristics...")
        peripheral.discoverCharacteristics_forService_([CHAR_UUID], svc)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        if error:
            logging.error(f"Characteristic discovery error: {error.localizedDescription()}")
            return
        chars = service.characteristics()
        if not chars:
            logging.warning("No characteristics found on service.")
            return
        self.char = next((c for c in chars if c.UUID() == CHAR_UUID), None)
        if not self.char:
            logging.warning("BitChat characteristic not found.")
            return

        # Enable notify
        peripheral.setNotifyValue_forCharacteristic_(True, self.char)

        # === Send VersionHello ===
        vh_payload = build_version_hello_payload()
        vh_pkt = BitchatPacket(
            type_u8=MT["versionHello"],
            payload=vh_payload,
            ttl=DEFAULT_TTL,
            sender_id=MY_PEER_ID,
            recipient_id=None  # no recipient => handled as general handshake
        )
        data = vh_pkt.to_bytes()
        # NOTE: CoreBluetooth write type: 1 = WithoutResponse, 0 = WithResponse
        peripheral.writeValue_forCharacteristic_type_(NSData.dataWithBytes_length_(data, len(data)), self.char, 1)
        logging.info(f"{periph_to_str(peripheral)} - Sent VersionHello")
        
        # Small delay to avoid rate-limit collision with immediate follow-up
        time.sleep(0.20)

        # === Send Announce (nickname) ===
        ann_payload = build_announce_payload(MY_NICKNAME)
        ann_pkt = BitchatPacket(
            type_u8=MT["announce"],
            payload=ann_payload,
            ttl=DEFAULT_TTL,
            sender_id=MY_PEER_ID,
            recipient_id=None
        )
        d2 = ann_pkt.to_bytes()
        peripheral.writeValue_forCharacteristic_type_(NSData.dataWithBytes_length_(d2, len(d2)), self.char, 1)
        logging.info(f"{periph_to_str(peripheral)} - Sent Announce")

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
        if error:
            logging.error(f"didUpdateValue error: {error.localizedDescription()}")
            return
        if not characteristic.value():
            return
        raw = characteristic.value().bytes().tobytes()
        pkt = BitchatPacket.from_bytes(raw)
        if not pkt:
            logging.info(f"[C] RX undecodable: {hexlify(raw).decode()[:120]}...")
            return
        tname = pkt_type_name(pkt.type)
        sender = peer_hex(pkt.sender_id)
        logging.info(f"[C] RX {typename(pkt.type)} from {hexlify(pkt.sender_id).decode()} ttl={pkt.ttl} len={len(pkt.payload)}")
        logging.info(f"[C] RX {tname} from {sender} ttl={pkt.ttl} len={len(pkt.payload)}")

        # Example: parse VersionAck if received
        if pkt.type == MT["versionAck"]:
            info = parse_version_ack_payload(pkt.payload)
            if info:
                logging.info(f"[C] VersionAck: {info}")
            else:
                logging.info("[C] VersionAck: could not parse")

# ----------------------------
# Main
# ----------------------------

running = True

def signal_handler(sig, frame):
    global running
    running = False
    logging.info("Ctrl+C received, shutting down")
    AppHelper.stopEventLoop()

signal.signal(signal.SIGINT, signal_handler)

def main():
    # Start our local peripheral (so iPhone can also write to us)
    peripheral_thread = threading.Thread(target=lambda: PeripheralDelegate.alloc().init())
    peripheral_thread.daemon = True
    peripheral_thread.start()

    # Central to connect to iPhone
    _ = CentralDelegate.alloc().init()

    AppHelper.runConsoleEventLoop(installInterrupt=True)

if __name__ == "__main__":
    main()
