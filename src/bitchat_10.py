import threading
import time
import random
import logging
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ed25519  # For future signing; not used yet
import signal
from datetime import datetime

# pyobjc imports with type: ignore to suppress Pylance errors
import objc  # type: ignore
from Foundation import NSObject, NSData, NSRunLoop, NSDate  # type: ignore
from CoreBluetooth import (CBCentralManager, CBPeripheral, CBPeripheralManager, CBManagerStatePoweredOn,  # type: ignore
                          CBUUID, CBMutableCharacteristic, CBMutableService, CBMutableDescriptor, CBCharacteristicPropertyRead,  # type: ignore
                          CBCharacteristicPropertyWrite, CBCharacteristicPropertyNotify, CBAttributePermissionsReadable,  # type: ignore
                          CBAttributePermissionsWriteable, CBATTErrorSuccess, CBAdvertisementDataServiceUUIDsKey, CBAdvertisementDataLocalNameKey)  # type: ignore
from PyObjCTools import AppHelper


# def log(message):
#     print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} {message}", flush=True)
    
# Simplified log format (no class name)
LOG_FORMAT = (
    "[%(asctime)s] "
    "[%(levelname)s] "
    # "[%(threadName)s] "
    # "[Module: %(module)s] "
    # "[Function: %(funcName)s] "
    "- %(message)s"
)

# Set up logger
logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT
)

# BitChat UUIDs and constants
SERVICE_UUID_STR = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHAR_UUID_STR = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
DESC_UUID_STR = "00002902-0000-1000-8000-00805f9b34fb"

SERVICE_UUID = CBUUID.UUIDWithString_(SERVICE_UUID_STR)
CHAR_UUID = CBUUID.UUIDWithString_(CHAR_UUID_STR)

MY_PEER_ID = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))  # 16 hex chars
MY_NICKNAME = b"MyMacPeer"  # Your nickname as bytes

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
    # return f"<CBPeripheral identifier = {identifier}, state = {state}, name = {name}>"
    return f"<{identifier}, {state}, {name}>"
    
class BitchatPacket:
    def __init__(self, version=1, packet_type=1, senderID=b'\0'*8, recipientID=BROADCAST_RECIPIENT, timestamp=0, payload=b'', signature=b'', ttl=7):
        self.version = version
        self.packet_type = packet_type
        self.senderID = senderID
        self.recipientID = recipientID
        self.timestamp = timestamp
        self.payload = payload
        self.signature = signature
        self.ttl = ttl

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
            version = int.from_bytes(data[pos:pos+1], 'big')
            pos += 1
            logging.info(f"Parsing: version={version} at pos={pos}")
            packet_type = int.from_bytes(data[pos:pos+1], 'big')
            pos += 1
            logging.info(f"Parsing: type={packet_type} at pos={pos}")
            senderID = data[pos:pos+8]
            pos += 8
            logging.info(f"Parsing: senderID={hexlify(senderID).decode()} at pos={pos}")
            recipientID = data[pos:pos+8]
            pos += 8
            logging.info(f"Parsing: recipientID={hexlify(recipientID).decode()} at pos={pos}")
            timestamp = int.from_bytes(data[pos:pos+8], 'big')
            pos += 8
            logging.info(f"Parsing: timestamp={timestamp} at pos={pos}")
            ttl = int.from_bytes(data[pos:pos+1], 'big')
            pos += 1
            logging.info(f"Parsing: ttl={ttl} at pos={pos}")
            payload_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            logging.info(f"Parsing: payload_len={payload_len} at pos={pos}")
            if pos + payload_len > len(data):
                logging.error("Parsing failed: payload_len exceeds data length")
                return None
            payload = data[pos:pos+payload_len]
            pos += payload_len
            sig_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            logging.info(f"Parsing: sig_len={sig_len} at pos={pos}")
            if pos + sig_len > len(data):
                logging.error("Parsing failed: sig_len exceeds data length")
                return None
            signature = data[pos:pos+sig_len]
            if pos + sig_len != len(data):
                logging.warning(f"Parsing warning: extra bytes after signature: {len(data) - (pos + sig_len)}")
            return cls(version, packet_type, senderID, recipientID, timestamp, payload, signature, ttl)
        except Exception as e:
            logging.error(f"Parsing error: {str(e)} at pos={pos}")
            return None

class PeripheralDelegate(NSObject):
    def init(self):
        self = objc.super(PeripheralDelegate, self).init()
        self.manager = CBPeripheralManager.alloc().initWithDelegate_queue_(self, None)
        self.characteristic = None
        return self

    def peripheralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            # logging.info("Peripheral powered on")
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
                hex_data = hexlify(data).decode()
                logging.info(f"Received write: {hex_data}")
                packet = BitchatPacket.from_binary(data)
                if packet:
                    hex_sender = hexlify(packet.senderID).decode()
                    hex_payload = hexlify(packet.payload).decode()
                    logging.info(f"Parsed packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}, payload={hex_payload}")
                    if packet.packet_type == 1:  # ANNOUNCE
                        nickname = packet.payload.decode('utf-8', 'ignore')
                        logging.info(f"ANNOUNCE from peerID {hex_sender} with nickname {nickname}")
                        # Add peer logic here
                    elif packet.packet_type == 2:  # MESSAGE
                        self.parse_message(packet.payload)
                    elif packet.packet_type == 4:  # FRAGMENT (stub)
                        logging.info("Received FRAGMENT packet - handle reassembly")
                else:
                    logging.error("Failed to parse received packet")
                manager.respondToRequest_withResult_(request, CBATTErrorSuccess)
                if self.characteristic:
                    manager.updateValue_forCharacteristic_onSubscribedCentrals_(NSData.dataWithBytes_length_(data, len(data)), self.characteristic, None)
        except Exception as e:
            logging.error(f"Error in write handler: {str(e)}")

    def peripheralManager_central_didSubscribeToCharacteristic_(self, manager, central, characteristic):
        logging.info("Central subscribed")

    def parse_message(self, payload):
        try:
            pos = 0
            sender_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            sender = payload[pos:pos+sender_len].decode('utf-8')
            pos += sender_len
            content_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            content = payload[pos:pos+content_len].decode('utf-8')
            pos += content_len
            timestamp = int.from_bytes(payload[pos:pos+8], 'big')
            pos += 8
            isRelay = int.from_bytes(payload[pos:pos+1], 'big')
            pos += 1
            senderPeerID_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            senderPeerID = payload[pos:pos+senderPeerID_len].decode('utf-8')
            pos += senderPeerID_len
            isPrivate = int.from_bytes(payload[pos:pos+1], 'big')
            pos += 1
            recipientNickname = None
            if isPrivate:
                recipient_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2
                recipientNickname = payload[pos:pos+recipient_len].decode('utf-8')
                pos += recipient_len
            channel = None
            channel_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            if channel_len > 0:
                channel = payload[pos:pos+channel_len].decode('utf-8')
                pos += channel_len
            mentions_count = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            mentions = []
            for _ in range(mentions_count):
                ment_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2
                ment = payload[pos:pos+ment_len].decode('utf-8')
                pos += ment_len
                mentions.append(ment)
            logging.info(f"Decoded MESSAGE: sender={sender}, content={content}, timestamp={timestamp}, isRelay={isRelay}, senderPeerID={senderPeerID}, isPrivate={isPrivate}, recipient={recipientNickname}, channel={channel}, mentions={mentions}")
        except Exception as e:
            logging.error(f"Error parsing MESSAGE: {str(e)}")

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
            # logging.info("Central powered on")
            logging.info("Scanning for peripherals with services...")
            # manager.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)
            manager.scanForPeripheralsWithServices_options_([], None)
        else:
            logging.warning(f"Central state not powered on: {manager.state()}")

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, manager, peripheral, adv_data, rssi):
        identifier = peripheral.identifier().UUIDString()
        
        if identifier in connected_identifiers:
            return
        
        if identifier not in self.known_peripherals.keys():
            self.known_peripherals[identifier] = peripheral_to_dict(peripheral)
            self.known_peripherals[identifier]["state"] = "discovered"
            # logging.info(f"{peripheral_to_str(peripheral)} - Discovered peripheral")
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
            # peripheral.discoverServices_([SERVICE_UUID])
            logging.info(f"{peripheral_to_str(peripheral)} - Discovering peripheral's services")
            peripheral.discoverServices_([])

    def centralManager_didFailToConnectPeripheral_error_(self, manager, peripheral, error):
        identifier = peripheral.identifier().UUIDString()
        logging.error(f"{peripheral_to_str(peripheral)} - Failed to connect to peripheral - Error: {error.localizedDescription() if error else 'Unknown error'}")
        self.known_peripherals[identifier]["state"] = "failed to connect"

    def centralManager_didDisconnectPeripheral_error_(self, manager, peripheral, error):
        identifier = peripheral.identifier().UUIDString()
        self.known_peripherals[identifier]["state"] = "disconnected"
        connected_identifiers.remove(identifier) if identifier in connected_identifiers else None
        logging.info(f"{peripheral_to_str(peripheral)} - Disconnected from peripheral: {error.localizedDescription() if error else 'Unknown error'}")
        # Restart scanning
        manager.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)

    def peripheral_didDiscoverServices_(self, peripheral, error):
        if error:
            logging.error(f"Error discovering services: {error.localizedDescription()}")
            return
        services = peripheral.services()
        service_uuids = [s.UUID().UUIDString() for s in services]
        if not services:
            logging.info("{peripheral_to_str(peripheral)} - No services discovered - disconnecting")
            peripheral.delegate().manager.cancelPeripheralConnection_(peripheral)
            return
        # logging.info(f"{peripheral_to_str(peripheral)} - Discovered {len(services)} services: {service_uuids}")
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
        packet = BitchatPacket(packet_type=1, senderID=sender_id, recipientID=BROADCAST_RECIPIENT, timestamp=timestamp, payload=MY_NICKNAME, ttl=7)
        announce_data = NSData.dataWithBytes_length_(packet.to_binary(), len(packet.to_binary()))
        peripheral.writeValue_forCharacteristic_type_(announce_data, self.characteristic, 1)  # With response
        logging.info(f"{peripheral_to_str(peripheral)} - Sent ANNOUNCE payload")
        # Send NOISE_IDENTITY_ANNOUNCE
        noise_payload = create_noise_identity_announcement()
        noise_packet = BitchatPacket(packet_type=3, senderID=sender_id, recipientID=BROADCAST_RECIPIENT, timestamp=timestamp, payload=noise_payload, ttl=7)
        noise_data = NSData.dataWithBytes_length_(noise_packet.to_binary(), len(noise_packet.to_binary()))
        peripheral.writeValue_forCharacteristic_type_(noise_data, self.characteristic, 1)
        logging.info(f"{peripheral_to_str(peripheral)} - Sent NOISE_IDENTITY_ANNOUNCE")

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
        try:
            if error:
                logging.error(f"{peripheral_to_str(peripheral)} - Error updating value: {error.localizedDescription()}")
                return
            received_bytes = characteristic.value().bytes().tobytes()
            hex_data = hexlify(received_bytes).decode()
            logging.info(f"{peripheral_to_str(peripheral)} - Received data: {hex_data}")
            packet = BitchatPacket.from_binary(received_bytes)
            if packet:
                hex_sender = hexlify(packet.senderID).decode()
                hex_payload = hexlify(packet.payload).decode()
                logging.info(f"{peripheral_to_str(peripheral)} - Parsed packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}, payload={hex_payload}")
                if packet.packet_type == 1:  # ANNOUNCE
                    nickname = packet.payload.decode('utf-8', 'ignore')
                    logging.info(f"{peripheral_to_str(peripheral)} - ANNOUNCE from peerID {hex_sender} with nickname {nickname}")
                    # Add peer logic here
                elif packet.packet_type == 2:  # MESSAGE
                    self.parse_message(packet.payload)
                elif packet.packet_type == 4:  # FRAGMENT (stub)
                    logging.info(f"{peripheral_to_str(peripheral)} - Received FRAGMENT packet - handle reassembly")
                elif packet.packet_type == 3:  # NOISE_IDENTITY_ANNOUNCE
                    logging.info(f"{peripheral_to_str(peripheral)} - Received NOISE_IDENTITY_ANNOUNCE - initiating handshake")
                    timestamp = int(time.time() * 1000)
                    sender_id = bytes.fromhex(MY_PEER_ID)
                    handshake_packet = BitchatPacket(packet_type=5, senderID=sender_id, recipientID=packet.senderID, timestamp=timestamp, payload=bytes(32), ttl=7)  # Stub 32 byte handshake
                    handshake_data = NSData.dataWithBytes_length_(handshake_packet.to_binary(), len(handshake_packet.to_binary()))
                    peripheral.writeValue_forCharacteristic_type_(handshake_data, characteristic, 1)
                    logging.info(f"{peripheral_to_str(peripheral)} - Responded with NOISE_HANDSHAKE_INIT")
                elif packet.packet_type == 6:  # NOISE_HANDSHAKE_RESP
                    logging.info(f"{peripheral_to_str(peripheral)} - Received NOISE_HANDSHAKE_RESP - session established")
            else:
                logging.info(f"{peripheral_to_str(peripheral)} - Failed to parse received packet - attempting alternative parse")
                self.alternative_parse(received_bytes)
        except Exception as e:
            logging.error(f"{peripheral_to_str(peripheral)} - Error in update value handler: {str(e)}")

    def parse_message(self, payload):
        try:
            pos = 0
            sender_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            sender = payload[pos:pos+sender_len].decode('utf-8')
            pos += sender_len
            content_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            content = payload[pos:pos+content_len].decode('utf-8')
            pos += content_len
            timestamp = int.from_bytes(payload[pos:pos+8], 'big')
            pos += 8
            isRelay = int.from_bytes(payload[pos:pos+1], 'big')
            pos += 1
            senderPeerID_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            senderPeerID = payload[pos:pos+senderPeerID_len].decode('utf-8')
            pos += senderPeerID_len
            isPrivate = int.from_bytes(payload[pos:pos+1], 'big')
            pos += 1
            recipientNickname = None
            if isPrivate:
                recipient_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2
                recipientNickname = payload[pos:pos+recipient_len].decode('utf-8')
                pos += recipient_len
            channel = None
            channel_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            if channel_len > 0:
                channel = payload[pos:pos+channel_len].decode('utf-8')
                pos += channel_len
            mentions_count = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            mentions = []
            for _ in range(mentions_count):
                ment_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2
                ment = payload[pos:pos+ment_len].decode('utf-8')
                pos += ment_len
                mentions.append(ment)
            logging.info(f"Decoded MESSAGE: sender={sender}, content={content}, timestamp={timestamp}, isRelay={isRelay}, senderPeerID={senderPeerID}, isPrivate={isPrivate}, recipient={recipientNickname}, channel={channel}, mentions={mentions}")
        except Exception as e:
            logging.error(f"Error parsing MESSAGE: {str(e)}")

    def alternative_parse(self, data):
        try:
            # Try to find 'blake' or 'd' in the data
            if b'blake' in data:
                pos = data.find(b'blake')
                logging.info(f"Found 'blake' at position {pos}")
            if b'81ake' in data:
                pos = data.find(b'81ake')
                logging.info(f"Found '81ake' at position {pos}")
            # if b'd' in data:
            #     pos = data.find(b'd')
            #     logging.info(f"Found 'd' at position {pos}")
            # Stub for fragment or other
            inner = data[6:]  # Skip potential header
            packet = BitchatPacket.from_binary(inner)
            if packet:
                logging.info("Alternative parse succeeded")
                hex_sender = hexlify(packet.senderID).decode()
                hex_payload = hexlify(packet.payload).decode()
                logging.info(f"Parsed alternative packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}, payload={hex_payload}")
        except Exception as e:
            logging.error(f"Error in alternative parse: {str(e)}")

def create_noise_identity_announcement():
    # Stub implementation based on original code
    static_key = bytes(32)  # Stub Noise static public key
    signing_key = bytes(32)  # Stub Ed25519 public key
    timestamp = int(time.time() * 1000)
    binding_data = MY_PEER_ID.encode('utf-8') + static_key + str(timestamp).encode('utf-8')
    signature = bytes(64)  # Stub signature
    previous = b''
    # Binary format: len(peerID) (2) + peerID + 32 static + 32 signing + len(nickname) (2) + nickname + 8 timestamp + len(previous) (2) + previous + 64 signature
    data = len(MY_PEER_ID).to_bytes(2, 'big') + MY_PEER_ID.encode('utf-8') + static_key + signing_key + len(MY_NICKNAME).to_bytes(2, 'big') + MY_NICKNAME + timestamp.to_bytes(8, 'big') + len(previous).to_bytes(2, 'big') + previous + signature
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