import threading
import time
import random
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ed25519  # For future signing; not used yet
import signal
from datetime import datetime

# pyobjc imports with type: ignore to suppress Pylance errors
import objc  # type: ignore
from Foundation import NSObject, NSData, NSRunLoop, NSDate  # type: ignore
from CoreBluetooth import (CBCentralManager, CBPeripheral, CBPeripheralManager, CBManagerStatePoweredOn,
                          CBUUID, CBMutableCharacteristic, CBMutableService, CBMutableDescriptor, CBCharacteristicPropertyRead,
                          CBCharacteristicPropertyWrite, CBCharacteristicPropertyNotify, CBAttributePermissionsReadable,
                          CBAttributePermissionsWriteable, CBATTErrorSuccess, CBAdvertisementDataServiceUUIDsKey, CBAdvertisementDataLocalNameKey)  # type: ignore
from PyObjCTools import AppHelper  # type: ignore

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

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} {message}", flush=True)

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
            log(f"Parsing: version={version} at pos={pos}")
            packet_type = int.from_bytes(data[pos:pos+1], 'big')
            pos += 1
            log(f"Parsing: type={packet_type} at pos={pos}")
            senderID = data[pos:pos+8]
            pos += 8
            log(f"Parsing: senderID={hexlify(senderID).decode()} at pos={pos}")
            recipientID = data[pos:pos+8]
            pos += 8
            log(f"Parsing: recipientID={hexlify(recipientID).decode()} at pos={pos}")
            timestamp = int.from_bytes(data[pos:pos+8], 'big')
            pos += 8
            log(f"Parsing: timestamp={timestamp} at pos={pos}")
            ttl = int.from_bytes(data[pos:pos+1], 'big')
            pos += 1
            log(f"Parsing: ttl={ttl} at pos={pos}")
            payload_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            log(f"Parsing: payload_len={payload_len} at pos={pos}")
            if pos + payload_len > len(data):
                log("Parsing failed: payload_len exceeds data length")
                return None
            payload = data[pos:pos+payload_len]
            pos += payload_len
            sig_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            log(f"Parsing: sig_len={sig_len} at pos={pos}")
            if pos + sig_len > len(data):
                log("Parsing failed: sig_len exceeds data length")
                return None
            signature = data[pos:pos+sig_len]
            if pos + sig_len != len(data):
                log(f"Parsing warning: extra bytes after signature: {len(data) - (pos + sig_len)}")
            return cls(version, packet_type, senderID, recipientID, timestamp, payload, signature, ttl)
        except Exception as e:
            log(f"Parsing error: {str(e)} at pos={pos}")
            return None

class FragmentManager:
    def __init__(self):
        self.fragments = {}  # fragID: {'total': n, 'received': set, 'data': [None] * n}

    def handle_fragment(self, packet):
        frag_id = packet.senderID + packet.timestamp.to_bytes(8, 'big')  # Stub ID
        frag_index = int.from_bytes(packet.payload[:1], 'big')  # Assume first byte index
        total = int.from_bytes(packet.payload[1:2], 'big')  # Second byte total
        chunk = packet.payload[2:]  # Rest chunk

        if frag_id not in self.fragments:
            self.fragments[frag_id] = {'total': total, 'received': set(), 'data': [None] * total}

        frag = self.fragments[frag_id]
        frag['received'].add(frag_index)
        frag['data'][frag_index] = chunk

        if len(frag['received']) == frag['total']:
            full_data = b''.join(frag['data'])
            del self.fragments[frag_id]
            return full_data
        return None

fragment_manager = FragmentManager()

class PeripheralDelegate(NSObject):
    def init(self):
        self = objc.super(PeripheralDelegate, self).init()
        self.manager = CBPeripheralManager.alloc().initWithDelegate_queue_(self, None)
        self.characteristic = None
        return self

    def peripheralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            log("Peripheral powered on")
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
            log(f"Error adding service: {error.localizedDescription()}")
            return
        log("Service added; starting advertising")
        adv_data = {CBAdvertisementDataLocalNameKey: "BitChatMac", CBAdvertisementDataServiceUUIDsKey: [SERVICE_UUID]}
        manager.startAdvertising_(adv_data)

    def peripheralManager_didReceiveWriteRequests_(self, manager, requests):
        try:
            for request in requests:
                data = request.value().bytes().tobytes()
                hex_data = hexlify(data).decode()
                log(f"Received write: {hex_data}")
                packet = BitchatPacket.from_binary(data)
                if packet:
                    hex_sender = hexlify(packet.senderID).decode()
                    hex_payload = hexlify(packet.payload).decode()
                    log(f"Parsed packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}, payload={hex_payload}")
                    if packet.packet_type == 1:  # ANNOUNCE
                        nickname = packet.payload.decode('utf-8', 'ignore')
                        log(f"ANNOUNCE from peerID {hex_sender} with nickname {nickname}")
                        # Add peer logic here
                    elif packet.packet_type == 2:  # MESSAGE
                        self.parse_message(packet.payload)
                    elif packet.packet_type == 4:  # FRAGMENT
                        reassembled = fragment_manager.handle_fragment(packet)
                        if reassembled:
                            inner_packet = BitchatPacket.from_binary(reassembled)
                            if inner_packet:
                                log("Reassembled inner packet")
                                # Process inner_packet (e.g., if type 2, parse_message(inner_packet.payload))
                                if inner_packet.packet_type == 2:
                                    self.parse_message(inner_packet.payload)
                                elif inner_packet.packet_type == 6:  # NOISE_ENCRYPTED
                                    decrypted = decrypt_noise(inner_packet.payload, inner_packet.senderID)
                                    if decrypted:
                                        inner_inner_packet = BitchatPacket.from_binary(decrypted)
                                        if inner_inner_packet and inner_inner_packet.packet_type == 2:
                                            self.parse_message(inner_inner_packet.payload)
                    elif packet.packet_type == 3:  # NOISE_IDENTITY_ANNOUNCE
                        log("Received NOISE_IDENTITY_ANNOUNCE - initiating handshake")
                        timestamp = int(time.time() * 1000)
                        sender_id = bytes.fromhex(MY_PEER_ID)
                        handshake_data = initiate_noise_handshake(hex_sender)
                        if handshake_data:
                            handshake_packet = BitchatPacket(packet_type=5, senderID=sender_id, recipientID=packet.senderID, timestamp=timestamp, payload=handshake_data, ttl=7)
                            handshake_data_ns = NSData.dataWithBytes_length_(handshake_packet.to_binary(), len(handshake_packet.to_binary()))
                            manager.writeValue_forCharacteristic_type_(handshake_data_ns, self.characteristic, 1)  # Note: manager is not defined here; use self.manager if needed
                            log("Responded with NOISE_HANDSHAKE_INIT")
                    elif packet.packet_type == 6:  # NOISE_HANDSHAKE_RESP
                        log("Received NOISE_HANDSHAKE_RESP - completing session")
                        complete_noise_handshake(packet.payload, hex_sender)
                else:
                    log("Failed to parse received packet - attempting alternative parse")
                    self.alternative_parse(data)
                manager.respondToRequest_withResult_(request, CBATTErrorSuccess)
                if self.characteristic:
                    manager.updateValue_forCharacteristic_onSubscribedCentrals_(NSData.dataWithBytes_length_(data, len(data)), self.characteristic, None)
        except Exception as e:
            log(f"Error in write handler: {str(e)}")

    def peripheralManager_central_didSubscribeToCharacteristic_(self, manager, central, characteristic):
        log("Central subscribed")

    def alternative_parse(self, data):
        try:
            # Try to find 'blake' or 'd' in the data
            if b'blake' in data:
                pos = data.find(b'blake')
                log(f"Found 'blake' at position {pos}")
            if b'd' in data:
                pos = data.find(b'd')
                log(f"Found 'd' at position {pos}")
            # Stub for fragment or other
            inner = data[6:]  # Skip potential header
            packet = BitchatPacket.from_binary(inner)
            if packet:
                log("Alternative parse succeeded")
                hex_sender = hexlify(packet.senderID).decode()
                hex_payload = hexlify(packet.payload).decode()
                log(f"Parsed alternative packet: type={packet.packet_type}, senderID={hex_sender}, ttl={packet.ttl}, payload={hex_payload}")
        except Exception as e:
            log(f"Error in alternative parse: {str(e)}")

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

def initiate_noise_handshake(peer_id):
    # Stub Noise XX initiator
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    # Assume we have peer's public from announcement
    peer_pub = bytes(32)  # Stub
    shared = ephemeral_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake', backend=default_backend())
    key = kdf.derive(shared)
    sessions[peer_id] = key
    return ephemeral_pub  # Send ephemeral pub as payload

def complete_noise_handshake(payload, peer_id):
    # Stub responder
    ephemeral_pub = payload  # Assume payload is responder's ephemeral pub
    ephemeral_priv = X25519PrivateKey.generate()
    shared = ephemeral_priv.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake', backend=default_backend())
    key = kdf.derive(shared)
    sessions[peer_id] = key
    return True

def decrypt_noise(data, sender_id):
    key = sessions.get(sender_id)
    if not key:
        log("No session key for decryption")
        return None
    # Stub decryption (e.g., AES with key)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    iv = data[:16]  # Assume first 16 bytes IV
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

running = True

def signal_handler(sig, frame):
    global running
    running = False
    log("Ctrl+C received, shutting down")
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