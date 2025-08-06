import threading
import time
import random
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ed25519  # For future signing; not used yet

# pyobjc imports with type: ignore to suppress Pylance errors
import objc  # type: ignore
from Foundation import NSObject, NSLog, NSData, NSRunLoop, NSDate  # type: ignore
from CoreBluetooth import (CBCentralManager, CBPeripheral, CBPeripheralManager, CBManagerStatePoweredOn,
                          CBUUID, CBMutableCharacteristic, CBMutableService, CBCharacteristicPropertyRead,
                          CBCharacteristicPropertyWrite, CBCharacteristicPropertyNotify, CBAttributePermissionsReadable,
                          CBAttributePermissionsWriteable, CBATTErrorSuccess, CBAdvertisementDataServiceUUIDsKey)  # type: ignore
from PyObjCTools import AppHelper  # type: ignore

# BitChat UUIDs and constants
SERVICE_UUID_STR = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHAR_UUID_STR = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
DESC_UUID_STR = "00002902-0000-1000-8000-00805f9b34fb"

SERVICE_UUID = CBUUID.UUIDWithString_(SERVICE_UUID_STR)
CHAR_UUID = CBUUID.UUIDWithString_(CHAR_UUID_STR)

MY_PEER_ID = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))  # 16 hex chars
MY_NICKNAME = b"MyMacPeer"  # Your nickname as bytes

BROADCAST_RECIPIENT = b'\xff' * 8  # SpecialRecipients.BROADCAST (-1.toByte() in Kotlin)

class BitchatPacket:
    def __init__(self, version=1, packet_type=1, senderID=b'\0'*8, recipientID=BROADCAST_RECIPIENT, timestamp=0, payload=b'', signature=None, ttl=7):
        self.version = version
        self.packet_type = packet_type
        self.senderID = senderID
        self.recipientID = recipientID
        self.timestamp = timestamp
        self.payload = payload
        self.signature = signature if signature is not None else b''
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
        if len(data) < 1 + 1 + 8 + 8 + 8 + 1 + 2:
            return None
        pos = 0
        version = int.from_bytes(data[pos:pos+1], 'big')
        pos += 1
        packet_type = int.from_bytes(data[pos:pos+1], 'big')
        pos += 1
        senderID = data[pos:pos+8]
        pos += 8
        recipientID = data[pos:pos+8]
        pos += 8
        timestamp = int.from_bytes(data[pos:pos+8], 'big')
        pos += 8
        ttl = int.from_bytes(data[pos:pos+1], 'big')
        pos += 1
        payload_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2
        if pos + payload_len > len(data):
            return None
        payload = data[pos:pos+payload_len]
        pos += payload_len
        sig_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2
        if pos + sig_len > len(data):
            return None
        signature = data[pos:pos+sig_len]
        return cls(version, packet_type, senderID, recipientID, timestamp, payload, signature, ttl)

class PeripheralDelegate(NSObject):
    def init(self):
        self = objc.super(PeripheralDelegate, self).init()
        self.manager = CBPeripheralManager.alloc().initWithDelegate_queue_(self, None)
        self.characteristic = None
        return self

    def peripheralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            NSLog("Peripheral powered on")
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
            NSLog(f"Error adding service: {error}")
            return
        NSLog("Service added; starting advertising")
        adv_data = {CBAdvertisementDataServiceUUIDsKey: [SERVICE_UUID]}
        manager.startAdvertising_(adv_data)

    def peripheralManager_didReceiveWriteRequests_(self, manager, requests):
        for request in requests:
            data = request.value().bytes().tobytes()
            NSLog(f"Received write: {data}")
            packet = BitchatPacket.from_binary(data)
            if packet:
                NSLog(f"Parsed packet: type={packet.packet_type}, senderID={hexlify(packet.senderID).decode()}, ttl={packet.ttl}, payload={packet.payload}")
                if packet.packet_type == 1:  # Assume ANNOUNCE
                    nickname = packet.payload.decode('utf-8', 'ignore')
                    NSLog(f"ANNOUNCE from peerID {hexlify(packet.senderID).decode()} with nickname {nickname}")
                    # Add peer here in a dict or list
            manager.respondToRequest_withResult_(request, CBATTErrorSuccess)
            if self.characteristic:
                manager.updateValue_forCharacteristic_onSubscribedCentrals_(NSData.dataWithBytes_length_(data, len(data)), self.characteristic, None)

    def peripheralManager_central_didSubscribeToCharacteristic_(self, manager, central, characteristic):
        NSLog("Central subscribed")

class CentralDelegate(NSObject):
    def init(self):
        self = objc.super(CentralDelegate, self).init()
        self.manager = CBCentralManager.alloc().initWithDelegate_queue_(self, None)
        self.peripheral = None
        self.characteristic = None
        return self

    def centralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            NSLog("Central powered on; scanning")
            manager.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)
        else:
            NSLog(f"Central state not powered on: {manager.state()}")

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, manager, peripheral, adv_data, rssi):
        if SERVICE_UUID in adv_data.get(CBAdvertisementDataServiceUUIDsKey, []):
            NSLog(f"Discovered peer: {peripheral.name()} with RSSI: {rssi}")
            self.peripheral = peripheral
            manager.connectPeripheral_options_(peripheral, None)
            manager.stopScan()
        else:
            NSLog(f"Discovered non-BitChat peripheral: {peripheral.name()}")

    def centralManager_didConnectPeripheral_(self, manager, peripheral):
        NSLog(f"Connected to {peripheral.name()}")
        peripheral.setDelegate_(self)
        peripheral.discoverServices_([SERVICE_UUID])

    def centralManager_didFailToConnectPeripheral_error_(self, manager, peripheral, error):
        NSLog(f"Failed to connect to {peripheral.name()}: {error}")

    def centralManager_didDisconnectPeripheral_error_(self, manager, peripheral, error):
        NSLog(f"Disconnected from {peripheral.name()}: {error}")

    def peripheral_didDiscoverServices_(self, peripheral, error):
        if error:
            NSLog(f"Error discovering services: {error}")
            return
        services = peripheral.services()
        NSLog(f"Discovered {len(services)} services: {[s.UUID().UUIDString() for s in services]}")
        if not services:
            NSLog("No services discovered - disconnecting")
            peripheral.delegate().manager.cancelPeripheralConnection_(peripheral)
            return
        service = next((s for s in services if s.UUID() == SERVICE_UUID), None)
        if not service:
            NSLog("BitChat service not found - disconnecting")
            peripheral.delegate().manager.cancelPeripheralConnection_(peripheral)
            return
        peripheral.discoverCharacteristics_forService_([CHAR_UUID], service)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        if error:
            NSLog(f"Error discovering characteristics: {error}")
            return
        chars = service.characteristics()
        NSLog(f"Discovered {len(chars)} characteristics for service {service.UUID().UUIDString()}: {[c.UUID().UUIDString() for c in chars]}")
        if not chars:
            NSLog("No characteristics discovered")
            return
        self.characteristic = next((c for c in chars if c.UUID() == CHAR_UUID), None)
        if not self.characteristic:
            NSLog("BitChat characteristic not found")
            return
        peripheral.setNotifyValue_forCharacteristic_(True, self.characteristic)
        # Send ANNOUNCE
        timestamp = int(time.time() * 1000)
        sender_id = bytes.fromhex(MY_PEER_ID)
        packet = BitchatPacket(packet_type=1, senderID=sender_id, recipientID=BROADCAST_RECIPIENT, timestamp=timestamp, payload=MY_NICKNAME, ttl=7)
        announce_data = NSData.dataWithBytes_length_(packet.to_binary(), len(packet.to_binary()))
        peripheral.writeValue_forCharacteristic_type_(announce_data, self.characteristic, 1)  # With response
        NSLog("Sent ANNOUNCE payload")

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
        if error:
            NSLog(f"Error updating value: {error}")
            return
        data = characteristic.value().bytes().tobytes()
        NSLog(f"Received notification: {data}")
        packet = BitchatPacket.from_binary(data)
        if packet:
            NSLog(f"Parsed packet: type={packet.packet_type}, senderID={hexlify(packet.senderID).decode()}, ttl={packet.ttl}, payload={packet.payload}")
            if packet.packet_type == 1:  # Assume ANNOUNCE
                nickname = packet.payload.decode('utf-8', 'ignore')
                NSLog(f"ANNOUNCE from peerID {hexlify(packet.senderID).decode()} with nickname {nickname}")
                # Add peer here

def main():
    # Start peripheral in thread
    peripheral_thread = threading.Thread(target=lambda: PeripheralDelegate.alloc().init())
    peripheral_thread.daemon = True
    peripheral_thread.start()

    # Start central in main with event loop
    central_delegate = CentralDelegate.alloc().init()
    AppHelper.runConsoleEventLoop()

if __name__ == "__main__":
    main()