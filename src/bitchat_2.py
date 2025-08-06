import threading
import time
import random
import struct
from binascii import hexlify
# from cryptography.hazmat.primitives import ed25519  # For future signing; not used yet
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
MY_NICKNAME = b"MyMacPeer"  # Simplified announcement payload

class PeripheralDelegate(NSObject):
    def init(self):
        self = super(PeripheralDelegate, self).init()
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

            # Add CCCD descriptor
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
            NSLog(f"Received write: {data}")  # Parse as BitChat packet, e.g., add peer if ANNOUNCE
            # Respond success
            manager.respondToRequest_withResult_(request, CBATTErrorSuccess)
            # Optionally notify back
            if self.characteristic:
                manager.updateValue_forCharacteristic_onSubscribedCentrals_(NSData.dataWithBytes_length_(data, len(data)), self.characteristic, None)

    def peripheralManager_central_didSubscribeToCharacteristic_(self, manager, central, characteristic):
        NSLog("Central subscribed")

class CentralDelegate(NSObject):
    def init(self):
        self = super(CentralDelegate, self).init()
        self.manager = CBCentralManager.alloc().initWithDelegate_queue_(self, None)
        self.peripheral = None
        self.characteristic = None
        return self

    def centralManagerDidUpdateState_(self, manager):
        if manager.state() == CBManagerStatePoweredOn:
            NSLog("Central powered on; scanning")
            manager.scanForPeripheralsWithServices_options_([SERVICE_UUID], None)

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, manager, peripheral, adv_data, rssi):
        if SERVICE_UUID in adv_data.get(CBAdvertisementDataServiceUUIDsKey, []):
            NSLog(f"Discovered peer: {peripheral.name()}")
            self.peripheral = peripheral
            manager.connectPeripheral_options_(peripheral, None)
            manager.stopScan()

    def centralManager_didConnectPeripheral_(self, manager, peripheral):
        NSLog(f"Connected to {peripheral.name()}")
        peripheral.setDelegate_(self)
        peripheral.discoverServices_([SERVICE_UUID])

    def peripheral_didDiscoverServices_(self, peripheral, error):
        if error:
            NSLog(f"Error discovering services: {error}")
            return
        service = peripheral.services()[0]
        peripheral.discoverCharacteristics_forService_([CHAR_UUID], service)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        if error:
            NSLog(f"Error discovering characteristics: {error}")
            return
        self.characteristic = service.characteristics()[0]
        peripheral.setNotifyValue_forCharacteristic_(True, self.characteristic)
        # Send ANNOUNCE
        announce_data = NSData.dataWithBytes_length_(MY_NICKNAME, len(MY_NICKNAME))
        peripheral.writeValue_forCharacteristic_type_(announce_data, self.characteristic, 1)  # With response

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
        if error:
            NSLog(f"Error updating value: {error}")
            return
        data = characteristic.value().bytes().tobytes()
        NSLog(f"Received notification: {data}")  # Parse as BitChat packet

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