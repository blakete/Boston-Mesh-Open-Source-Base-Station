import asyncio
import logging
import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
import random
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib  # Need to install python3-gi in Dockerfile
from bleak import BleakScanner, BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from cryptography.hazmat.primitives.asymmetric import ed25519  # For BitChat signing (expand as needed)

# BitChat UUIDs
SERVICE_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHAR_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
DESC_UUID = "00002902-0000-1000-8000-00805f9b34fb"

# Generate MY_PEER_ID: 8 random bytes as hex (16 chars), like original code
MY_PEER_ID = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))
MY_NICKNAME = b"MyLinuxPeer"  # Your nickname as bytes; serialize full BitchatPacket as needed

logging.basicConfig(level=logging.INFO)

# D-Bus constants for BlueZ
BLUEZ_SERVICE_NAME = 'org.bluez'
ADAPTER_INTERFACE = 'org.bluez.Adapter1'
LE_ADVERTISING_MANAGER_INTERFACE = 'org.bluez.LEAdvertisingManager1'
GATT_MANAGER_INTERFACE = 'org.bluez.GattManager1'
GATT_SERVICE_INTERFACE = 'org.bluez.GattService1'
GATT_CHARACTERISTIC_INTERFACE = 'org.bluez.GattCharacteristic1'
GATT_DESCRIPTOR_INTERFACE = 'org.bluez.GattDescriptor1'

class Advertisement(dbus.service.Object):
    PATH_BASE = '/org/bluez/example/advertisement'

    def __init__(self, bus, index, advertising_type):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = advertising_type
        self.service_uuids = [SERVICE_UUID]
        self.manufacturer_data = None
        self.solicit_uuids = None
        self.service_data = None
        self.local_name = 'BitChatLinux'
        self.include_tx_power = True
        self.data = None
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        properties = dict()
        properties['Type'] = self.ad_type
        if self.service_uuids is not None:
            properties['ServiceUUIDs'] = dbus.Array(self.service_uuids, signature='s')
        if self.local_name is not None:
            properties['LocalName'] = dbus.String(self.local_name)
        if self.include_tx_power:
            properties['Includes'] = dbus.Array(['tx-power'], signature='s')
        return {'org.bluez.LEAdvertisement1': properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(dbus.PROPERTIES_INTERFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != 'org.bluez.LEAdvertisement1':
            raise dbus.exceptions.DBusException("Invalid interface")
        return self.get_properties()['org.bluez.LEAdvertisement1']

    @dbus.service.method('org.bluez.LEAdvertisement1', in_signature='', out_signature='')
    def Release(self):
        logging.info(f'{self.path} released')

class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + '/char' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.flags = flags
        self.value = bytearray()
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_CHARACTERISTIC_INTERFACE: {
                'Service': dbus.ObjectPath(self.service.path),
                'UUID': self.uuid,
                'Flags': self.flags,
                'Value': dbus.ByteArray(self.value)
            }
        }

    @dbus.service.method(GATT_CHARACTERISTIC_INTERFACE, in_signature='', out_signature='ay')
    def ReadValue(self, options):
        logging.info('Characteristic read')
        return self.value

    @dbus.service.method(GATT_CHARACTERISTIC_INTERFACE, in_signature='aya{sv}', out_signature='')
    def WriteValue(self, value, options):
        self.value = value
        logging.info(f'Characteristic written: {value}')  # Parse as BitChat packet here, e.g., add peer on ANNOUNCE

    @dbus.service.method(GATT_CHARACTERISTIC_INTERFACE, in_signature='', out_signature='')
    def StartNotify(self):
        logging.info('Start notify')

    @dbus.service.method(GATT_CHARACTERISTIC_INTERFACE, in_signature='', out_signature='')
    def StopNotify(self):
        logging.info('Stop notify')

# ... (Add Descriptor class similarly for CCCD)

class Service(dbus.service.Object):
    PATH_BASE = '/org/bluez/example/service'

    def __init__(self, bus, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = '/'
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def add_service(self, service):
        self.services.append(service)

def register_ad_cb():
    logging.info('Advertisement registered')

def register_ad_error_cb(error):
    logging.error(f'Failed to register advertisement: {str(error)}')

def register_app_cb():
    logging.info('GATT application registered')

def register_app_error_cb(error):
    logging.error(f'Failed to register application: {str(error)}')

async def advertise_and_serve():
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    
    adapter = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/org/bluez/hci0'), ADAPTER_INTERFACE)
    
    # Advertising
    ad_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/org/bluez/hci0'), LE_ADVERTISING_MANAGER_INTERFACE)
    ad = Advertisement(bus, 0, 'peripheral')
    ad_manager.RegisterAdvertisement(ad.get_path(), {}, reply_handler=register_ad_cb, error_handler=register_ad_error_cb)
    
    # GATT Server
    app = Application(bus)
    service = Service(bus, 0, SERVICE_UUID, True)
    char = Characteristic(bus, 0, CHAR_UUID, ['read', 'write', 'notify'], service)
    # Add descriptor for CCCD if needed
    service.add_characteristic(char)
    app.add_service(service)
    
    gatt_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/org/bluez/hci0'), GATT_MANAGER_INTERFACE)
    gatt_manager.RegisterApplication(app.get_path(), {}, reply_handler=register_app_cb, error_handler=register_app_error_cb)
    
    mainloop = GLib.MainLoop()
    mainloop.run()  # Blocks; run in thread if needed for async integration

async def scan_and_connect():
    async with BleakScanner(detection_callback=discovery_callback) as scanner:
        await asyncio.sleep(60)  # Adjust or loop

async def discovery_callback(device, advertisement_data):
    if SERVICE_UUID in advertisement_data.service_uuids:
        async with BleakClient(device) as client:
            if await client.is_connected():
                logging.info(f"Connected to {device.address}")
                await client.start_notify(CHAR_UUID, notification_handler)
                # Send ANNOUNCE (simplified)
                announce_payload = MY_NICKNAME
                await client.write_gatt_char(CHAR_UUID, announce_payload)

def notification_handler(sender: BleakGATTCharacteristic, data: bytearray):
    logging.info(f"Received: {data}")  # Parse BitChat packet

async def main():
    # Run D-Bus peripheral in a separate thread
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, advertise_and_serve)
    await scan_and_connect()

if __name__ == "__main__":
    asyncio.run(main())
    