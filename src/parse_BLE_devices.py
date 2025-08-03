import struct
import binascii
from collections import defaultdict
import numpy as np

def parse_ad_data(adv_data):
    names = set()
    types = set()
    connectable = None
    i = 0
    while i < len(adv_data):
        if i + 1 >= len(adv_data):
            break
        length = adv_data[i]
        if length == 0 or i + length + 1 > len(adv_data):
            break
        ad_type = adv_data[i + 1]
        ad_value = adv_data[i + 2 : i + 1 + length]
        if ad_type in [0x08, 0x09]:  # Short/Complete name
            try:
                name = ad_value.decode('utf-8', errors='ignore').strip()
                if name:
                    names.add(name)
            except:
                pass
        if ad_type == 0x01:  # Flags
            if len(ad_value) > 0:
                flags = ad_value[0]
                connectable = bool(flags & 0x02) or bool(flags & 0x04)
        if ad_type in [0x02, 0x03, 0x06, 0x07]:  # UUIDs
            uuid_len = 2 if ad_type in [0x02, 0x03] else 16
            for j in range(0, len(ad_value), uuid_len):
                if j + uuid_len > len(ad_value):
                    break
                uuid_bytes = ad_value[j : j + uuid_len]
                uuid_str = binascii.hexlify(bytes(reversed(uuid_bytes))).decode('utf-8')
                if uuid_len == 16:
                    uuid_formatted = f"{uuid_str[0:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:32]}"
                else:
                    uuid_formatted = uuid_str
                types.add(uuid_formatted)
        i += length + 1
    return names, types, connectable

def extract_ble_devices(pcap_file):
    with open(pcap_file, 'rb') as f:
        # Global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            return []

        magic, _, _, _, _, _, linktype = struct.unpack('<IHHIIII', global_header)
        if magic not in [0xa1b2c3d4, 0xa1b23c4d]:  # Standard or nanosecond
            return []  # Invalid PCAP
        if linktype not in [251, 256]:  # BT_LE_LL or BT_LE_LL_WITH_PHDR
            return []  # Not BLE

        devices = defaultdict(lambda: {'names': set(), 'types': set(), 'connectable': None, 'rssi_values': [], 'packet_count': 0})

        while True:
            # Packet header (16 bytes)
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)

            # Packet data
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            # Parse BTLE_RF header if present (linktype 256 has PHDR)
            offset = 0
            rssi = None
            if linktype == 256:  # BT_LE_LL_WITH_PHDR
                if len(pkt_data) < 1:
                    continue
                rf_hdr_len = pkt_data[0]
                if len(pkt_data) < rf_hdr_len + 1:
                    continue
                rf_hdr = pkt_data[1:1 + rf_hdr_len]
                # RSSI is signed int8, often at offset 1 (signal)
                if len(rf_hdr) >= 2:
                    rssi = struct.unpack('b', rf_hdr[1:2])[0]  # dBm

                offset = 1 + rf_hdr_len

            # BTLE LL data
            btle_data = pkt_data[offset:]
            if len(btle_data) < 6:  # Min: AA (4) + PDU header (2)
                continue

            # Access Address (4 bytes, little-endian)
            aa = struct.unpack('<I', btle_data[0:4])[0]
            if aa != 0x8e89bed6:  # Standard BLE advertising AA
                continue

            # PDU header (2 bytes)
            pdu_header = struct.unpack('<BB', btle_data[4:6])
            pdu_type = pdu_header[0] & 0x0F
            tx_add = bool(pdu_header[0] & 0x40)
            rx_add = bool(pdu_header[0] & 0x80)
            pdu_len = pdu_header[1] & 0x3F

            if len(btle_data) < 6 + pdu_len:
                continue

            # AdvA (6 bytes, little-endian)
            adv_a_bytes = btle_data[6:12]
            adv_mac = ':'.join(f'{b:02x}' for b in reversed(adv_a_bytes))

            # Adv data starts after AdvA + header
            adv_data_start = 12
            adv_data = btle_data[adv_data_start : 6 + pdu_len]

            # Parse AD
            names, types_set, connectable = parse_ad_data(adv_data)

            # Update device
            devices[adv_mac]['packet_count'] += 1
            if names:
                devices[adv_mac]['names'].update(names)
            if types_set:
                devices[adv_mac]['types'].update(types_set)
            if connectable is not None:
                devices[adv_mac]['connectable'] = connectable
            if rssi is not None:
                devices[adv_mac]['rssi_values'].append(rssi)

    # Format results
    unique_devices = []
    for mac, info in devices.items():
        avg_rssi = np.mean(info['rssi_values']) if info['rssi_values'] else 'N/A'
        name = ', '.join(info['names']) if info['names'] else 'Unknown'
        device_type = ', '.join(info['types']) if info['types'] else 'Unknown'
        connectable_str = 'Yes' if info['connectable'] else 'No' if info['connectable'] is not None else 'Unknown'

        unique_devices.append({
            'MAC': mac,
            'Name': name,
            'Type/UUIDs': device_type,
            'Connectable': connectable_str,
            'Avg RSSI (dB)': avg_rssi,
            'Packets Seen': info['packet_count']
        })

    return unique_devices

# Replace with your actual PCAP path
pcap_path = "/Users/blake/repos/Boston-Mesh-Open-Source-Base-Station/data/hackrf_BLE_sniff_20_channels_for_bitchat.pcap"  # Update this to your local path
devices = extract_ble_devices(pcap_path)

if isinstance(devices, list) and devices:
    # Print as table
    print("| MAC | Name | Type/UUIDs | Connectable | Avg RSSI (dB) | Packets Seen |")
    print("|---|----|------------|-------------|---------------|--------------|")
    for dev in sorted(devices, key=lambda x: int(x['Packets Seen']) if isinstance(x['Packets Seen'], (int, float)) else 0, reverse=True):
        print(f"| {dev['MAC']} | {dev['Name']} | {dev['Type/UUIDs']} | {dev['Connectable']} | {dev['Avg RSSI (dB)']} | {dev['Packets Seen']} |")
else:
    print(devices if devices else "No BLE devices found")