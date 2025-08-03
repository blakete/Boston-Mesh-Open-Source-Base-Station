import struct
import binascii
from collections import defaultdict
import numpy as np

def parse_ad_data(adv_data):
    names = set()
    types = set()
    connectable = None
    tx_power = None
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
        if ad_type == 0x0a:  # Tx Power Level
            if len(ad_value) == 1:
                tx_power = struct.unpack('b', ad_value)[0]
        i += length + 1
    return names, types, connectable, tx_power

def extract_ble_devices(pcap_file):
    with open(pcap_file, 'rb') as f:
        # Global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            print("Invalid PCAP: Too short")
            return []

        magic, major, minor, _, _, snaplen, linktype = struct.unpack('<IHHIIII', global_header)
        if magic not in [0xa1b2c3d4, 0xa1b23c4d]:
            print("Invalid PCAP magic")
            return []
        if linktype not in [251, 256]:
            print(f"Unsupported linktype: {linktype}")
            return []

        devices = defaultdict(lambda: {'names': set(), 'types': set(), 'connectable': None, 'rssi_values': [], 'tx_power_values': [], 'packet_count': 0})

        pkt_num = 0
        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)

            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                print(f"Pkt {pkt_num}: Incomplete data")
                break

            offset = 0
            rssi = None
            channel = None
            if linktype == 256:
                if len(pkt_data) < 1:
                    print(f"Pkt {pkt_num}: No PHDR")
                    continue
                rf_hdr_len = pkt_data[0]
                if len(pkt_data) < rf_hdr_len + 1:
                    print(f"Pkt {pkt_num}: Short PHDR")
                    continue
                rf_hdr = pkt_data[1:1 + rf_hdr_len]
                # Ice9 PHDR format (from source): board_id (1), channel (1), rssi (1 signed), timestamp (8), flags (1)
                if len(rf_hdr) >= 3:
                    channel = rf_hdr[1]
                    rssi = struct.unpack('b', rf_hdr[2:3])[0]
                offset = 1 + rf_hdr_len
                print(f"Pkt {pkt_num}: PHDR len={rf_hdr_len}, channel={channel}, rssi={rssi}")  # Debug

            btle_data = pkt_data[offset:]
            if len(btle_data) < 6:
                print(f"Pkt {pkt_num}: Short LL {len(btle_data)}")
                continue

            aa = struct.unpack('<I', btle_data[0:4])[0]
            if aa != 0x8e89bed6:
                print(f"Pkt {pkt_num}: Bad AA 0x{aa:x}")
                continue

            pdu_header = struct.unpack('<BB', btle_data[4:6])
            pdu_type = pdu_header[0] & 0x0F
            pdu_len = pdu_header[1] & 0x3F

            if len(btle_data) < 6 + pdu_len:
                print(f"Pkt {pkt_num}: Short PDU, need {6 + pdu_len}, have {len(btle_data)}")
                continue

            # AdvA only for advertising PDUs (types 0,1,2,3,4,6)
            if pdu_type in [0, 1, 2, 3, 4, 6]:
                adv_a_bytes = btle_data[6:12]
                adv_mac = ':'.join(f'{b:02x}' for b in reversed(adv_a_bytes))
            else:
                print(f"Pkt {pkt_num}: Non-advertising PDU type {pdu_type}")
                continue

            adv_data_start = 12 if pdu_type != 1 else 18  # ADV_DIRECT_IND has extra targetA (6 bytes)
            adv_data_end = 6 + pdu_len
            adv_data = btle_data[adv_data_start : adv_data_end]

            names, types_set, connectable, tx_power = parse_ad_data(adv_data)

            devices[adv_mac]['packet_count'] += 1
            if names:
                devices[adv_mac]['names'].update(names)
            if types_set:
                devices[adv_mac]['types'].update(types_set)
            if connectable is not None:
                devices[adv_mac]['connectable'] = connectable
            if rssi is not None:
                devices[adv_mac]['rssi_values'].append(rssi)
            if tx_power is not None:
                devices[adv_mac]['tx_power_values'].append(tx_power)

            print(f"Pkt {pkt_num}: Extracted MAC {adv_mac}, name {names}, type {types_set}, connectable {connectable}, rssi {rssi}")  # Debug
            pkt_num += 1

        # Format
        unique_devices = []
        for mac, info in devices.items():
            avg_rssi = np.mean(info['rssi_values']) if info['rssi_values'] else (np.mean(info['tx_power_values']) if info['tx_power_values'] else 'N/A')
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
pcap_path = "/Users/blake/repos/Boston-Mesh-Open-Source-Base-Station/data/hackrf_BLE_sniff_20_channels_for_bitchat.pcap"  # Update this
devices = extract_ble_devices(pcap_path)

if devices:
    print("| MAC | Name | Type/UUIDs | Connectable | Avg RSSI (dB) | Packets Seen |")
    print("|---|----|------------|-------------|---------------|--------------|")
    for dev in sorted(devices, key=lambda x: x['Packets Seen'], reverse=True):
        print(f"| {dev['MAC']} | {dev['Name']} | {dev['Type/UUIDs']} | {dev['Connectable']} | {dev['Avg RSSI (dB)']} | {dev['Packets Seen']} |")
else:
    print("No BLE devices found")