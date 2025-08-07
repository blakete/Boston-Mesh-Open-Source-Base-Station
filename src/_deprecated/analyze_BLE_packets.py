from scapy.all import *
from scapy.layers.bluetooth4LE import BTLE_ADV, BTLE_ADV_IND

def find_bitchat_advertisements(pcap_file, bitchat_uuid):
    packets = rdpcap(pcap_file)
    found = []
    for pkt in packets:
        if BTLE_ADV in pkt and BTLE_ADV_IND in pkt:  # Advertisement indication
            try:
                adv_data = bytes(pkt[BTLE_ADV_IND].payload)  # Raw adv data
                i = 0
                while i < len(adv_data):
                    length = adv_data[i]
                    if length == 0:
                        break
                    ad_type = adv_data[i + 1]
                    ad_value = adv_data[i + 2 : i + 1 + length]
                    # Check for 128-bit service UUIDs (complete/incomplete list)
                    if ad_type in [0x06, 0x07]:
                        for j in range(0, len(ad_value), 16):
                            uuid_bytes = ad_value[j : j + 16]
                            if len(uuid_bytes) == 16:
                                # Convert to string format (little-endian to big-endian hex)
                                uuid_str = ''.join(f'{b:02x}' for b in reversed(uuid_bytes))
                                uuid_formatted = f"{uuid_str[0:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:32]}"
                                if uuid_formatted.lower() == bitchat_uuid.lower():
                                    mac = pkt.addr if hasattr(pkt, 'addr') else "Unknown"
                                    found.append((mac, pkt.time, uuid_formatted))
                    i += length + 1
            except Exception as e:
                print(f"Error parsing packet: {e}")
    return found

BITCHAT_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"

# Example usage
data_dir = "/Users/blake/repos/Boston-Mesh-Open-Source-Base-Station/data"
pcap_files = ["hackrf_BLE_sniff_20_channels_for_bitchat.pcap"]
for file in pcap_files:
    pcap_file = os.path.join(data_dir, file)
    results = find_bitchat_advertisements(pcap_file, BITCHAT_UUID)
    for mac, timestamp, uuid in results:
        print(f"Found bitchat broadcast: MAC={mac}, Time={timestamp}, UUID={uuid}")