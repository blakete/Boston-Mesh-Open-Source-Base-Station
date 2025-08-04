# Sniffing BLE Packets

After cloning and building the `ice9-bluetooth-sniffer` this is what I ran to do a BLE packet capture on 20 channels:

```console
cd /Users/blake/repos/ice9-bluetooth-sniffer/build
./ice9-bluetooth -l -i hackrf-000000000000000078d063dc2b877067 -c 2427 -C 20 -w <some-unique-name>.pcap
```

```console
# Adv Ch 37 (2402 MHz)
./ice9-bluetooth -l -i hackrf-000000000000000078d063dc2b877067 -c 2402 -C 2 -w adv37.pcap

# Adv Ch 38 (2426 MHz)
./ice9-bluetooth -l -i hackrf-000000000000000078d063dc2b877067 -c 2426 -C 2 -w adv38.pcap

# Adv Ch 39 (2480 MHz)
./ice9-bluetooth -l -i hackrf-000000000000000078d063dc2b877067 -c 2480 -C 2 -w adv39.pcap

# Merge into one file
mergecap -w ble_all_adv.pcap adv37.pcap adv38.pcap adv39.pcap
```

# Analyzing Sniffed Packets

```console
$ capinfos -t -I -E -e ble_all_adv.pcap
File name:           ble_all_adv.pcap
File type:           Wireshark/... - pcapng
File encapsulation:  Bluetooth Low Energy Link Layer RF
Latest packet time:   2025-08-03 21:13:31.694404
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Bluetooth Low Energy Link Layer RF (161 - bluetooth-le-ll-rf)
                     Capture length = 264
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 221
```

## WireShark

* Filtering Wireshark PCAP Display: `_ws.col.info matches "ADV_IND|SCAN_RSP|SCAN_REQ|CONNECT_REQ"`
* Advertisements: ``_ws.col.info matches "ADV_IND|SCAN_RSP"`
* Scanning: `_ws.col.info matches "SCAN_REQ|CONNECT_REQ"`
* Filtering: `_ws.col.info matches "ADV_IND|SCAN_REQ|SCAN_RSP" and not btle.advertising_address == a8:48:fa:70:ea:ea and not btle.advertising_address == 08:eb:ed:68:d6:8d and not btle.advertising_address == d5:18:32:31:04:4b and not btle.advertising_address == d5:38:32:b1:04:4b and not btle.advertising_address == d5:38:32:31:04:4b and not btle.advertising_address == 60:74:f4:50:6a:91 and not btle.advertising_address == b2:13:bc:4b:a3:57 and not btle.advertising_address == d5:38:32:31:00:4b and not btle.advertising_address == d1:38:32:31:04:4b and not btle.advertising_address == a8:48:f2:70:ea:eb and not btle.advertising_address == d5:30:32:31:04:4b and not btle.advertising_address == 40:74:f4:50:6a:91`
    * filtering 2: `_ws.col.info matches "ADV_IND|SCAN_REQ|SCAN_RSP" and (btle.advertising_address == 52:e0:d5:28:6a:91 or btle.advertising_address == 54:4e:54:a1:6f:51)`
    * filtering 3: `btle.advertising_address == 54:4e:54:a1:6f:51`

