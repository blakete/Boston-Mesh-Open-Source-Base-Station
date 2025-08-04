"""
Filtering Wireshark PCAP Display: `_ws.col.info matches "ADV_IND|SCAN_RSP|SCAN_REQ|CONNECT_REQ"`
Advertisements: ``_ws.col.info matches "ADV_IND|SCAN_RSP"`
Scanning: `_ws.col.info matches "SCAN_REQ|CONNECT_REQ"`

Filtering: `_ws.col.info matches "ADV_IND|SCAN_RSP" and not btle.advertising_address == a8:48:fa:70:ea:ea`
"""