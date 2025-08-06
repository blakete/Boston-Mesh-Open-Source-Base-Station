filter: 
    * `btle.advertising_header.pdu_type == 0x04 and !(btcommon.eir_ad.entry.company_id == 0x058e)`
    * `_ws.col.info matches "ADV_IN|SCAN_REQ|SCAN_RSP" and btcommon.eir_ad.entry.company_id == 0x004c and bluetooth.src == 66:ec:0e:84:4f:6e`

---

```
Frame 237: 46 bytes on wire (368 bits), 46 bytes captured (368 bits)
Bluetooth
    [Source: 66:ec:0e:84:4f:6e (66:ec:0e:84:4f:6e)]
    [Destination: Broadcast (ff:ff:ff:ff:ff:ff)]
Bluetooth Low Energy RF Info
Bluetooth Low Energy Link Layer
    Access Address: 0x8e89bed6
    Packet Header: 0x1b44 (PDU Type: SCAN_RSP, TxAdd: Random)
        .... 0100 = PDU Type: 0x4 SCAN_RSP
        ...0 .... = Reserved: 0
        ..0. .... = Reserved: 0
        .1.. .... = Tx Address: Random
        0... .... = Reserved: 0
        Length: 27
    Advertising Address: 66:ec:0e:84:4f:6e (66:ec:0e:84:4f:6e)
    Scan Response Data: 14ff4c000100000000000000000000000080000000
        Advertising Data
            Manufacturer Specific
                Length: 20
                Type: Manufacturer Specific (0xff)
                Company ID: Apple, Inc. (0x004c)
                Data: 0100000000000000000000000080000000
                    [Expert Info (Note/Undecoded): Undecoded]
                        [Undecoded]
                        [Severity level: Note]
                        [Group: Undecoded]
    CRC: 0xa4ced9

```

---

```
Frame 291: 46 bytes on wire (368 bits), 46 bytes captured (368 bits)
Bluetooth
    [Source: 66:ec:0e:84:6f:6e (66:ec:0e:84:6f:6e)]
    [Destination: Broadcast (ff:ff:ff:ff:ff:ff)]
Bluetooth Low Energy RF Info
Bluetooth Low Energy Link Layer
    Access Address: 0x8e89bed6
    Packet Header: 0x1b44 (PDU Type: SCAN_RSP, TxAdd: Random)
        .... 0100 = PDU Type: 0x4 SCAN_RSP
        ...0 .... = Reserved: 0
        ..0. .... = Reserved: 0
        .1.. .... = Tx Address: Random
        0... .... = Reserved: 0
        Length: 27
    Advertising Address: 66:ec:0e:84:6f:6e (66:ec:0e:84:6f:6e)
    Scan Response Data: 14fd4c000100000080000000000000000080002080
        Advertising Data
            Unknown
                Length: 20
                Type: Unknown (0xfd)
                Data: 4c000100000080000000000000000080002080
                    [Expert Info (Warning/Protocol): Unknown data]
                        [Unknown data]
                        [Severity level: Warning]
                        [Group: Protocol]
    CRC: 0xa4ced9
        [Expert Info (Warning/Checksum): Incorrect CRC]
            [Incorrect CRC]
            [Severity level: Warning]
            [Group: Checksum]

```

---

```
Frame 2725: 46 bytes on wire (368 bits), 46 bytes captured (368 bits)
Bluetooth
    [Source: 66:e4:0e:84:4f:6e (66:e4:0e:84:4f:6e)]
    [Destination: Broadcast (ff:ff:ff:ff:ff:ff)]
Bluetooth Low Energy RF Info
Bluetooth Low Energy Link Layer
    Access Address: 0x8e89bed6
    Packet Header: 0x1b44 (PDU Type: SCAN_RSP, TxAdd: Random)
        .... 0100 = PDU Type: 0x4 SCAN_RSP
        ...0 .... = Reserved: 0
        ..0. .... = Reserved: 0
        .1.. .... = Tx Address: Random
        0... .... = Reserved: 0
        Length: 27
    Advertising Address: 66:e4:0e:84:4f:6e (66:e4:0e:84:4f:6e)
    Scan Response Data: 14ff44000120000000020000000000000080000000
        Advertising Data
            Manufacturer Specific
                Length: 20
                Type: Manufacturer Specific (0xff)
                Company ID: Socket Mobile (0x0044)
                Data: 0120000000020000000000000080000000
                    [Expert Info (Note/Undecoded): Undecoded]
                        [Undecoded]
                        [Severity level: Note]
                        [Group: Undecoded]
    CRC: 0xa4ccd9
        [Expert Info (Warning/Checksum): Incorrect CRC]
            [Incorrect CRC]
            [Severity level: Warning]
            [Group: Checksum]
```

---

```
Frame 2592: 46 bytes on wire (368 bits), 46 bytes captured (368 bits)
Bluetooth
    [Source: 66:ec:0e:84:4f:6e (66:ec:0e:84:4f:6e)]
    [Destination: Broadcast (ff:ff:ff:ff:ff:ff)]
Bluetooth Low Energy RF Info
Bluetooth Low Energy Link Layer
    Access Address: 0x8e89bed6
    Packet Header: 0x1b44 (PDU Type: SCAN_RSP, TxAdd: Random)
        .... 0100 = PDU Type: 0x4 SCAN_RSP
        ...0 .... = Reserved: 0
        ..0. .... = Reserved: 0
        .1.. .... = Tx Address: Random
        0... .... = Reserved: 0
        Length: 27
    Advertising Address: 66:ec:0e:84:4f:6e (66:ec:0e:84:4f:6e)
    Scan Response Data: 14ff4c000100000000000000000000000080000000
        Advertising Data
            Manufacturer Specific
                Length: 20
                Type: Manufacturer Specific (0xff)
                Company ID: Apple, Inc. (0x004c)
                Data: 0100000000000000000000000080000000
                    [Expert Info (Note/Undecoded): Undecoded]
                        [Undecoded]
                        [Severity level: Note]
                        [Group: Undecoded]
    CRC: 0xa4ced9
```
