Source: `bitchat/bitchat/Services/BluetoothMeshService.swift`

| Packet Type | Description | Purpose in BitChat Mesh Network |
|-------------|-------------|---------------------------------|
| **ADV_IND** | Connectable undirected advertising packet on primary channels (37, 38, 39), containing flags and possibly part of the advertisement data like service UUID or local name. | Primary advertising packet sent by BitChat when acting as peripheral to broadcast presence, service UUID "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C", and ephemeral `myPeerID` as local name. Enables discovery by nearby devices. Called in `startAdvertising()`. |
| **SCAN_RSP** | Scan response packet sent in response to SCAN_REQ, containing additional data that didn't fit in ADV_IND, such as full local name or service UUID if overflowed. | Provides extra advertisement data like the full 16-byte `myPeerID` local name if not fitted in ADV_IND. CoreBluetooth automatically handles splitting data between ADV_IND and SCAN_RSP. |
| **CONNECT_REQ** | Connection request packet on primary channels to establish a connection with an advertiser. | Sent by BitChat when acting as central to connect to discovered peripherals advertising the BitChat service. Triggered in `didDiscover peripheral` after deciding to connect. Forms direct links in the mesh. |
| **SCAN_REQ** (sent by BitChat as scanner) | Scan request packet to request additional data from scannable advertisers. | Sent automatically by CoreBluetooth when scanning if the advertiser's ADV_IND is scannable and data is needed (e.g., for full local name). Helps gather complete advertisement data before connecting. 

---

Based on the code from `bitchat/bitchat/Services/BluetoothMeshService.swift`, the types of BLE packets used by BitChat to scan for and advertise to nearby local peers are:

- **Advertising (Peripheral Mode)**: Primarily ADV_IND packets on primary channels (37, 38, 39) to broadcast presence, including the service UUID "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C" and ephemeral `myPeerID` (16-hex local name). SCAN_RSP packets are implicitly used by CoreBluetooth if additional data overflows ADV_IND.

- **Scanning and Connecting (Central Mode)**: Receives ADV_IND from advertisers; may send SCAN_REQ for more data if the advertiser supports it; sends CONNECT_REQ to initiate connections with discovered peripherals matching the service UUID.

These enable peer discovery and mesh formation via dual central/peripheral roles.