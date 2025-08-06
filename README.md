## Open BitChat Mesh Station – Open Source BitChat Relay & Base Station

Open Source 🛠️  Decentralized 🌐  Encrypted 🔐  Uncensorable 🗣️  Unstoppable 🚀

**Part of the [Boston Mesh Project](https://primal.net/p/nprofile1qqsfccxvukwe8vnqwcd6t5l4kvjnl32jt6spcjpv6w7whyx54s9uhzs8v35q7)**

An open-source **relay & base station node** for the [BitChat](https://github.com/permissionlesstech/bitchat/tree/main) peer-to-peer messaging protocol.  
Built to extend BitChat’s range, reliability, and resilience across Boston—and beyond!

---

### What is a BitChat Meshstation?  
A BitChat Meshstation acts as a **central hub** or **anchor point** in your mesh network. Unlike portable peers, it stays power-and-antenna-equipped in one spot, providing a rock-solid rendezvous for mobile nodes.  
- **Always-on & stable**: high-quality BLE dongle (or long-range radio), reliable power, and ample processing headroom.  
- **Relay & store-and-forward**: picks up encrypted BitChat packets, rebroadcasts them to extend range, and queues messages for offline peers.  
- **Bridges islands**: uses both P2P radio links (BLE/LoRa/etc.) and existing Internet/LAN backhaul to connect distant clusters into one unified mesh.

---

### 🎯 Initial Goal  
Build a **cheap, open-source** BitChat base station & relay to extend peer discovery and messaging across Boston.  
- **Client links**: phones connect via **BLE** or **LAN/IP** (e.g., at home).  
- **Backhaul**: the Meshstation leverages **P2P radio** and **Internet infrastructure** to join and maintain the wider mesh network.

---

## References
- **BitChat Whitepaper** – https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md  
- **BitChat for iOS** – https://github.com/permissionlesstech/bitchat  
- **BitChat for Android (Kotlin)** – https://github.com/permissionlesstech/bitchat-android  
- **Noise Protocol Framework** – https://www.noiseprotocol.org/
  
