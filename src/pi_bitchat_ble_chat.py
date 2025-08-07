#!/usr/bin/env python3
"""
Dual-role BitChat BLE bridge for Raspberry Pi
  • Bluezero peripheral  → iPhone can write to us
  • Bleak   central      → we send VersionHello + Announce
"""

from __future__ import annotations
import asyncio, logging, time, argparse, threading
from binascii import hexlify
from typing import Optional, Dict, List

# ─── 3rd-party ────────────────────────────────────────────────────────────────
from bleak import BleakClient, BleakScanner, BleakGATTCharacteristic, BleakError
from bluezero import adapter as bz_adapter, peripheral as bz_peripheral

# ─── logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] [%(levelname)s] - %(message)s')

# ─── BitChat constants ────────────────────────────────────────────────────────
SERVICE_UUID_STR = 'F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C'
CHAR_UUID_STR    = 'A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D'
PROTOCOL_VERSION = 1
DEFAULT_TTL      = 3

MT = {  # Message-type table
    'announce':0x01,'leave':0x03,'message':0x04,
    'fragmentStart':0x05,'fragmentContinue':0x06,'fragmentEnd':0x07,
    'deliveryAck':0x0A,'deliveryStatusRequest':0x0B,'readReceipt':0x0C,
    'noiseHandshakeInit':0x10,'noiseHandshakeResp':0x11,'noiseEncrypted':0x12,
    'noiseIdentityAnnounce':0x13,
    'versionHello':0x20,'versionAck':0x21,
    'protocolAck':0x22,'protocolNack':0x23,
    'systemValidation':0x24,'handshakeRequest':0x25
}
def pkt_type_name(t:int)->str:                     # pretty-print helper
    return next((k for k,v in MT.items() if v==t), f'0x{t:02x}')

# ─── helpers ──────────────────────────────────────────────────────────────────
# Static PeerID
MY_PEER_ID_HEX = '731976a98540396b'  # Fixed
MY_PEER_ID     = bytes.fromhex(MY_PEER_ID_HEX)
logging.info(f'My PeerID: {MY_PEER_ID_HEX}')

PEER_NICKS: Dict[str,str] = {}
HEXSET = set(b'0123456789abcdefABCDEF')
def looks_hex_ascii(b:bytes)->bool: return len(b)>0 and all(c in HEXSET for c in b)

def u8(x):  return x.to_bytes(1,'big')
def u16(x): return x.to_bytes(2,'big')
def u64(x): return x.to_bytes(8,'big')
def now_ms(): return int(time.time()*1000)
def enc_str(s:str)->bytes:
    b=s.encode();  return b'\xff'+u16(len(b))+b if len(b)>255 else u8(len(b))+b
def sanitize_oneline(s:str)->str: return s.replace('\r',' ').replace('\n',' ').strip()

def read_len_str(buf:bytes,pos:int,*,prefer_one_byte=True,one_byte_max=64):
    n=len(buf)
    if pos>=n: raise ValueError('OOB')
    def t1(p):
        if p>=n: return None
        L=buf[p]; end=p+1+L
        if L<=one_byte_max and end<=n:
            return buf[p+1:end].decode(),end
    def t2(p):
        if p+2>n: return None
        L=int.from_bytes(buf[p:p+2],'big'); end=p+2+L
        if end<=n: return buf[p+2:end].decode(),end
    v=t1(pos) if prefer_one_byte else t2(pos)
    if v is None: v=t2(pos) if prefer_one_byte else t1(pos)
    if v is None: raise ValueError('decode fail')
    return v

def plausible_epoch_ms(ms): return 1420070400000<=ms<=2051222400000
def decode_broadcast_message(payload:bytes)->dict:
    pos = 9 if len(payload)>=9 and plausible_epoch_ms(int.from_bytes(payload[1:9],'big')) else 0
    sender,pos = read_len_str(payload,pos,prefer_one_byte=True)
    text,pos   = read_len_str(payload,pos,prefer_one_byte=False)
    sender_peer=None
    if pos<len(payload) and 8<=payload[pos]<=32 and pos+1+payload[pos]<=len(payload):
        cand=payload[pos+1:pos+1+payload[pos]]
        if looks_hex_ascii(cand): sender_peer,_ = read_len_str(payload,pos)
    return {'sender':sender,'content':text,'senderPeerID':sender_peer}

def update_peer_nick(peer_hex:str,nick:str):
    nick=nick.strip()
    prev=PEER_NICKS.get(peer_hex)
    if nick and nick!=prev:
        PEER_NICKS[peer_hex]=nick
        logging.info(('👋 Peer appeared: %s (nick: @%s)'%(peer_hex,nick))
                     if prev is None else
                     f'🔄 Peer nick updated: {peer_hex}: {prev} → {nick}')

# ─── Packet codec ─────────────────────────────────────────────────────────────
FLAG_HAS_RECIPIENT=1; FLAG_HAS_SIGNATURE=2
class BitchatPacket:
    def __init__(self,type_u8:int,payload:bytes,*,ttl:int=DEFAULT_TTL,
                 sender_id:bytes=MY_PEER_ID,
                 recipient_id:Optional[bytes]=None,
                 signature:Optional[bytes]=None,
                 timestamp_ms:Optional[int]=None,
                 version:int=PROTOCOL_VERSION):
        self.version=version; self.type=type_u8; self.ttl=ttl&0xFF
        self.timestamp=now_ms() if timestamp_ms is None else int(timestamp_ms)
        self.sender_id=sender_id[:8].ljust(8,b'\x00')
        self.recipient_id=recipient_id[:8] if recipient_id else None
        self.payload=payload or b''; self.signature=signature
    def to_bytes(self)->bytes:
        flags = (FLAG_HAS_RECIPIENT if self.recipient_id else 0) | \
                (FLAG_HAS_SIGNATURE if self.signature else 0)
        hdr=b''.join([u8(self.version),u8(self.type),u8(self.ttl),
                      u64(self.timestamp),u8(flags),u16(len(self.payload))])
        body=[self.sender_id]
        if self.recipient_id: body.append(self.recipient_id)
        body.append(self.payload)
        if self.signature:
            if len(self.signature)!=64: raise ValueError
            body.append(self.signature)
        return hdr+b''.join(body)
    @classmethod
    def from_bytes(cls,data:bytes):
        try:
            if len(data)<21: return None
            v,t,ttl = data[0],data[1],data[2]
            ts      = int.from_bytes(data[3:11],'big')
            fl      = data[11]
            plen    = int.from_bytes(data[12:14],'big')
            pos     = 14
            sid     = data[pos:pos+8]; pos+=8
            rid=None
            if fl&FLAG_HAS_RECIPIENT:
                rid=data[pos:pos+8]; pos+=8
            payload=data[pos:pos+plen]; pos+=plen
            sig=None
            if fl&FLAG_HAS_SIGNATURE:
                sig=data[pos:pos+64]
            return cls(t,payload,ttl=ttl,sender_id=sid,
                       recipient_id=rid,signature=sig,
                       timestamp_ms=ts,version=v)
        except Exception:
            return None

# ─── VersionHello payload ────────────────────────────────────────────────────
def build_version_hello_payload(client_ver='linux_python/0.1',
                                platform='Linux-Python',
                                caps:Optional[List[str]]=None)->bytes:
    caps=caps or []; flags=0x01 if caps else 0
    out=bytearray([flags,1,PROTOCOL_VERSION,PROTOCOL_VERSION])
    out+=enc_str(client_ver)+enc_str(platform)
    if caps:
        out.append(len(caps))
        for c in caps: out+=enc_str(c)
    return bytes(out)

# ─── VersionAck payload ──────────────────────────────────────────────────────
def build_version_ack_payload(agreed_version: int = PROTOCOL_VERSION,
                              server_ver: str = 'linux_python/0.1',
                              platform: str = 'Linux-Python',
                              capabilities: Optional[List[str]] = None,
                              rejected: bool = False,
                              reason: Optional[str] = None) -> bytes:
    capabilities = capabilities or []
    flags = 0
    if capabilities:
        flags |= 0x01
    if reason:
        flags |= 0x02
    out = bytearray([flags])
    out += u8(agreed_version)
    out += enc_str(server_ver)
    out += enc_str(platform)
    out += u8(1 if rejected else 0)
    if capabilities:
        out += u8(len(capabilities))
        for cap in capabilities:
            out += enc_str(cap)
    if reason:
        out += enc_str(reason)
    return bytes(out)

# ─── Bluezero Peripheral (server) ─────────────────────────────────────────────
class BitChatPeripheral:
    def __init__(self,local_name='BitChatPi'):
        adapter_addr=list(bz_adapter.Adapter.available())[0].address
        self.dev=bz_peripheral.Peripheral(adapter_addr,local_name=local_name,appearance=0)
        self.dev.add_service(srv_id=1,uuid=SERVICE_UUID_STR,primary=True)
        self.dev.add_characteristic(
            srv_id=1, chr_id=1, uuid=CHAR_UUID_STR,
            value=[], notifying=True,
            flags=['read','write','write-without-response','notify'],
            read_callback=self._on_read,
            write_callback=self._on_write,
            notify_callback=None
        )
    def _on_read(self):                   # must return list[int]
        return self.dev.get_characteristic(1,1).value
    def _on_write(self,value,_options=None):
        data=bytes(value)
        pkt=BitchatPacket.from_bytes(data)
        if not pkt:
            logging.info(f'[P] undecodable {hexlify(data)[:60].decode()}…')
            return
        sh=hexlify(pkt.sender_id).decode()
        logging.info(f'[P] RX {pkt_type_name(pkt.type)} from {sh} - Payload: {pkt.payload}')
        if pkt.type==MT['announce']:
            nick=pkt.payload.decode('utf-8','ignore').strip()
            if nick and sh!=MY_PEER_ID_HEX:
                update_peer_nick(sh,nick)
        elif pkt.type==MT['message']:
            info=decode_broadcast_message(pkt.payload)
            disp=PEER_NICKS.get(sh) or info['sender'] or sh
            logging.info(f'💬 [P] @{disp}: {sanitize_oneline(info["content"])}')
        # Respond if VersionHello
        if pkt.type == MT['versionHello']:
            ack_payload = build_version_ack_payload()
            ack_pkt = BitchatPacket(MT['versionAck'], ack_payload).to_bytes()
            self.dev.notify(1, ack_pkt)  # chr_id=1
            logging.info(f'[P] Sent VersionAck to {sh} via notify')
    def publish_forever(self):
        self.dev.publish()               # blocks inside GLib loop

# ─── Bleak Central (client) ───────────────────────────────────────────────────
async def maybe_get_services(cli:BleakClient):
    return await cli.get_services() if hasattr(cli,'get_services') else cli.services

async def scan_for_phone(scan_s:int,
                         name_filter:Optional[str],
                         addr:Optional[str]):
    chosen=None
    def _cb(dev,adv):
        nonlocal chosen
        if chosen: return
        if SERVICE_UUID_STR.lower() not in (u.lower() for u in (adv.service_uuids or [])):
            return
        if addr and dev.address.lower()!=addr.lower(): return
        if adv.rssi <= -127: return
        n=adv.local_name or dev.name or 'Unknown'
        logging.info(f"Found {dev.address} '{n}' RSSI={adv.rssi}")
        if name_filter and name_filter.lower() not in n.lower(): return
        chosen=(dev,adv)
    scanner=BleakScanner(_cb)
    logging.info('Scanning for BitChat phone …')
    await scanner.start()
    for _ in range(max(1,scan_s*5)):
        await asyncio.sleep(0.2)
        if chosen:
            break
    await scanner.stop()
    if not chosen:
        raise RuntimeError('No BitChat peripheral found')
    return chosen

async def central_handshake(nick:str,scan_s:int,
                            name_filter:Optional[str],
                            addr:Optional[str],
                            dump:bool, cli: BleakClient, char: BleakGATTCharacteristic):
    # VersionHello
    version_hello_pkt = BitchatPacket(MT['versionHello'], build_version_hello_payload()).to_bytes()
    await cli.write_gatt_char(char, version_hello_pkt, response=False)
    logging.info('Sent VersionHello')
    await asyncio.sleep(0.25)

    # Announce
    announce_pkt = BitchatPacket(MT['announce'], nick.encode()).to_bytes()
    await cli.write_gatt_char(char, announce_pkt, response=False)
    logging.info('Sent Announce')

    # Periodic keep-alive
    while True:
        await asyncio.sleep(10)
        await cli.write_gatt_char(char, announce_pkt, response=False)
        logging.info('Sent keep-alive Announce')

async def _on_notify(_, data, cli: BleakClient, char: BleakGATTCharacteristic):
    pkt = BitchatPacket.from_bytes(bytes(data))
    if pkt:
        logging.info(f'[C] RX {pkt_type_name(pkt.type)} - Payload: {pkt.payload}')
        if pkt.type == MT['versionHello']:
            ack_payload = build_version_ack_payload()
            ack_pkt = BitchatPacket(MT['versionAck'], ack_payload).to_bytes()
            await cli.write_gatt_char(char, ack_pkt, response=False)
            logging.info('Sent VersionAck')

# ─── orchestrate ──────────────────────────────────────────────────────────────
async def run_dual(nick:str,scan_s:int,name_filter:Optional[str],
                   addr:Optional[str],dump:bool):
    threading.Thread(target=BitChatPeripheral().publish_forever,
                     daemon=True).start()
    await asyncio.sleep(1)              # allow advertising to start
    cycle=0
    while True:
        try:
            dev,_ = await scan_for_phone(scan_s,name_filter,addr)
            logging.info(f'Connecting to {dev.address} …')
            async with BleakClient(dev,timeout=60) as cli:
                if not cli.is_connected: raise RuntimeError('connect failed')
                services = await maybe_get_services(cli)
                if dump:
                    for s in services:
                        logging.info(f'SVC {s.uuid}')
                        for c in s.characteristics:
                            logging.info(f'  CHAR {c.uuid} {c.properties}')
                bit_chat_services = [s for s in services if s.uuid.lower() == SERVICE_UUID_STR.lower()]
                if not bit_chat_services:
                    raise RuntimeError('No BitChat service found')

                success = False
                for svc in bit_chat_services:
                    try:
                        char = next((c for c in svc.characteristics if 'write-without-response' in c.properties and 'notify' in c.properties), None)
                        if not char: continue

                        await cli.start_notify(char, lambda s, d: asyncio.create_task(_on_notify(s, d, cli, char)))
                        logging.info(f'Notify enabled on char handle {char.handle}')

                        asyncio.create_task(central_handshake(nick, scan_s, name_filter, addr, dump, cli, char))

                        logging.info('Handshake done; maintaining connection …')
                        success = True
                        while True:
                            await asyncio.sleep(30)
                    except BleakError as e:
                        logging.warning(f'Failed on service {svc.uuid}: {e} - Trying next')
                if not success:
                    raise RuntimeError('Failed on all services')
        except (asyncio.CancelledError,KeyboardInterrupt):
            raise
        except Exception as e:
            cycle+=1
            logging.error(f'cycle {cycle} failed: {e}')
            await asyncio.sleep(3)

# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--nickname',default='PiRelay')
    ap.add_argument('--scan-seconds',type=int,default=15)
    ap.add_argument('--name-contains',default=None)
    ap.add_argument('--address',dest='pin_address',default=None)
    ap.add_argument('--dump-gatt',action='store_true')
    a=ap.parse_args()
    logging.info(f'Nickname: @{a.nickname}')
    try:
        asyncio.run(run_dual(a.nickname,
                             a.scan_seconds,
                             a.name_contains,
                             a.pin_address,
                             a.dump_gatt))
    except KeyboardInterrupt:
        logging.info('Exiting…')

if __name__ == '__main__':
    main()