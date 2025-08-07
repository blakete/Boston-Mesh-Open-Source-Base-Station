#!/usr/bin/env python3
# pi_bitchat_ble_chat.py — Dual-role BitChat bridge (Raspberry Pi)

from __future__ import annotations
import asyncio, logging, random, time, argparse, threading
from binascii import hexlify
from typing import Optional, Dict, List

from bleak import BleakClient, BleakScanner, BleakGATTCharacteristic
from bluezero import adapter as bz_adapter, peripheral as bz_peripheral

# ───────────── logging ─────────────
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] [%(levelname)s] - %(message)s')

# ────────── BitChat constants ──────
SERVICE_UUID_STR = 'F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C'
CHAR_UUID_STR    = 'A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D'
PROTOCOL_VERSION = 1
DEFAULT_TTL      = 3

MT = {  # enum from the Swift code
    'announce':0x01,'leave':0x03,'message':0x04,
    'versionHello':0x20,'versionAck':0x21,
}
def pkt_name(t:int)->str: return next((k for k,v in MT.items() if v==t),
                                      f'0x{t:02x}')

# ────────── helpers ────────────────
MY_PEER_ID_HEX = ''.join(f'{random.randint(0,255):02x}' for _ in range(8))
MY_PEER_ID     = bytes.fromhex(MY_PEER_ID_HEX)
logging.info(f'My PeerID: {MY_PEER_ID_HEX}')

def u8(x):  return x.to_bytes(1,'big')
def u16(x): return x.to_bytes(2,'big')
def u64(x): return x.to_bytes(8,'big')
def now_ms(): return int(time.time()*1000)
def enc_str(s:str)->bytes:
    b=s.encode()
    return b'\xff'+u16(len(b))+b if len(b)>255 else u8(len(b))+b

# ────────── packet codec ───────────
FLAG_RECIPIENT=1; FLAG_SIGNATURE=2
class Packet:
    def __init__(self, t:int, payload:bytes,
                 *, ttl:int=DEFAULT_TTL,
                 sender:bytes=MY_PEER_ID,
                 recipient:bytes|None=None,
                 ts:int|None=None):
        self.ver=PROTOCOL_VERSION; self.t=t; self.ttl=ttl&0xFF
        self.ts = now_ms() if ts is None else ts
        self.sender = sender[:8].ljust(8,b'\x00')
        self.rec = recipient[:8] if recipient else None
        self.pay = payload or b''
    def to_bytes(self)->bytes:
        flags = FLAG_RECIPIENT if self.rec else 0
        hdr=b''.join([u8(self.ver),u8(self.t),u8(self.ttl),
                      u64(self.ts),u8(flags),u16(len(self.pay))])
        body=[self.sender]
        if self.rec: body.append(self.rec)
        body.append(self.pay)
        return hdr+b''.join(body)
    @classmethod
    def from_bytes(cls,b:bytes):
        if len(b)<21: return None
        v,t,ttl=b[0],b[1],b[2]
        ts=int.from_bytes(b[3:11],'big')
        fl=b[11]; plen=int.from_bytes(b[12:14],'big'); pos=14
        sid=b[pos:pos+8]; pos+=8
        rec=None
        if fl&FLAG_RECIPIENT:
            rec=b[pos:pos+8]; pos+=8
        pay=b[pos:pos+plen]
        return cls(t,pay,ttl=ttl,sender=sid,recipient=rec,ts=ts)

# ─── Version payload helpers ─────────────────────────────────────────────
def build_version_hello()->bytes:
    flags=0; out=bytearray([flags,1,PROTOCOL_VERSION,PROTOCOL_VERSION])
    out+=enc_str('linux_python/0.1')
    out+=enc_str('Linux-Python')
    return bytes(out)

def build_version_ack(agreed:int=PROTOCOL_VERSION)->bytes:
    # flags: no caps, no reason
    flags=0
    out=bytearray([flags,u8(agreed)[0]])
    out+=enc_str('linux_python/0.1')
    out+=enc_str('Linux-Python')
    out+=u8(0)               # rejected? 0 = false
    return bytes(out)

# ─── Peripheral (Bluezero) ───────────────────────────────────────────────
class MeshPeripheral:
    def __init__(self,name='BitChatPi'):
        hci=list(bz_adapter.Adapter.available())[0].address
        self.dev=bz_peripheral.Peripheral(hci,local_name=name,appearance=0)
        self.dev.add_service(1,SERVICE_UUID_STR,True)
        self.dev.add_characteristic(
            1,1,CHAR_UUID_STR,value=[],notifying=False,
            flags=['read','write','write-without-response','notify'],
            read_callback=self.on_read, write_callback=self.on_write)
        self._char_path='/service1/char1'
    def on_read(self): return []
    def on_write(self,val,_):
        data=bytes(val)
        pkt=Packet.from_bytes(data)
        if not pkt: return
        logging.info(f'[P] RX {pkt_name(pkt.t)} from {hexlify(pkt.sender).decode()}')
        # respond to VersionHello with VersionAck
        if pkt.t==MT['versionHello']:
            ack=Packet(MT['versionAck'],build_version_ack()).to_bytes()
            # send via notification
            self.dev.notify(self._char_path,list(ack))
    def publish(self): self.dev.publish()

# ─── Central (Bleak) ─────────────────────────────────────────────────────
async def discover_phone(scan:int, name_filter:str|None, addr:str|None):
    found=None
    def cb(dev,adv):
        nonlocal found
        if found: return
        if SERVICE_UUID_STR.lower() not in (u.lower() for u in (adv.service_uuids or [])): return
        if addr and dev.address.lower()!=addr.lower(): return
        n=adv.local_name or dev.name or 'phone'
        if name_filter and name_filter.lower() not in n.lower(): return
        logging.info(f'Found {dev.address} {n} RSSI={adv.rssi}')
        found=(dev,adv)
    sc=BleakScanner(cb); await sc.start()
    for _ in range(scan*5):
        await asyncio.sleep(0.2)
        if found: break
    await sc.stop()
    if not found: raise RuntimeError('no phone')
    return found[0]

async def central_handshake(nick:str,scan:int,name_filter:str|None,addr:str|None):
    dev = await discover_phone(scan,name_filter,addr)
    logging.info(f'Connect {dev.address} …')
    async with BleakClient(dev,timeout=30) as cli:
        if not cli.is_connected: raise RuntimeError('connect fail')
        svcs=await (cli.get_services() if hasattr(cli,'get_services') else cli.services)
        # search every characteristic once; ignore duplicate services
        char:BleakGATTCharacteristic|None=None
        for c in svcs.characteristics.values():
            if c.uuid.lower()==CHAR_UUID_STR.lower() and \
               'write-without-response' in c.properties:
                char=c; break
        if not char: raise RuntimeError('char not found')
        vh=Packet(MT['versionHello'],build_version_hello()).to_bytes()
        await cli.write_gatt_char(char,vh,response=False)
        await asyncio.sleep(0.25)
        ann=Packet(MT['announce'],nick.encode()).to_bytes()
        await cli.write_gatt_char(char,ann,response=False)
        async def on_notify(_,d):
            pkt=Packet.from_bytes(bytes(d))
            if pkt: logging.info(f'[C] RX {pkt_name(pkt.t)}')
        try:
            await cli.start_notify(char,on_notify)
        except Exception: pass
        await asyncio.sleep(2)

# ─── run both roles ──────────────────────────────────────────────────────
async def run(nick:str,scan:int,name_filter:str|None,addr:str|None,dump:bool):
    threading.Thread(target=MeshPeripheral().publish,daemon=True).start()
    await asyncio.sleep(1)
    while True:
        try:
            await central_handshake(nick,scan,name_filter,addr)
            logging.info('idle …'); await asyncio.sleep(30)
        except (KeyboardInterrupt,asyncio.CancelledError): raise
        except Exception as e:
            logging.error(e); await asyncio.sleep(3)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--nickname',default='PiRelay')
    ap.add_argument('--scan-seconds',type=int,default=15)
    ap.add_argument('--name-contains',default=None)
    ap.add_argument('--address',default=None)
    ap.add_argument('--dump-gatt',action='store_true')
    a=ap.parse_args()
    asyncio.run(run(a.nickname,a.scan_seconds,a.name_contains,a.address,a.dump_gatt))

if __name__=='__main__':
    main()
