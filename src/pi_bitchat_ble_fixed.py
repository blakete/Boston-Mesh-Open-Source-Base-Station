#!/usr/bin/env python3
# pi_bitchat_ble.py — robust notify/handshake for BitChat on Linux/BlueZ (iOS peripheral)
from __future__ import annotations

import asyncio, logging, random, time, argparse
from binascii import hexlify
from typing import Optional, Tuple, Dict, List
from bleak import BleakScanner, BleakClient, BleakError

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

SERVICE_UUID_STR = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
DEFAULT_CHAR_UUID_GUESS = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

MT = {
    "announce": 0x01, "leave": 0x03, "message": 0x04,
    "fragmentStart": 0x05, "fragmentContinue": 0x06, "fragmentEnd": 0x07,
    "deliveryAck": 0x0A, "deliveryStatusRequest": 0x0B, "readReceipt": 0x0C,
    "noiseHandshakeInit": 0x10, "noiseHandshakeResp": 0x11, "noiseEncrypted": 0x12,
    "noiseIdentityAnnounce": 0x13, "versionHello": 0x20, "versionAck": 0x21,
    "protocolAck": 0x22, "protocolNack": 0x23, "systemValidation": 0x24, "handshakeRequest": 0x25,
}
FLAG_HAS_RECIPIENT  = 0x01
FLAG_HAS_SIGNATURE  = 0x02
PROTOCOL_VERSION = 1
DEFAULT_TTL = 3

MY_PEER_ID_HEX = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))
MY_PEER_ID = bytes.fromhex(MY_PEER_ID_HEX)
logging.info(f"My PeerID: {MY_PEER_ID_HEX}")

PEER_NICKS: Dict[str, str] = {}
HEXSET = set(b"0123456789abcdefABCDEF")

def looks_hex_ascii(b: bytes) -> bool: return len(b) > 0 and all(ch in HEXSET for ch in b)
def sanitize_oneline(s: str) -> str: return s.replace("\r", " ").replace("\n", " ").strip()
def u8(x: int) -> bytes:  return x.to_bytes(1, "big", signed=False)
def u16(x: int) -> bytes: return x.to_bytes(2, "big", signed=False)
def u64(x: int) -> bytes: return x.to_bytes(8, "big", signed=False)
def now_ms() -> int:      return int(time.time() * 1000)

def enc_str(s: str) -> bytes:
    b = s.encode("utf-8")
    if len(b) > 255: return b"\xff" + u16(len(b)) + b
    return u8(len(b)) + b

def dec_str(buf: bytes, pos: int) -> Tuple[str, int]:
    if pos >= len(buf): raise ValueError("string pos OOB")
    L = buf[pos]
    if L != 0xFF:
        pos += 1; end = pos + L
        if end > len(buf): raise ValueError("string len OOB")
        return buf[pos:end].decode("utf-8", "ignore"), end
    if pos + 3 > len(buf): raise ValueError("string len2 OOB")
    L2 = int.from_bytes(buf[pos+1:pos+3], "big"); pos += 3
    end = pos + L2
    if end > len(buf): raise ValueError("string len2 OOB2")
    return buf[pos:end].decode("utf-8", "ignore"), end

def safe_utf8(b: bytes) -> str:
    try:
        s = b.decode("utf-8")
        if any(ord(ch) < 0x20 and ch not in "\t\r\n" for ch in s): return ""
        return s
    except Exception:
        return ""

class BitchatPacket:
    def __init__(self, type_u8: int, payload: bytes, *,
                 ttl: int = DEFAULT_TTL, sender_id: bytes = MY_PEER_ID,
                 recipient_id: Optional[bytes] = None, signature: Optional[bytes] = None,
                 timestamp_ms: Optional[int] = None, version: int = PROTOCOL_VERSION):
        self.version = version; self.type = type_u8; self.ttl = ttl & 0xFF
        self.timestamp = now_ms() if timestamp_ms is None else int(timestamp_ms)
        self.sender_id = sender_id[:8].ljust(8, b"\x00")
        self.recipient_id = recipient_id[:8] if recipient_id else None
        self.payload = payload or b""; self.signature = signature if signature else None
    def to_bytes(self) -> bytes:
        flags = 0
        if self.recipient_id is not None: flags |= FLAG_HAS_RECIPIENT
        if self.signature is not None:    flags |= FLAG_HAS_SIGNATURE
        header = b"".join([u8(self.version), u8(self.type), u8(self.ttl),
                           u64(self.timestamp), u8(flags), u16(len(self.payload))])
        body = [self.sender_id]
        if self.recipient_id is not None: body.append(self.recipient_id)
        body.append(self.payload)
        if self.signature is not None:
            if len(self.signature) != 64: raise ValueError("signature must be 64 bytes")
            body.append(self.signature)
        return header + b"".join(body)
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["BitchatPacket"]:
        try:
            if len(data) < 13 + 8: return None
            pos = 0
            version = data[pos]; pos += 1
            type_u8 = data[pos]; pos += 1
            ttl = data[pos]; pos += 1
            timestamp = int.from_bytes(data[pos:pos+8], "big"); pos += 8
            flags = data[pos]; pos += 1
            payload_len = int.from_bytes(data[pos:pos+2], "big"); pos += 2
            if pos + 8 > len(data): return None
            sender_id = data[pos:pos+8]; pos += 8
            recipient_id = None
            if flags & FLAG_HAS_RECIPIENT:
                if pos + 8 > len(data): return None
                recipient_id = data[pos:pos+8]; pos += 8
            if pos + payload_len > len(data): return None
            payload = data[pos:pos+payload_len]; pos += payload_len
            signature = None
            if flags & FLAG_HAS_SIGNATURE:
                if pos + 64 > len(data): return None
                signature = data[pos:pos+64]; pos += 64
            return cls(type_u8=type_u8, payload=payload, ttl=ttl, sender_id=sender_id,
                       recipient_id=recipient_id, signature=signature,
                       timestamp_ms=timestamp, version=version)
        except Exception as e:
            logging.error(f"Decode error: {e}")
            return None

def build_version_hello_payload(client_version: str = "linux_python/0.1",
                                platform: str = "Linux-Python",
                                capabilities: Optional[List[str]] = None) -> bytes:
    flags = 0; caps = capabilities or []
    if caps: flags |= 0x01
    supported = [PROTOCOL_VERSION]; preferred = PROTOCOL_VERSION
    out = bytearray()
    out += u8(flags); out += u8(len(supported))
    for v in supported: out += u8(v)
    out += u8(preferred); out += enc_str(client_version); out += enc_str(platform)
    if caps:
        out += u8(len(caps))
        for c in caps: out += enc_str(c)
    return bytes(out)

def parse_version_ack_payload(data: bytes) -> dict:
    try:
        pos = 0
        flags = data[pos]; pos += 1
        has_caps = (flags & 0x01) != 0; has_reason = (flags & 0x02) != 0
        agreed = data[pos]; pos += 1
        server_version, pos = dec_str(data, pos)
        platform, pos       = dec_str(data, pos)
        rejected = data[pos] != 0; pos += 1
        caps = []
        if has_caps:
            cap_count = data[pos]; pos += 1
            for _ in range(cap_count):
                s, pos = dec_str(data, pos); caps.append(s)
        reason = None
        if has_reason: reason, pos = dec_str(data, pos)
        return {"agreedVersion": agreed, "serverVersion": server_version,
                "platform": platform, "rejected": rejected,
                "capabilities": caps, "reason": reason}
    except Exception:
        return {}

def plausible_epoch_ms(ms: int) -> bool: return 1420070400000 <= ms <= 2051222400000

def read_len_str(buf: bytes, pos: int, *, prefer_one_byte: bool = True, one_byte_max: int = 64) -> Tuple[str, int]:
    n = len(buf)
    if pos >= n: raise ValueError("read_len_str: pos OOB")
    def try_1byte(p: int):
        if p >= n: return None
        L = buf[p]; end = p + 1 + L
        if L <= one_byte_max and end <= n: return buf[p+1:end].decode("utf-8", "ignore"), end
        return None
    def try_2byte(p: int):
        if p + 2 > n: return None
        L2 = int.from_bytes(buf[p:p+2], "big"); end = p + 2 + L2
        if end <= n: return buf[p+2:end].decode("utf-8", "ignore"), end
        return None
    if prefer_one_byte:
        v = try_1byte(pos); v = v or try_2byte(pos)
    else:
        v = try_2byte(pos); v = v or try_1byte(pos)
    if v is None: raise ValueError(f"read_len_str: cannot decode at pos {pos}")
    return v

def decode_broadcast_message(payload: bytes) -> dict:
    pos = 0; n = len(payload)
    if n >= 9:
        ts = int.from_bytes(payload[1:9], "big")
        if plausible_epoch_ms(ts): pos = 9
    sender, pos = read_len_str(payload, pos, prefer_one_byte=True)
    content, pos = read_len_str(payload, pos, prefer_one_byte=False)
    sender_peer = None
    if pos < n:
        L = payload[pos]
        if 8 <= L <= 32 and pos + 1 + L <= n:
            cand = payload[pos+1:pos+1+L]
            if looks_hex_ascii(cand):
                try:
                    sender_peer, pos = read_len_str(payload, pos, prefer_one_byte=True)
                except Exception:
                    sender_peer = cand.decode("ascii", "ignore")
    if pos < n:
        L = payload[pos]
        if L >= 1 and pos + 1 + L <= n: pos += 1 + L
    return {"id": None, "sender": sender, "content": content, "senderPeerID": sender_peer}

def try_parse_noise_identity_nick(payload: bytes) -> str:
    if not payload: return ""
    if payload[:1] in (b"{", b"["):
        try:
            import json
            js = json.loads(payload.decode("utf-8", "ignore"))
            for key in ("nickname", "name"):
                if isinstance(js, dict) and key in js and isinstance(js[key], str):
                    return js[key].strip()
        except Exception:
            return ""
        return ""
    try:
        pos = 0
        if len(payload) < 2: return ""
        L_peer = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        if pos + L_peer > len(payload): return ""
        pos += L_peer
        if pos + 64 > len(payload): return ""
        pos += 64
        if pos + 2 > len(payload): return ""
        L_nick = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        if pos + L_nick > len(payload): return ""
        nick = safe_utf8(payload[pos:pos+L_nick]); pos += L_nick
        return nick.strip()
    except Exception:
        return ""

def update_peer_nick(peer_id_hex: str, nickname: str):
    nickname = (nickname or "").strip()
    if not nickname: return
    prev = PEER_NICKS.get(peer_id_hex)
    if prev != nickname:
        PEER_NICKS[peer_id_hex] = nickname
        logging.info(("👋 Peer appeared: " if prev is None else "🔄 Peer nick updated: ")
                     + f"{peer_id_hex} (nick: @{nickname})")

async def maybe_get_services(client: BleakClient):
    services = None
    get_services_attr = getattr(client, "get_services", None)
    if callable(get_services_attr):
        res = get_services_attr()
        services = await res if asyncio.iscoroutine(res) else res
    if services is None:
        services = getattr(client, "services", None)
    return services

def _props_str(props: List[str]) -> str: return ",".join(sorted(props or []))

def pick_bitchat_char(services, service_uuid: str, preferred_char_uuid: Optional[str]) -> Optional[str]:
    candidates, notify_only = [], []
    try:
        for s in services:
            if s.uuid.lower() != service_uuid.lower(): continue
            for c in s.characteristics:
                cuuid = c.uuid.lower()
                props = set((c.properties or []))
                if preferred_char_uuid and cuuid == preferred_char_uuid.lower():
                    logging.info(f"Matched preferred characteristic: {c.uuid} (props={_props_str(list(props))})")
                    return c.uuid
                if "notify" in props and ("write" in props or "write-without-response" in props):
                    candidates.append((c.uuid, props, c))
                elif "notify" in props:
                    notify_only.append((c.uuid, props, c))
    except Exception:
        pass
    if candidates:
        c = candidates[0]; logging.info(f"Auto-picked BitChat characteristic (notify+write): {c[0]} (props={_props_str(list(c[1]))})"); return c[0]
    if notify_only:
        c = notify_only[0]; logging.info(f"Auto-picked BitChat characteristic (notify): {c[0]} (props={_props_str(list(c[1]))})"); return c[0]
    return None

async def wait_for_services(client: BleakClient, timeout_s: float = 15.0):
    start = time.time()
    while time.time() - start < timeout_s:
        services = await maybe_get_services(client)
        try:
            if services and sum(1 for _ in services) > 0: return services
        except Exception:
            pass
        await asyncio.sleep(0.3)
    return await maybe_get_services(client)

async def scan_for_bitchat(service_uuid: str, scan_seconds: int, name_contains: Optional[str], pin_address: Optional[str]):
    chosen = None
    def detection_callback(device, adv_data):
        nonlocal chosen
        if chosen is not None: return
        svc_uuids = set(adv_data.service_uuids or [])
        if service_uuid.lower() not in (u.lower() for u in svc_uuids): return
        if pin_address and device.address.lower() != pin_address.lower(): return
        name = adv_data.local_name or device.name or "Unknown"
        if name_contains and name_contains.lower() not in name.lower(): return
        logging.info(f"Discovered: {device.address}  RSSI={adv_data.rssi}  Name='{name}'  Services={list(svc_uuids)}")
        chosen = (device, adv_data)
    scanner = BleakScanner(detection_callback=detection_callback)
    logging.info("Scanning for BitChat iPhone peripheral...")
    await scanner.start()
    for _ in range(max(1, scan_seconds*5)):
        await asyncio.sleep(0.2)
        if chosen is not None: break
    await scanner.stop()
    if chosen is None:
        raise RuntimeError("No BitChat peripheral found. Open the app and keep it in foreground (screen on).")
    return chosen

async def write_packet(client: BleakClient, char_uuid: str, pkt: BitchatPacket):
    data = pkt.to_bytes()
    try:
        await client.write_gatt_char(char_uuid, data, response=False)
    except BleakError:
        await client.write_gatt_char(char_uuid, data, response=True)

async def start_notify_with_fallback(client: BleakClient, char_uuid: str) -> bool:
    # 1) Try normal start_notify with timeout
    try:
        await asyncio.wait_for(client.start_notify(char_uuid, lambda *_: None), timeout=6.0)
        await client.stop_notify(char_uuid)  # we only wanted to prove CCCD works
        return True
    except Exception as e:
        logging.warning(f"start_notify timed out/failed ({e}). Trying manual CCCD write...")

    # 2) Manual CCCD write to enable notifications
    try:
        services = await maybe_get_services(client)
        cccd_handle = None
        for s in services:
            for c in s.characteristics:
                if c.uuid.lower() == char_uuid.lower():
                    for d in getattr(c, "descriptors", []):
                        # bleak exposes UUID; on Linux it also exposes handle
                        if d.uuid.lower() == CCCD_UUID:
                            cccd_handle = getattr(d, "handle", None)
                            break
        if cccd_handle is not None:
            try:
                await client.write_gatt_descriptor(cccd_handle, b"\x01\x00")  # notifications on
                logging.info("CCCD write (notify=1) succeeded.")
                return True
            except Exception as e2:
                logging.warning(f"Manual CCCD write failed: {e2}")
    except Exception as e3:
        logging.debug(f"Descriptor search failed: {e3}")

    return False

async def run_once(nickname: str, service_uuid: str, char_uuid_hint: Optional[str],
                   scan_seconds: int, name_contains: Optional[str], pin_address: Optional[str],
                   dump_gatt: bool):
    device, adv = await scan_for_bitchat(service_uuid, scan_seconds, name_contains, pin_address)
    address = device.address
    name = adv.local_name or device.name or "Unknown"
    logging.info(f"Connecting to {address} ('{name}')...  (If iOS prompts to pair, tap Allow)")

    async with BleakClient(device, timeout=30.0) as client:
        if not client.is_connected: raise RuntimeError("Failed to connect")
        logging.info(f"Connected: {address}")

        services = await wait_for_services(client, timeout_s=15.0)

        if dump_gatt:
            logging.info("----- GATT DUMP BEGIN -----")
            try:
                for s in services:
                    logging.info(f"SERVICE {s.uuid}")
                    for c in s.characteristics:
                        logging.info(f"  CHAR {c.uuid}  props=[{','.join(sorted(c.properties or []))}]")
                        for d in getattr(c, "descriptors", []):
                            logging.info(f"    DESC {d.uuid}")
            except Exception as e:
                logging.info(f"(gatt dump error: {e})")
            logging.info("----- GATT DUMP END -----")

        chosen_char = pick_bitchat_char(services, service_uuid, char_uuid_hint)
        if not chosen_char:
            raise RuntimeError("BitChat characteristic not found under service; run with --dump-gatt and share output.")

        # ===== PRE-NOTIFY NUDGE: send VersionHello once even if CCCD not yet enabled =====
        try:
            vh_payload = build_version_hello_payload(client_version="linux_python/0.1", platform="Linux-Python")
            await write_packet(client, chosen_char, BitchatPacket(MT["versionHello"], vh_payload, sender_id=MY_PEER_ID))
            logging.info("Sent VersionHello (pre-notify)")
        except Exception as e:
            logging.warning(f"Pre-notify VersionHello failed (will retry later): {e}")

        # ===== Enable notifications (with fallback) =====
        def handle_notify(_: int, data: bytearray):
            raw = bytes(data)
            pkt = BitchatPacket.from_bytes(raw)
            if not pkt:
                logging.info(f"[C] RX undecodable (len={len(raw)}): {hexlify(raw).decode()[:120]}..."); return
            tname = next((k for k,v in MT.items() if v == pkt.type), f"0x{pkt.type:02x}")
            sender_hex = hexlify(pkt.sender_id).decode()
            logging.info(f"[C] RX {tname} from {sender_hex} ttl={pkt.ttl} len={len(pkt.payload)}")
            if pkt.type == MT["announce"]:
                nick = pkt.payload.decode("utf-8", "ignore").strip()
                if sender_hex != MY_PEER_ID_HEX and nick:
                    PEER_NICKS[sender_hex] = nick
                    logging.info(f"👋 Peer appeared: {sender_hex} (nick: {nick})"); return
            if pkt.type == MT["noiseIdentityAnnounce"]:
                nick = try_parse_noise_identity_nick(pkt.payload)
                if nick: update_peer_nick(sender_hex, nick); return
            if pkt.type == MT["versionAck"]:
                info = parse_version_ack_payload(pkt.payload)
                logging.info(f"[C] VersionAck: {info or '(unparsed)'}"); return
            if pkt.type == MT["message"]:
                try:
                    info = decode_broadcast_message(pkt.payload)
                    display = PEER_NICKS.get(sender_hex) or info.get("sender") or sender_hex
                    text = sanitize_oneline(info.get("content", ""))
                    logging.info(f"💬 Broadcast from @{display} : {text}")
                except Exception as e2:
                    logging.info(f"💬 Broadcast (hex, decode error: {e2}): {hexlify(pkt.payload).decode()}")

        # Try normal enable first
        notify_ok = False
        try:
            await asyncio.wait_for(client.start_notify(chosen_char, handle_notify), timeout=6.0)
            notify_ok = True
        except Exception as e:
            logging.warning(f"start_notify timeout/failure: {e}. Trying fallback...")
            notify_ok = await start_notify_with_fallback(client, chosen_char)
            if notify_ok:
                # Re-attach real callback
                try:
                    await client.start_notify(chosen_char, handle_notify)
                except Exception as e2:
                    logging.error(f"Re-attach notify failed: {e2}")
                    notify_ok = False

        if not notify_ok:
            raise RuntimeError("Could not enable notifications (likely needs pairing/trust). See `bluetoothctl info` and `btmon`.")

        # ===== Re-send handshake now that notify is up =====
        vh_payload = build_version_hello_payload(client_version="linux_python/0.1", platform="Linux-Python")
        await write_packet(client, chosen_char, BitchatPacket(MT["versionHello"], vh_payload, sender_id=MY_PEER_ID))
        logging.info("Sent VersionHello")
        await asyncio.sleep(0.25)
        await write_packet(client, chosen_char, BitchatPacket(MT["announce"], nickname.encode("utf-8"), sender_id=MY_PEER_ID))
        logging.info("Sent Announce")

        logging.info("Listening for notifications (Ctrl+C to exit)...")
        try:
            while True:
                await asyncio.sleep(1.0)
        finally:
            try: await client.stop_notify(chosen_char)
            except Exception: pass

async def run_forever(**kwargs):
    attempt = 0
    while True:
        attempt += 1
        try:
            await run_once(**kwargs); return
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logging.error(f"Cycle {attempt} failed: {e}")
            logging.info("Retrying in 3s...")
            await asyncio.sleep(3.0)

def main():
    p = argparse.ArgumentParser(description="BitChat BLE Central (Linux/BlueZ)")
    p.add_argument("--nickname", default="PiRelay")
    p.add_argument("--service-uuid", default=SERVICE_UUID_STR)
    p.add_argument("--char-uuid", default=DEFAULT_CHAR_UUID_GUESS)
    p.add_argument("--scan-seconds", type=int, default=12)
    p.add_argument("--name-contains", default=None)
    p.add_argument("--address", dest="pin_address", default=None)
    p.add_argument("--dump-gatt", action="store_true")
    a = p.parse_args()
    logging.info(f"Nickname: @{a.nickname}")
    try:
        asyncio.run(run_forever(
            nickname=a.nickname, service_uuid=a.service_uuid, char_uuid_hint=a.char_uuid,
            scan_seconds=a.scan_seconds, name_contains=a.name_contains, pin_address=a.pin_address,
            dump_gatt=a.dump_gatt))
    except KeyboardInterrupt:
        logging.info("Ctrl+C received, exiting.")
    except Exception as e:
        logging.error(f"Fatal: {e}")

if __name__ == "__main__":
    main()
