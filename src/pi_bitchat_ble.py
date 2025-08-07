#!/usr/bin/env python3
# pi_bitchat_ble.py — BitChat BLE Central for Raspberry Pi (Linux/BlueZ) using bleak
# Works across Bleak versions that may/may not have .get_services()

from __future__ import annotations

import asyncio
import logging
import random
import time
import argparse
from binascii import hexlify
from typing import Optional, Tuple, Dict

from bleak import BleakScanner, BleakClient, BleakError

# ----------------------------
# Logging
# ----------------------------
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# ----------------------------
# BitChat constants (binary protocol & types)
# ----------------------------

SERVICE_UUID_STR = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
CHAR_UUID_STR    = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"

MT = {
    "announce": 0x01,
    "leave": 0x03,
    "message": 0x04,
    "fragmentStart": 0x05,
    "fragmentContinue": 0x06,
    "fragmentEnd": 0x07,
    "deliveryAck": 0x0A,
    "deliveryStatusRequest": 0x0B,
    "readReceipt": 0x0C,
    "noiseHandshakeInit": 0x10,
    "noiseHandshakeResp": 0x11,
    "noiseEncrypted": 0x12,
    "noiseIdentityAnnounce": 0x13,
    "versionHello": 0x20,
    "versionAck": 0x21,
    "protocolAck": 0x22,
    "protocolNack": 0x23,
    "systemValidation": 0x24,
    "handshakeRequest": 0x25,
}

def pkt_type_name(t: int) -> str:
    for k, v in MT.items():
        if v == t:
            return k
    return f"0x{t:02x}"

FLAG_HAS_RECIPIENT  = 0x01
FLAG_HAS_SIGNATURE  = 0x02
FLAG_COMPRESSED     = 0x04

PROTOCOL_VERSION = 1
DEFAULT_TTL = 3

MY_PEER_ID_HEX = ''.join(f"{random.randint(0, 255):02x}" for _ in range(8))
MY_PEER_ID = bytes.fromhex(MY_PEER_ID_HEX)
logging.info(f"My PeerID: {MY_PEER_ID_HEX}")

PEER_NICKS: Dict[str, str] = {}
HEXSET = set(b"0123456789abcdefABCDEF")

# ----------------------------
# Helpers
# ----------------------------

def looks_hex_ascii(b: bytes) -> bool:
    return len(b) > 0 and all(ch in HEXSET for ch in b)

def sanitize_oneline(s: str) -> str:
    return s.replace("\r", " ").replace("\n", " ").strip()

def u8(x: int) -> bytes:  return x.to_bytes(1, "big", signed=False)
def u16(x: int) -> bytes: return x.to_bytes(2, "big", signed=False)
def u64(x: int) -> bytes: return x.to_bytes(8, "big", signed=False)
def now_ms() -> int:      return int(time.time() * 1000)

def enc_str(s: str) -> bytes:
    b = s.encode("utf-8")
    if len(b) > 255:
        return b"\xff" + u16(len(b)) + b
    return u8(len(b)) + b

def dec_str(buf: bytes, pos: int) -> Tuple[str, int]:
    if pos >= len(buf): raise ValueError("string pos OOB")
    L = buf[pos]
    if L != 0xFF:
        pos += 1
        end = pos + L
        if end > len(buf): raise ValueError("string len OOB")
        return buf[pos:end].decode("utf-8", "ignore"), end
    if pos + 3 > len(buf): raise ValueError("string len2 OOB")
    L2 = int.from_bytes(buf[pos+1:pos+3], "big")
    pos += 3
    end = pos + L2
    if end > len(buf): raise ValueError("string len2 OOB2")
    return buf[pos:end].decode("utf-8", "ignore"), end

def safe_utf8(b: bytes) -> str:
    try:
        s = b.decode("utf-8")
        if any(ord(ch) < 0x20 and ch not in "\t\r\n" for ch in s):
            return ""
        return s
    except Exception:
        return ""

# ----------------------------
# Packet
# ----------------------------

class BitchatPacket:
    def __init__(self, type_u8: int, payload: bytes, *,
                 ttl: int = DEFAULT_TTL,
                 sender_id: bytes = MY_PEER_ID,
                 recipient_id: Optional[bytes] = None,
                 signature: Optional[bytes] = None,
                 timestamp_ms: Optional[int] = None,
                 version: int = PROTOCOL_VERSION):
        self.version = version
        self.type = type_u8
        self.ttl = ttl & 0xFF
        self.timestamp = now_ms() if timestamp_ms is None else int(timestamp_ms)
        self.sender_id = sender_id[:8].ljust(8, b"\x00")
        self.recipient_id = recipient_id[:8] if recipient_id else None
        self.payload = payload or b""
        self.signature = signature if signature else None

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
            if len(self.signature) != 64:
                raise ValueError("signature must be 64 bytes")
            body.append(self.signature)
        return header + b"".join(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["BitchatPacket"]:
        try:
            if len(data) < 13 + 8: return None
            pos = 0
            version   = data[pos]; pos += 1
            type_u8   = data[pos]; pos += 1
            ttl       = data[pos]; pos += 1
            timestamp = int.from_bytes(data[pos:pos+8], "big"); pos += 8
            flags     = data[pos]; pos += 1
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

# ----------------------------
# Version negotiation payloads
# ----------------------------

def build_version_hello_payload(client_version: str = "linux_python/0.1",
                                platform: str = "Linux-Python",
                                capabilities: Optional[list[str]] = None) -> bytes:
    flags = 0
    caps = capabilities or []
    if caps: flags |= 0x01
    supported = [PROTOCOL_VERSION]
    preferred = PROTOCOL_VERSION
    out = bytearray()
    out += u8(flags)
    out += u8(len(supported))
    for v in supported: out += u8(v)
    out += u8(preferred)
    out += enc_str(client_version)
    out += enc_str(platform)
    if caps:
        out += u8(len(caps))
        for c in caps: out += enc_str(c)
    return bytes(out)

def parse_version_ack_payload(data: bytes) -> dict:
    try:
        pos = 0
        flags = data[pos]; pos += 1
        has_caps   = (flags & 0x01) != 0
        has_reason = (flags & 0x02) != 0
        agreed = data[pos]; pos += 1
        server_version, pos = dec_str(data, pos)
        platform, pos       = dec_str(data, pos)
        rejected = data[pos] != 0; pos += 1
        caps = []
        if has_caps:
            cap_count = data[pos]; pos += 1
            for _ in range(cap_count):
                s, pos = dec_str(data, pos)
                caps.append(s)
        reason = None
        if has_reason:
            reason, pos = dec_str(data, pos)
        return {"agreedVersion": agreed, "serverVersion": server_version,
                "platform": platform, "rejected": rejected,
                "capabilities": caps, "reason": reason}
    except Exception:
        return {}

# ----------------------------
# Broadcast/identity helpers
# ----------------------------

def plausible_epoch_ms(ms: int) -> bool:
    return 1420070400000 <= ms <= 2051222400000  # 2015-2035

def read_len_str(buf: bytes, pos: int, *, prefer_one_byte: bool = True, one_byte_max: int = 64) -> Tuple[str, int]:
    n = len(buf)
    if pos >= n: raise ValueError("read_len_str: pos OOB")
    def try_1byte(p: int):
        if p >= n: return None
        L = buf[p]; end = p + 1 + L
        if L <= one_byte_max and end <= n:
            return buf[p+1:end].decode("utf-8", "ignore"), end
        return None
    def try_2byte(p: int):
        if p + 2 > n: return None
        L2 = int.from_bytes(buf[p:p+2], "big"); end = p + 2 + L2
        if end <= n: return buf[p+2:end].decode("utf-8", "ignore"), end
        return None
    if prefer_one_byte:
        v = try_1byte(pos)
        if v is not None: return v
        v = try_2byte(pos)
        if v is not None: return v
    else:
        v = try_2byte(pos)
        if v is not None: return v
        v = try_1byte(pos)
        if v is not None: return v
    raise ValueError(f"read_len_str: cannot decode at pos {pos}")

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
        if L >= 1 and pos + 1 + L <= n:
            pos += 1 + L
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
        if prev is None:
            logging.info(f"👋 Peer appeared: {peer_id_hex} (nick: @{nickname})")
        else:
            logging.info(f"🔄 Peer nick updated: {peer_id_hex}: '{prev}' → '{nickname}'")

def build_announce_payload(nickname: str) -> bytes:
    return nickname.encode("utf-8")

# ----------------------------
# BLE (central) logic with bleak
# ----------------------------

async def scan_for_bitchat(service_uuid: str, scan_seconds: int):
    chosen = None
    def detection_callback(device, adv_data):
        nonlocal chosen
        if chosen is not None: return
        svc_uuids = set(adv_data.service_uuids or [])
        if service_uuid.lower() in (u.lower() for u in svc_uuids):
            name = adv_data.local_name or device.name or "Unknown"
            logging.info(f"Discovered: {device.address}  RSSI={adv_data.rssi}  Name='{name}'  Services={list(svc_uuids)}")
            chosen = (device, adv_data)
    scanner = BleakScanner(detection_callback=detection_callback)
    logging.info("Scanning for BitChat iPhone peripheral...")
    await scanner.start()
    await asyncio.sleep(scan_seconds)
    await scanner.stop()
    if chosen is None:
        raise RuntimeError("No BitChat peripheral found. Open the app and keep it in foreground.")
    return chosen

async def write_packet(client: BleakClient, char_uuid: str, pkt: BitchatPacket):
    data = pkt.to_bytes()
    try:
        await client.write_gatt_char(char_uuid, data, response=False)
    except BleakError:
        await client.write_gatt_char(char_uuid, data, response=True)

async def maybe_get_services(client: BleakClient):
    """
    Compatibility shim across Bleak versions:
      - Prefer callable client.get_services() (await if coroutine)
      - Fallback to client.services property if present
    """
    services = None
    get_services_attr = getattr(client, "get_services", None)
    if callable(get_services_attr):
        res = get_services_attr()
        if asyncio.iscoroutine(res):
            services = await res
        else:
            services = res
    if services is None:
        services = getattr(client, "services", None)
    return services

def find_char_in_services(services, service_uuid: str, char_uuid: str):
    """Return characteristic object if found (works with BleakGATTServiceCollection)."""
    if services is None:
        return None
    # Some Bleak versions expose a helper:
    get_char = getattr(services, "get_characteristic", None)
    if callable(get_char):
        ch = get_char(char_uuid)
        if ch is not None:
            return ch
    # Generic iteration fallback
    try:
        for s in services:
            if s.uuid.lower() == service_uuid.lower():
                for c in s.characteristics:
                    if c.uuid.lower() == char_uuid.lower():
                        return c
        # If not found under service, search all chars
        for s in services:
            for c in s.characteristics:
                if c.uuid.lower() == char_uuid.lower():
                    return c
    except Exception:
        pass
    return None

async def run_central(nickname: str, service_uuid: str, char_uuid: str, scan_seconds: int):
    device, adv = await scan_for_bitchat(service_uuid, scan_seconds)
    address = device.address
    name = adv.local_name or device.name or "Unknown"
    logging.info(f"Connecting to {address} ('{name}')...")
    async with BleakClient(address) as client:
        if not client.is_connected:
            raise RuntimeError("Failed to connect")
        logging.info(f"Connected: {address}")

        # --- Services/characteristic resolution (version-agnostic) ---
        services = await maybe_get_services(client)  # works even if get_services doesn't exist
        ch = find_char_in_services(services, service_uuid, char_uuid)

        # If we still didn't find it, try to start/stop notify directly to force discovery, then re-check.
        if ch is None:
            try:
                await client.start_notify(char_uuid, lambda *_: None)
                await client.stop_notify(char_uuid)
            except Exception:
                pass
            services = await maybe_get_services(client)
            ch = find_char_in_services(services, service_uuid, char_uuid)

        if ch is None:
            # Final attempt: rely on Bleak’s internal UUID lookup on write/notify
            logging.warning("Characteristic not pre-resolved; proceeding via UUID (Bleak will resolve internally).")

        # --- Notifications ---
        def handle_notify(_: int, data: bytearray):
            raw = bytes(data)
            pkt = BitchatPacket.from_bytes(raw)
            if not pkt:
                logging.info(f"[C] RX undecodable (len={len(raw)}): {hexlify(raw).decode()[:120]}...")
                return
            tname = pkt_type_name(pkt.type)
            sender_hex = hexlify(pkt.sender_id).decode()
            logging.info(f"[C] RX {tname} from {sender_hex} ttl={pkt.ttl} len={len(pkt.payload)}")

            if pkt.type == MT["announce"]:
                nick = pkt.payload.decode("utf-8", "ignore").strip()
                if sender_hex != MY_PEER_ID_HEX:
                    if nick:
                        PEER_NICKS[sender_hex] = nick
                    logging.info(f"👋 Peer appeared: {sender_hex} (nick: {nick or 'unknown'})")
                return

            if pkt.type == MT["noiseIdentityAnnounce"]:
                nick = try_parse_noise_identity_nick(pkt.payload)
                if nick:
                    update_peer_nick(sender_hex, nick)
                return

            if pkt.type == MT["versionAck"]:
                info = parse_version_ack_payload(pkt.payload)
                if info:
                    logging.info(f"[C] VersionAck: {info}")
                else:
                    logging.info("[C] VersionAck: could not parse")
                return

            if pkt.type == MT["message"]:
                try:
                    info = decode_broadcast_message(pkt.payload)
                    display = PEER_NICKS.get(sender_hex) or info.get("sender") or sender_hex
                    text = sanitize_oneline(info.get("content", ""))
                    logging.info(f"💬 Broadcast from @{display} : {text}")
                except Exception as e:
                    logging.info(f"💬 Broadcast (hex, decode error: {e}): {hexlify(pkt.payload).decode()}")
                return

        # Start notify (Bleak will resolve by UUID if needed)
        await client.start_notify(CHAR_UUID_STR, handle_notify)

        # --- Send VersionHello ---
        vh_payload = build_version_hello_payload(client_version="linux_python/0.1", platform="Linux-Python")
        vh_pkt = BitchatPacket(type_u8=MT["versionHello"], payload=vh_payload, ttl=DEFAULT_TTL, sender_id=MY_PEER_ID)
        await write_packet(client, CHAR_UUID_STR, vh_pkt)
        logging.info("Sent VersionHello")

        # --- Send Announce ---
        await asyncio.sleep(0.25)
        ann_payload = build_announce_payload(nickname)
        ann_pkt = BitchatPacket(type_u8=MT["announce"], payload=ann_payload, ttl=DEFAULT_TTL, sender_id=MY_PEER_ID)
        await write_packet(client, CHAR_UUID_STR, ann_pkt)
        logging.info("Sent Announce")

        logging.info("Listening for notifications (Ctrl+C to exit)...")
        try:
            while True:
                await asyncio.sleep(1.0)
        finally:
            try:
                await client.stop_notify(CHAR_UUID_STR)
            except Exception:
                pass

# ----------------------------
# Entry point
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="BitChat BLE Central (Linux/BlueZ)")
    parser.add_argument("--nickname", default="PiRelay", help="Nickname to announce")
    parser.add_argument("--service-uuid", default=SERVICE_UUID_STR, help="BitChat service UUID")
    parser.add_argument("--char-uuid", default=CHAR_UUID_STR, help="BitChat characteristic UUID")
    parser.add_argument("--scan-seconds", type=int, default=8, help="How long to scan before connecting")
    args = parser.parse_args()

    logging.info(f"Nickname: @{args.nickname}")
    try:
        asyncio.run(run_central(args.nickname, args.service_uuid, args.char_uuid, args.scan_seconds))
    except KeyboardInterrupt:
        logging.info("Ctrl+C received, exiting.")
    except Exception as e:
        logging.error(f"Fatal: {e}")

if __name__ == "__main__":
    main()
