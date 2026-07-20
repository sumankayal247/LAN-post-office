#!/usr/bin/env python3
"""
LAN PostOffice — zero-dependency signaling server + static host.

Run:  python3 server.py [port]   (default 8088)

The server only relays tiny WebSocket signaling messages (WebRTC SDP/ICE) so two
browsers on the same Wi-Fi can find each other. The actual files travel
peer-to-peer over WebRTC and never pass through this process.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, "static")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_PAYLOAD = 512 * 1024  # signaling msgs are tiny; cap to refuse abuse
# True when running on a remote host (behind a proxy) rather than on someone's
# own machine — the ARP "who else is on this Wi-Fi" scan is meaningless there
# (it would scan the host's own container network, not the visitor's LAN).
HOSTED = bool(os.environ.get("RENDER") or os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("FLY_APP_NAME"))

ADJ = [
    "Amber", "Azure", "Brave", "Calm", "Cobalt", "Coral", "Crimson", "Dusty",
    "Emerald", "Gentle", "Golden", "Hazel", "Indigo", "Jolly", "Lively", "Lunar",
    "Mellow", "Misty", "Noble", "Olive", "Pearl", "Quiet", "Rapid", "Royal",
    "Rustic", "Scarlet", "Silver", "Snowy", "Solar", "Spry", "Sunny", "Teal",
    "Velvet", "Witty",
]
ANI = [
    "Otter", "Falcon", "Panda", "Lynx", "Heron", "Bison", "Koala", "Gecko",
    "Marlin", "Raven", "Tapir", "Wombat", "Yak", "Zebra", "Ferret", "Quokka",
    "Lemur", "Moth", "Newt", "Owl", "Puffin", "Robin", "Seal", "Toad",
    "Urchin", "Viper", "Walrus", "Sparrow",
]
DEV_EMOJI = {"mobile": "📱", "tablet": "📱", "laptop": "💻", "desktop": "🖥️", "tv": "📺"}
CTYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".ico": "image/x-icon", ".png": "image/png",
    ".webmanifest": "application/manifest+json",
}


def name_for(cid):
    h = hashlib.sha256(cid.encode()).digest()
    return f"{ADJ[h[0] % len(ADJ)]} {ANI[h[1] % len(ANI)]}"


def color_for(cid):
    h = hashlib.sha256(("c" + cid).encode()).digest()
    return f"hsl({h[0] * 360 // 256} 65% 55%)"


# --------------------------------------------------------- LAN awareness scan
# Awareness only: lists devices the host can see on the local subnet. You still
# cannot send to one until it opens the app (nothing is listening on it).
SCAN_LOCK = threading.Lock()
SCAN_CACHE = {"at": 0.0, "data": None}
# Small, partial OUI map for devices that still use real (non-randomized) MACs
# (routers, PCs, IoT, VMs). Modern phones randomize MACs, so they show as private.
OUI = {
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi", "2C:CF:67": "Raspberry Pi",
    "F0:18:98": "Apple", "A4:5E:60": "Apple", "3C:07:54": "Apple", "AC:DE:48": "Apple",
    "00:1A:11": "Google", "F4:F5:E8": "Google", "D8:6C:63": "Google", "1C:F2:9A": "Google",
    "44:65:0D": "Amazon", "FC:65:DE": "Amazon", "68:54:FD": "Amazon",
    "EC:FA:BC": "Espressif (ESP)", "24:0A:C4": "Espressif (ESP)", "A0:20:A6": "Espressif (ESP)",
    "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link", "14:CC:20": "TP-Link", "AC:84:C6": "TP-Link",
    "B4:2E:99": "Intel", "00:1B:21": "Intel", "34:13:E8": "Intel", "8C:16:45": "Intel",
    "52:54:00": "Linux VM (KVM)", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "00:11:32": "Synology NAS", "70:85:C2": "ASUS", "1C:B7:2C": "Xiaomi",
}


def _primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def _poke(ip):
    """Send a tiny UDP packet so the kernel ARP-resolves the host (no root)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.sendto(b"\x00", (ip, 9))  # discard port
        s.close()
    except OSError:
        pass


def _read_arp():
    table = {}
    try:
        with open("/proc/net/arp") as f:
            for ln in f.read().splitlines()[1:]:
                c = ln.split()
                if len(c) >= 4:
                    ip, flags, mac = c[0], c[2], c[3]
                    if flags != "0x0" and mac != "00:00:00:00:00:00":
                        table[ip] = mac.upper()
    except OSError:
        pass
    return table


def _vendor(mac):
    try:
        if int(mac[0:2], 16) & 0x02:  # locally-administered bit -> randomized MAC
            return "Private (randomized MAC)"
    except ValueError:
        return ""
    return OUI.get(mac[0:8], "")


def _do_scan():
    myip = _primary_ip()
    if not myip:
        return []
    base = ".".join(myip.split(".")[:3])
    targets = [f"{base}.{i}" for i in range(1, 255)]
    try:
        with ThreadPoolExecutor(max_workers=80) as ex:
            list(ex.map(_poke, targets))
    except Exception:
        pass
    time.sleep(0.35)  # let ARP replies settle
    res = []
    for ip, mac in _read_arp().items():
        if ip.startswith(base + ".") and ip != myip:
            res.append({"ip": ip, "mac": mac, "vendor": _vendor(mac)})
    res.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])
    return res


def scan_lan(connected_ips):
    now = time.time()
    with SCAN_LOCK:
        if SCAN_CACHE["data"] is not None and now - SCAN_CACHE["at"] < 5:
            data = SCAN_CACHE["data"]
        else:
            data = _do_scan()
            SCAN_CACHE["at"] = now
            SCAN_CACHE["data"] = data
    return [dict(d, hasApp=d["ip"] in connected_ips) for d in data]


def connected_ips():
    with lock:
        return {p.ip for r in rooms.values() for p in r.values() if p.ip}


# --------------------------------------------------------------- TURN relay
# Optional: STUN alone can't traverse every NAT (two devices on different
# networks, symmetric NAT, CGNAT/mobile carriers, ...). If TURN_KEY_ID and
# TURN_API_TOKEN are set (from a free Cloudflare Calls TURN app), the server
# mints short-lived TURN credentials for clients to fall back to. Without
# them, WebRTC just uses public STUN + falls back to a shaky public demo TURN
# — fine on the same network, unreliable across the open internet.
TURN_KEY_ID = os.environ.get("TURN_KEY_ID", "")
TURN_API_TOKEN = os.environ.get("TURN_API_TOKEN", "")
TURN_TTL = 3600
TURN_LOCK = threading.Lock()
TURN_CACHE = {"at": 0.0, "data": None}


def _fetch_turn_credentials():
    url = f"https://rtc.live.cloudflare.com/v1/turn/keys/{TURN_KEY_ID}/credentials/generate"
    body = json.dumps({"ttl": TURN_TTL}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": f"Bearer {TURN_API_TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    ice = data.get("iceServers")
    if isinstance(ice, dict):
        ice = [ice]
    return ice or None


def turn_credentials():
    if not (TURN_KEY_ID and TURN_API_TOKEN):
        return None
    now = time.time()
    with TURN_LOCK:
        if TURN_CACHE["data"] is not None and now - TURN_CACHE["at"] < TURN_TTL - 300:
            return TURN_CACHE["data"]
        fresh = _fetch_turn_credentials()
        if fresh:
            TURN_CACHE["at"] = now
            TURN_CACHE["data"] = fresh
        return TURN_CACHE["data"]


# ---------------------------------------------------------------- room registry
lock = threading.Lock()
rooms = {}  # room -> { peer_id -> Peer }


class Peer:
    def __init__(self, sock, room, pid, name, color, device, emoji, ip=None):
        self.sock = sock
        self.room = room
        self.id = pid
        self.name = name
        self.color = color
        self.device = device
        self.emoji = emoji
        self.ip = ip  # server-side only; never sent to other clients
        self.sendlock = threading.Lock()

    def info(self):
        return {"peerId": self.id, "name": self.name, "color": self.color,
                "device": self.device, "emoji": self.emoji}

    def send_json(self, obj):
        data = json.dumps(obj).encode("utf-8")
        with self.sendlock:
            try:
                ws_send_text(self.sock, data)
            except OSError:
                pass


# ----------------------------------------------------------------- ws framing
def ws_send_text(sock, payload):
    n = len(payload)
    header = bytearray([0x81])
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    sock.sendall(bytes(header) + payload)


def ws_send_pong(sock, payload=b""):
    sock.sendall(bytes([0x8A, len(payload) & 0x7F]) + payload)


def ws_send_close(sock, code=1000):
    try:
        sock.sendall(bytes([0x88, 0x02]) + struct.pack(">H", code))
    except OSError:
        pass


def read_exact(reader, n):
    if n == 0:
        return b""
    data = reader.read(n)
    if not data or len(data) < n:
        return None
    return data


def ws_read_message(reader, sock):
    """Return (kind, bytes) for one complete message, or None on close/error.
    Handles fragmentation and interleaved ping/pong/close control frames."""
    data = bytearray()
    msg_op = None
    while True:
        hdr = read_exact(reader, 2)
        if hdr is None:
            return None
        b0, b1 = hdr[0], hdr[1]
        fin = b0 & 0x80
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        length = b1 & 0x7F
        if length == 126:
            ext = read_exact(reader, 2)
            if ext is None:
                return None
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = read_exact(reader, 8)
            if ext is None:
                return None
            length = struct.unpack(">Q", ext)[0]
        if length > MAX_PAYLOAD:
            return None
        mask = b""
        if masked:
            mask = read_exact(reader, 4)
            if mask is None:
                return None
        payload = read_exact(reader, length) if length else b""
        if payload is None:
            return None
        if masked and payload:
            payload = bytes(payload[i] ^ mask[i % 4] for i in range(length))
        if opcode == 0x8:  # close
            return ("close", b"")
        if opcode == 0x9:  # ping -> pong
            try:
                ws_send_pong(sock, payload)
            except OSError:
                return None
            continue
        if opcode == 0xA:  # pong
            continue
        if opcode == 0x0:  # continuation
            data += payload
        else:
            msg_op = opcode
            data = bytearray(payload)
        if fin:
            kind = "text" if msg_op == 0x1 else "binary" if msg_op == 0x2 else "other"
            return (kind, bytes(data))


# -------------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    server_version = "LANPostOffice"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # quiet

    def real_ip(self):
        # Behind a reverse proxy (e.g. Render/Railway) client_address is the
        # proxy's own address; prefer the forwarded client IP when present.
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            return self.handle_ws()
        if path == "/lan-scan":
            return self.serve_scan()
        if path == "/turn-credentials":
            return self.serve_turn()
        return self.serve_static(path)

    def serve_turn(self):
        servers = turn_credentials() or []
        body = json.dumps({"iceServers": servers}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def serve_scan(self):
        if HOSTED:
            body = json.dumps({"devices": [], "hosted": True}).encode("utf-8")
        else:
            try:
                data = scan_lan(connected_ips())
            except Exception:
                data = []
            body = json.dumps({"devices": data}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    # --- static -----------------------------------------------------------
    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        rel = os.path.normpath(path).lstrip("/\\")
        full = os.path.abspath(os.path.join(STATIC, rel))
        if not (full == STATIC or full.startswith(STATIC + os.sep)):
            return self.send_error(403)
        if not os.path.isfile(full):
            return self.send_error(404)
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            return self.send_error(404)
        ctype = CTYPES.get(os.path.splitext(full)[1].lower(), "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; "
            "base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    # --- websocket --------------------------------------------------------
    def handle_ws(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            return self.send_error(400)
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True  # do not return to the keep-alive loop

        sock = self.connection
        reader = self.rfile
        peer = None
        try:
            while True:
                msg = ws_read_message(reader, sock)
                if msg is None:
                    break
                kind, raw = msg
                if kind == "close":
                    break
                if kind != "text":
                    continue
                try:
                    m = json.loads(raw.decode("utf-8"))
                except Exception:
                    continue
                t = m.get("type")
                if t == "hello" and peer is None:
                    peer = self.register(sock, m, self.real_ip())
                elif peer is None:
                    continue
                elif t == "signal":
                    self.relay(peer, m)
                elif t == "rename":
                    self.rename(peer, m.get("name"))
        finally:
            if peer:
                self.unregister(peer)
            ws_send_close(sock)

    def register(self, sock, m, ip=None):
        room = str(m.get("room") or "lobby")[:64]
        if room == "lobby":
            # Default room is scoped to the caller's /24 subnet, not shared
            # globally. On a LAN that's exactly "this Wi-Fi" (unchanged
            # behaviour); if this server is ever reachable over the public
            # internet, strangers no longer land in the same pool by default
            # — pairing across networks still works via an explicit ?room=
            # invite link/QR.
            subnet = ".".join(ip.split(".")[:3]) if ip else "unknown"
            room = f"lobby:{subnet}"
        cid = str(m.get("clientId") or uuid.uuid4().hex)[:128]
        pid = uuid.uuid4().hex
        custom = m.get("name")
        name = str(custom)[:32] if custom else name_for(cid)
        device = str(m.get("device") or "desktop")
        if device not in DEV_EMOJI:
            device = "desktop"
        peer = Peer(sock, room, pid, name, color_for(cid), device, DEV_EMOJI[device], ip)
        with lock:
            rooms.setdefault(room, {})[pid] = peer
            others = [p.info() for q, p in rooms[room].items() if q != pid]
        peer.send_json({"type": "welcome", "you": peer.info(), "peers": others, "room": room})
        self.broadcast(room, {"type": "peer-joined", "peer": peer.info()}, exclude=pid)
        return peer

    def relay(self, peer, m):
        to = m.get("to")
        data = m.get("data")
        if not to or data is None:
            return
        with lock:
            target = rooms.get(peer.room, {}).get(to)
        if target:
            target.send_json({"type": "signal", "from": peer.id, "data": data})

    def rename(self, peer, name):
        if not name:
            return
        peer.name = str(name)[:32]
        self.broadcast(peer.room, {"type": "peer-updated", "peer": peer.info()})

    def broadcast(self, room, obj, exclude=None):
        with lock:
            peers = list(rooms.get(room, {}).values())
        for p in peers:
            if p.id != exclude:
                p.send_json(obj)

    def unregister(self, peer):
        with lock:
            r = rooms.get(peer.room)
            if r and peer.id in r:
                del r[peer.id]
                if not r:
                    del rooms[peer.room]
        self.broadcast(peer.room, {"type": "peer-left", "peerId": peer.id})


# ----------------------------------------------------------------------- main
def lan_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips


def main():
    port = 8088
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    port = int(os.environ.get("PORT", port))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.daemon_threads = True
    ips = lan_ips()
    line = "─" * 52
    print(f"\n  ✉️  \033[1mLAN PostOffice\033[0m is open\n  {line}")
    print(f"  On this computer : \033[36mhttp://localhost:{port}\033[0m")
    for ip in ips:
        print(f"  On your phone    : \033[36mhttp://{ip}:{port}\033[0m")
    print(f"  {line}")
    print("  Open that address on any device on the same Wi-Fi.")
    print("  Press Ctrl+C to close.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  ✉️  PostOffice closed. Bye!\n")


if __name__ == "__main__":
    main()
