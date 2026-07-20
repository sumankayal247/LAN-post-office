# ✉️ LAN PostOffice

## 🔴 [**Go to Live →**](https://lan-post-office.onrender.com)

*(free tier — spins down when idle, so the first load after a while can take ~30s to wake up)*

Drop files, whole folders, and notes between any devices — straight from the browser. No install, no account, no cloud storage.

## Run

```bash
python3 server.py          # or:  python3 server.py 9000   to pick a port
```

No dependencies — pure Python standard library. It prints the addresses to open:

```
On this computer : http://localhost:8088
On your phone    : http://192.168.x.x:8088
```

Open that address in a browser on **every device on the same Wi-Fi**. Each one
shows up as a "mailbox." Drop a file onto a mailbox (or tap it), the other side
gets an **Accept** prompt, and the file lands in their **Inbox**.

## Features

- 🔌 **Auto-discovery** — devices on the same network appear instantly.
- 📎 **Drop or tap to send** — multiple files at once; or send a quick note/link.
- 📁 **Send whole folders** — drop a folder (or use "Choose folder") and it's zipped
  right in the browser, then sent as one `.zip` — no server upload, still P2P.
- 🛡️ **Accept gate** — nothing transfers until the receiver says yes.
- 📬 **Inbox** — received files wait with previews + a Save button (no surprise downloads).
- 📈 **Live progress + speed**, auto-reconnect, light/dark theme, QR invite.
- 📋 **Paste to send** — copy a file/image and paste (`Ctrl+V`) to send it.
- 📶 **"On your Wi-Fi" scan** — the server lists other devices on your network for
  awareness (ARP via no-root UDP poke). **Awareness only:** a listed device can't
  receive files until it opens the app — there's nothing listening on it otherwise.
  (Not shown on hosted deployments, where there's no real LAN to scan.)

## How it works

```
Browser A ──┐  (WebSocket: tiny SDP/ICE signaling only)  ┌── Browser B
            └──────────────►  server.py  ◄───────────────┘
A  ══════════════  WebRTC DataChannel (file bytes, P2P)  ══════════════  B
```

The file bytes never pass through `server.py`. On a single subnet the WebRTC
connection is direct device-to-device at full LAN speed.

## Security notes

- Server relays signaling only; it never stores or sees file contents.
- Every transfer requires explicit receiver acceptance.
- Filenames are rendered as text and sanitized on save (XSS / path-traversal safe).
- Static serving is path-traversal guarded; responses carry a strict CSP.
- WebRTC data channels are DTLS-encrypted in transit.
- The default room is scoped to your own network (LAN subnet, or public IP when
  hosted) — strangers on other networks never land in the same "lobby." To pair
  across networks on purpose, share an invite link/QR (`?room=yourcode`).

## Notes & limits

- Received files are held in browser memory until you Save them, so very large
  files (multi-GB) depend on the receiving device's available RAM.
- A public STUN server is used to help connections form; pure same-subnet LANs
  usually connect with no internet at all.
- Private room: add `?room=yourcode` to the URL on every device to make a
  separate, isolated PostOffice.

## Deploy your own

`server.py` is a single dependency-free process that reads `PORT` from the
environment, so it drops straight onto any Python host. A [`render.yaml`](render.yaml)
blueprint is included — on [Render](https://render.com), **New → Blueprint**,
point it at this repo, and it deploys as a free web service.
