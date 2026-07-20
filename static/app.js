/* LAN PostOffice — client.
   Signaling over WebSocket; file bytes over WebRTC DataChannel (peer-to-peer).
   Nothing here ever uploads files to the server. */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const CHUNK = 64 * 1024;          // 64 KB data-channel chunks
const HIGH_WATER = 8 * 1024 * 1024;
const RTC_CONFIG = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };
const TEXT_MAX = 8 * 1024;        // notes above this become a .txt file

const state = {
  ws: null,
  me: null,
  peers: new Map(),               // peerId -> info
  room: new URLSearchParams(location.search).get("room") || "lobby",
  clientId: localStorage.getItem("lpo-clientId") || (crypto.randomUUID?.() || rid()),
  transfers: new Map(),           // transferId -> transfer record
  composeTarget: null,
};
localStorage.setItem("lpo-clientId", state.clientId);

function rid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function newId() { return crypto.randomUUID?.() || rid(); }

/* ----------------------------------------------------------- formatting */
function fmtBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}
function fmtSpeed(bps) { return fmtBytes(bps) + "/s"; }
function sanitizeName(n) {
  return ((n || "file").replace(/[\/\\<>:"|?*\x00-\x1f]+/g, "_").replace(/^\.+/, "_").slice(0, 200)) || "file";
}
function detectDevice() {
  const ua = navigator.userAgent;
  if (/iPad|Tablet/i.test(ua)) return "tablet";
  if (/Mobi|Android|iPhone|iPod/i.test(ua)) return "mobile";
  return "desktop";
}
function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

/* ------------------------------------------------------------ sanitizer */
/* Notes may carry HTML pasted by the sender (kept for formatting), but that
   HTML arrives over the network from another person's browser — treat it as
   untrusted and strip anything that isn't plain text formatting. */
const ALLOWED_TAGS = new Set([
  "B", "STRONG", "I", "EM", "U", "S", "STRIKE", "A", "P", "BR", "DIV", "SPAN",
  "UL", "OL", "LI", "BLOCKQUOTE", "CODE", "PRE", "H1", "H2", "H3", "H4", "H5",
  "H6", "SUB", "SUP", "HR", "TABLE", "THEAD", "TBODY", "TR", "TD", "TH",
]);
const ALLOWED_STYLE_PROPS = new Set([
  "color", "background-color", "font-weight", "font-style", "text-decoration", "text-align", "font-size",
]);
function sanitizeHtml(html) {
  const doc = new DOMParser().parseFromString(`<div>${html || ""}</div>`, "text/html");
  const root = doc.body.firstChild;
  if (!root) return "";
  cleanNode(root);
  return root.innerHTML;
}
function cleanNode(node) {
  for (const child of [...node.childNodes]) {
    if (child.nodeType === Node.TEXT_NODE) continue;
    if (child.nodeType !== Node.ELEMENT_NODE) { child.remove(); continue; }
    const tag = child.tagName;
    if (!ALLOWED_TAGS.has(tag)) {
      if (["SCRIPT", "STYLE", "IFRAME", "OBJECT", "EMBED", "LINK", "META", "FORM",
           "INPUT", "BUTTON", "SVG", "IMG", "VIDEO", "AUDIO"].includes(tag)) {
        child.remove();
      } else {
        // unknown/disallowed wrapper — unwrap, keep cleaned children
        cleanNode(child);
        while (child.firstChild) node.insertBefore(child.firstChild, child);
        child.remove();
      }
      continue;
    }
    for (const attr of [...child.attributes]) {
      const name = attr.name.toLowerCase();
      if (name === "href" && tag === "A") {
        const val = attr.value.trim();
        if (!/^(https?:|mailto:)/i.test(val)) child.removeAttribute("href");
        else { child.setAttribute("target", "_blank"); child.setAttribute("rel", "noopener noreferrer"); }
        continue;
      }
      if (name === "style") {
        const clean = [...attr.value.matchAll(/([a-z-]+)\s*:\s*([^;]+)/gi)]
          .filter(([, prop]) => ALLOWED_STYLE_PROPS.has(prop.toLowerCase()))
          .map(([, prop, val]) => `${prop}:${val.trim()}`).join(";");
        if (clean) child.setAttribute("style", clean); else child.removeAttribute("style");
        continue;
      }
      if ((name === "colspan" || name === "rowspan") && (tag === "TD" || tag === "TH") && /^\d+$/.test(attr.value)) continue;
      child.removeAttribute(attr.name);
    }
    cleanNode(child);
  }
}

/* ------------------------------------------------------------ signaling */
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws = ws;
  ws.onopen = () => {
    setStatus("connected");
    sigSend({
      type: "hello", room: state.room, clientId: state.clientId,
      name: localStorage.getItem("lpo-name") || null, device: detectDevice(),
    });
  };
  ws.onmessage = (e) => { try { handle(JSON.parse(e.data)); } catch (err) { console.warn("bad ws message", err); } };
  ws.onclose = () => { setStatus("reconnecting"); setTimeout(connect, 1500); };
  ws.onerror = () => ws.close();
}
function sigSend(o) { if (state.ws && state.ws.readyState === 1) state.ws.send(JSON.stringify(o)); }
function signalTo(peerId, data) { sigSend({ type: "signal", to: peerId, data }); }
// keep the connection warm — hosted proxies (e.g. Render's free tier) can
// silently drop a WebSocket that's been idle for a while, which otherwise
// makes offers vanish into thin air on the receiving end
setInterval(() => sigSend({ type: "ping" }), 25000);

function handle(m) {
  switch (m.type) {
    case "welcome":
      state.me = m.you; renderMe();
      state.peers.clear();
      m.peers.forEach((p) => state.peers.set(p.peerId, p));
      renderPeers(); break;
    case "peer-joined":
      state.peers.set(m.peer.peerId, m.peer); renderPeers();
      toast(`${m.peer.name} arrived`); break;
    case "peer-updated":
      if (state.peers.has(m.peer.peerId)) { state.peers.set(m.peer.peerId, m.peer); renderPeers(); }
      break;
    case "peer-left": {
      const p = state.peers.get(m.peerId);
      state.peers.delete(m.peerId); renderPeers();
      if (p) toast(`${p.name} left`);
      break;
    }
    case "signal": onSignal(m.from, m.data); break;
  }
}

/* -------------------------------------------------- transfer signaling */
function onSignal(from, d) {
  switch (d.kind) {
    case "offer-files": return promptIncoming(from, d);
    case "accept":      return beginRtc(from, d.transferId);
    case "decline":     return onDeclined(d.transferId);
    case "rtc-offer":   return onRtcOffer(from, d);
    case "rtc-answer":  return onRtcAnswer(d);
    case "rtc-ice":     return onRtcIce(d);
    case "cancel":      return onCancel(d.transferId);
    case "message":     return showMessage(from, d.text, d.html);
    case "unreachable": return onUnreachable(d.transferId);
  }
}

/* ------------------------------------------------------- folder → zip */
function readAllEntries(reader) {
  return new Promise((resolve, reject) => {
    let all = [];
    (function read() {
      reader.readEntries((batch) => {
        if (!batch.length) resolve(all);
        else { all = all.concat(batch); read(); }
      }, reject);
    })();
  });
}
async function collectDirEntry(dirEntry, prefix, out) {
  const entries = await readAllEntries(dirEntry.createReader());
  for (const e of entries) {
    const path = prefix + e.name;
    if (e.isFile) {
      const file = await new Promise((res, rej) => e.file(res, rej));
      out.push({ path, file });
    } else if (e.isDirectory) {
      await collectDirEntry(e, path + "/", out);
    }
  }
}
async function pairsToZipFile(pairs, zipBaseName) {
  const entries = [];
  for (const { path, file } of pairs) {
    entries.push({ name: path, data: new Uint8Array(await file.arrayBuffer()) });
  }
  const blob = window.makeZip(entries);
  return new File([blob], sanitizeName(zipBaseName) + ".zip", { type: "application/zip" });
}
async function folderEntryToZipFile(dirEntry) {
  const out = [];
  await collectDirEntry(dirEntry, dirEntry.name + "/", out);
  return pairsToZipFile(out, dirEntry.name);
}
async function fileListToZipFile(fileList) {
  const files = [...fileList];
  if (!files.length) return null;
  const base = (files[0].webkitRelativePath || files[0].name).split("/")[0];
  const pairs = files.map((f) => ({ path: f.webkitRelativePath || f.name, file: f }));
  return pairsToZipFile(pairs, base);
}
/* dropped items may include whole folders (Chromium/Firefox: webkitGetAsEntry) */
async function filesFromDrop(dataTransfer) {
  const dtItems = dataTransfer.items;
  if (!dtItems || !dtItems.length || typeof dtItems[0].webkitGetAsEntry !== "function") {
    return [...(dataTransfer.files || [])];
  }
  const entries = [...dtItems].map((it) => it.webkitGetAsEntry()).filter(Boolean);
  const out = [];
  for (const entry of entries) {
    if (entry.isFile) {
      out.push(await new Promise((res, rej) => entry.file(res, rej)));
    } else if (entry.isDirectory) {
      toast(`Zipping "${entry.name}"…`);
      out.push(await folderEntryToZipFile(entry));
    }
  }
  return out;
}

/* sender: announce intent ------------------------------------------------ */
function sendFiles(peerId, files) {
  files = [...files].filter((f) => f && (f.size > 0 || f.size === 0));
  if (!files.length) return;
  const id = newId();
  const meta = files.map((f) => ({ name: f.name, size: f.size, type: f.type || "application/octet-stream" }));
  const totalBytes = files.reduce((a, f) => a + f.size, 0);
  const t = {
    id, peerId, dir: "out", files, meta, totalBytes,
    moved: 0, status: "offering", pc: null, dc: null, iceQueue: [],
    startAt: 0, lastAt: 0, lastBytes: 0, speed: 0,
  };
  state.transfers.set(id, t);
  renderTransfer(t);
  signalTo(peerId, { kind: "offer-files", transferId: id, files: meta, totalBytes });
  setTimeout(() => {
    if (t.status === "offering") {
      t.status = "failed"; renderTransfer(t);
      toast(`No response from ${nameOf(peerId)} — are they still online?`);
    }
  }, 45000);
}

function sendNote(peerId, el) {
  const text = (el.innerText || "").trim();
  if (!text) return;
  const html = sanitizeHtml(el.innerHTML);
  if (text.length > TEXT_MAX) {
    const f = new File([text], `note-${Date.now()}.txt`, { type: "text/plain" });
    return sendFiles(peerId, [f]);
  }
  signalTo(peerId, { kind: "message", text, html });
  toast("Note sent ✓");
}

/* receiver: accept gate -------------------------------------------------- */
function promptIncoming(from, d) {
  if (state.transfers.has(d.transferId)) return;
  const peer = state.peers.get(from) || { name: "Someone", emoji: "✉️", color: "var(--accent)" };
  const t = {
    id: d.transferId, peerId: from, dir: "in", meta: d.files, totalBytes: d.totalBytes,
    moved: 0, status: "pending", pc: null, dc: null, iceQueue: [], cur: null,
    startAt: 0, lastAt: 0, lastBytes: 0, speed: 0,
  };
  state.transfers.set(d.transferId, t);
  showAccept(peer, d, t);
}

/* sender: peer accepted -> create the connection ------------------------- */
async function beginRtc(from, transferId) {
  const t = state.transfers.get(transferId);
  if (!t || t.dir !== "out") return;
  const pc = newPC(t, from);
  const dc = pc.createDataChannel("data", { ordered: true });
  dc.binaryType = "arraybuffer";
  t.pc = pc; t.dc = dc; t.status = "connecting"; renderTransfer(t);
  dc.onopen = () => startSending(t);
  dc.onerror = () => failTransfer(t);
  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    signalTo(from, { kind: "rtc-offer", transferId, sdp: pc.localDescription });
  } catch { failTransfer(t); }
}

/* receiver: got the offer ------------------------------------------------ */
async function onRtcOffer(from, d) {
  const t = state.transfers.get(d.transferId);
  if (!t || t.dir !== "in") return;
  const pc = newPC(t, from);
  t.pc = pc; t.status = "connecting"; renderTransfer(t);
  pc.ondatachannel = (e) => { const dc = e.channel; dc.binaryType = "arraybuffer"; t.dc = dc; wireReceiver(t, dc); };
  try {
    await pc.setRemoteDescription(d.sdp);
    await flushIce(t);
    const ans = await pc.createAnswer();
    await pc.setLocalDescription(ans);
    signalTo(from, { kind: "rtc-answer", transferId: d.transferId, sdp: pc.localDescription });
  } catch { failTransfer(t); }
}

async function onRtcAnswer(d) {
  const t = state.transfers.get(d.transferId);
  if (!t || !t.pc) return;
  try { await t.pc.setRemoteDescription(d.sdp); await flushIce(t); } catch { failTransfer(t); }
}

async function onRtcIce(d) {
  const t = state.transfers.get(d.transferId);
  if (!t || !t.pc) return;
  const c = new RTCIceCandidate(d.candidate);
  if (t.pc.remoteDescription && t.pc.remoteDescription.type) {
    try { await t.pc.addIceCandidate(c); } catch {}
  } else { t.iceQueue.push(c); }
}
async function flushIce(t) {
  for (const c of t.iceQueue) { try { await t.pc.addIceCandidate(c); } catch {} }
  t.iceQueue = [];
}

function newPC(t, peerId) {
  const pc = new RTCPeerConnection(RTC_CONFIG);
  pc.onicecandidate = (e) => { if (e.candidate) signalTo(peerId, { kind: "rtc-ice", transferId: t.id, candidate: e.candidate }); };
  pc.onconnectionstatechange = () => {
    if (["failed", "closed"].includes(pc.connectionState) && t.status !== "done") failTransfer(t);
  };
  return pc;
}

/* sender: pump bytes ----------------------------------------------------- */
async function startSending(t) {
  t.status = "sending"; t.startAt = performance.now(); t.lastAt = t.startAt; renderTransfer(t);
  const dc = t.dc;
  dc.bufferedAmountLowThreshold = 1024 * 1024;
  try {
    for (let i = 0; i < t.files.length; i++) {
      const f = t.files[i];
      dc.send(JSON.stringify({ t: "fs", idx: i, name: f.name, size: f.size, type: f.type || "application/octet-stream" }));
      let off = 0;
      while (off < f.size) {
        if (dc.readyState !== "open") throw new Error("channel closed");
        const end = Math.min(off + CHUNK, f.size);
        const buf = await f.slice(off, end).arrayBuffer();
        if (dc.bufferedAmount > HIGH_WATER) await drain(dc);
        dc.send(buf);
        off = end; t.moved += buf.byteLength;
        tickProgress(t);
      }
      dc.send(JSON.stringify({ t: "fe", idx: i }));
    }
    dc.send(JSON.stringify({ t: "done" }));
    t.status = "done"; t.speed = 0; renderTransfer(t);
    toast(`Delivered to ${nameOf(t.peerId)} ✓`);
    closeWhenDrained(t);
  } catch { failTransfer(t); }
}
function drain(dc) {
  return new Promise((res) => {
    const h = () => { dc.removeEventListener("bufferedamountlow", h); res(); };
    dc.addEventListener("bufferedamountlow", h);
  });
}
function closeWhenDrained(t) {
  const tick = () => {
    if (!t.dc || t.dc.bufferedAmount === 0) { try { t.pc.close(); } catch {} }
    else setTimeout(tick, 200);
  };
  tick();
}

/* receiver: collect bytes ------------------------------------------------ */
function wireReceiver(t, dc) {
  t.status = "receiving"; t.startAt = performance.now(); t.lastAt = t.startAt; renderTransfer(t);
  dc.onmessage = (e) => {
    if (typeof e.data === "string") {
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.t === "fs") t.cur = { name: msg.name, size: msg.size, type: msg.type, chunks: [] };
      else if (msg.t === "fe") { finalizeFile(t, t.cur); t.cur = null; }
      else if (msg.t === "done") {
        t.status = "done"; t.speed = 0; renderTransfer(t);
        toast(`Received from ${nameOf(t.peerId)} ✓`);
        try { t.pc.close(); } catch {}
      }
    } else {
      if (!t.cur) return;
      t.cur.chunks.push(e.data); t.moved += e.data.byteLength;
      tickProgress(t);
    }
  };
}
function finalizeFile(t, cur) {
  if (!cur) return;
  const blob = new Blob(cur.chunks, { type: cur.type || "application/octet-stream" });
  addInboxFile(t, cur.name, blob);
}

/* shared status helpers -------------------------------------------------- */
function tickProgress(t) {
  const now = performance.now();
  if (now - t.lastAt > 350) {
    t.speed = (t.moved - t.lastBytes) / ((now - t.lastAt) / 1000);
    t.lastAt = now; t.lastBytes = t.moved;
    renderTransfer(t);
  }
}
function failTransfer(t) {
  if (t.status === "done" || t.status === "failed") return;
  t.status = "failed"; t.speed = 0; renderTransfer(t);
  try { t.pc && t.pc.close(); } catch {}
}
function onDeclined(id) {
  const t = state.transfers.get(id);
  if (!t) return;
  t.status = "declined"; renderTransfer(t);
  toast(`${nameOf(t.peerId)} declined`);
}
function cancelTransfer(t) {
  if (t.status !== "offering") return;
  signalTo(t.peerId, { kind: "cancel", transferId: t.id });
  t.status = "declined"; renderTransfer(t);
  toast("Send cancelled");
}
function onCancel(id) {
  const t = state.transfers.get(id);
  if (t && t.dir === "in" && t.status === "pending") {
    state.transfers.delete(id);
    if (pendingAcceptId === id) { hide("#acceptBackdrop"); pendingAcceptId = null; }
    toast("The sender cancelled that send");
    return;
  }
  if (t) failTransfer(t);
}
function onUnreachable(id) {
  const t = state.transfers.get(id);
  if (!t || t.status === "done" || t.status === "failed") return;
  t.status = "failed"; renderTransfer(t);
  toast(`${nameOf(t.peerId)} isn't connected anymore`);
}
function nameOf(peerId) { return (state.peers.get(peerId) || {}).name || "device"; }

/* --------------------------------------------------------------- render */
function setStatus(s) {
  const map = { connected: "online", reconnecting: "reconnecting…", connecting: "connecting…" };
  $("#statusText").textContent = map[s] || s;
}
function renderMe() {
  if (!state.me) return;
  $("#meAvatar").textContent = state.me.emoji;
  $("#meAvatar").style.background = `color-mix(in srgb, ${state.me.color} 22%, var(--card))`;
  $("#meName").textContent = state.me.name;
}
function renderPeers() {
  const wrap = $("#peers");
  wrap.textContent = "";
  const peers = [...state.peers.values()];
  $("#emptyState").classList.toggle("hidden", peers.length > 0);
  for (const p of peers) {
    const card = document.createElement("div");
    card.className = "peer";
    card.tabIndex = 0;

    const av = document.createElement("span");
    av.className = "avatar"; av.textContent = p.emoji;
    av.style.background = `color-mix(in srgb, ${p.color} 22%, var(--card))`;

    const nm = document.createElement("div");
    nm.className = "peer-name"; nm.textContent = p.name;
    const hint = document.createElement("div");
    hint.className = "peer-hint"; hint.textContent = "drop or tap to send";

    const acts = document.createElement("div");
    acts.className = "peer-actions";
    const noteBtn = document.createElement("button");
    noteBtn.textContent = "✎"; noteBtn.title = "Send a note";
    noteBtn.addEventListener("click", (e) => { e.stopPropagation(); openCompose(p.peerId, true); });
    acts.appendChild(noteBtn);

    card.append(acts, av, nm, hint);
    card.addEventListener("click", () => openCompose(p.peerId));
    card.addEventListener("keydown", (e) => { if (e.key === "Enter") openCompose(p.peerId); });

    // drag & drop straight onto a mailbox
    card.addEventListener("dragover", (e) => { e.preventDefault(); card.classList.add("drag"); });
    card.addEventListener("dragleave", () => card.classList.remove("drag"));
    card.addEventListener("drop", async (e) => {
      e.preventDefault(); card.classList.remove("drag");
      const files = await filesFromDrop(e.dataTransfer);
      if (files.length) sendFiles(p.peerId, files);
    });

    wrap.appendChild(card);
  }
}

function renderTransfer(t) {
  let el = document.getElementById("x-" + t.id);
  if (t.status === "declined" || (t.status === "failed" && t.dir === "in" && t.moved === 0)) {
    if (el) setTimeout(() => el.remove(), 2500);
  }
  if (!el) {
    el = document.createElement("div");
    el.id = "x-" + t.id; el.className = "xfer";
    el.innerHTML =
      '<div class="xfer-top"><span class="ic"></span>' +
      '<span class="xfer-name"></span><span class="xfer-pct"></span>' +
      '<button class="xfer-cancel ghost small hidden" type="button">Cancel</button></div>' +
      '<div class="bar-track"><div class="bar-fill"></div></div>' +
      '<div class="xfer-sub"></div>';
    $("#transfers").appendChild(el);
  }
  const total = t.totalBytes || 1;
  const pct = Math.min(100, Math.round((t.moved / total) * 100));
  const dirArrow = t.dir === "out" ? "↑" : "↓";
  const count = (t.meta || t.files).length;
  const label = count === 1 ? (t.meta ? t.meta[0].name : t.files[0].name) : `${count} files`;

  el.classList.toggle("done", t.status === "done");
  el.classList.toggle("failed", t.status === "failed" || t.status === "declined");
  el.querySelector(".ic").textContent = dirArrow;
  el.querySelector(".xfer-name").textContent = `${label} · ${nameOf(t.peerId)}`;
  el.querySelector(".xfer-pct").textContent =
    t.status === "done" ? "✓" : t.status === "failed" ? "failed" :
    t.status === "declined" ? "declined" : pct + "%";
  el.querySelector(".bar-fill").style.width =
    (t.status === "done" ? 100 : t.status === "failed" || t.status === "declined" ? 100 : pct) + "%";

  const cancelBtn = el.querySelector(".xfer-cancel");
  if (t.dir === "out" && t.status === "offering") {
    cancelBtn.classList.remove("hidden");
    cancelBtn.onclick = (e) => { e.stopPropagation(); cancelTransfer(t); };
  } else {
    cancelBtn.classList.add("hidden");
    cancelBtn.onclick = null;
  }

  const statusWord = {
    offering: "waiting for accept…", connecting: "connecting…",
    sending: "sending", receiving: "receiving", pending: "pending",
    done: "complete", failed: "transfer failed", declined: "declined",
  }[t.status] || t.status;
  const speed = (t.status === "sending" || t.status === "receiving") && t.speed > 0
    ? " · " + fmtSpeed(t.speed) : "";
  el.querySelector(".xfer-sub").textContent =
    `${statusWord} · ${fmtBytes(t.moved)} / ${fmtBytes(t.totalBytes)}${speed}`;

  if (t.status === "done") setTimeout(() => el.remove(), 4000);
  if (t.status === "failed") setTimeout(() => el.remove(), 6000);
}

/* ------------------------------------------------------------- inbox */
const inbox = $("#inbox");
function showInbox() { $("#inboxWrap").classList.remove("hidden"); }
function addInboxFile(t, name, blob) {
  showInbox();
  const url = URL.createObjectURL(blob);
  const item = document.createElement("div");
  item.className = "inbox-item";

  const thumb = document.createElement(blob.type.startsWith("image/") ? "img" : "div");
  thumb.className = "inbox-thumb";
  if (blob.type.startsWith("image/")) { thumb.src = url; thumb.alt = ""; }
  else thumb.textContent = "📄";

  const meta = document.createElement("div");
  meta.className = "inbox-meta";
  const nm = document.createElement("div"); nm.className = "inbox-name"; nm.textContent = name;
  const sub = document.createElement("div"); sub.className = "inbox-sub";
  sub.textContent = `${fmtBytes(blob.size)} · from ${nameOf(t.peerId)}`;
  meta.append(nm, sub);

  const save = document.createElement("button");
  save.className = "primary"; save.textContent = "Save";
  save.addEventListener("click", () => {
    const a = document.createElement("a");
    a.href = url; a.download = sanitizeName(name);
    document.body.appendChild(a); a.click(); a.remove();
  });

  item.append(thumb, meta, save);
  inbox.prepend(item);
}
async function copyRich(html, text) {
  try {
    if (navigator.clipboard && window.ClipboardItem) {
      const item = new ClipboardItem({
        "text/plain": new Blob([text], { type: "text/plain" }),
        "text/html": new Blob([html], { type: "text/html" }),
      });
      await navigator.clipboard.write([item]);
      return true;
    }
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
  }
}
function openNotePage(html, from) {
  const id = newId();
  const title = `Note from ${nameOf(from)}`;
  const tmp = document.createElement("div"); tmp.innerHTML = html;
  try {
    sessionStorage.setItem("lpo-note-" + id, JSON.stringify({ title, html, text: tmp.innerText }));
  } catch {
    toast("Couldn't open the note"); return;
  }
  window.open(`/note.html#${id}`, "_blank", "noopener");
}
function showMessage(from, text, html) {
  showInbox();
  const safeHtml = html ? sanitizeHtml(html) : escapeHtml(text).replace(/\n/g, "<br>");
  const item = document.createElement("div");
  item.className = "inbox-item inbox-item-note";
  const thumb = document.createElement("div");
  thumb.className = "inbox-thumb"; thumb.textContent = "📝";
  const meta = document.createElement("div"); meta.className = "inbox-meta";
  const sub = document.createElement("div"); sub.className = "inbox-sub";
  sub.textContent = `note · from ${nameOf(from)} · tap to open`;
  const body = document.createElement("div");
  body.className = "inbox-text"; body.innerHTML = safeHtml;
  meta.append(body, sub);
  const copy = document.createElement("button");
  copy.className = "ghost"; copy.textContent = "Copy";
  copy.addEventListener("click", async (e) => {
    e.stopPropagation();
    const ok = await copyRich(safeHtml, text);
    copy.textContent = ok ? "Copied" : "—";
    setTimeout(() => (copy.textContent = "Copy"), 1200);
  });
  item.append(thumb, meta, copy);
  item.addEventListener("click", () => openNotePage(safeHtml, from));
  inbox.prepend(item);
  toast(`Note from ${nameOf(from)}`);
}
$("#clearInbox").addEventListener("click", () => {
  inbox.textContent = ""; $("#inboxWrap").classList.add("hidden");
});

/* ------------------------------------------------------------- dialogs */
function show(b) { $(b).classList.remove("hidden"); }
function hide(b) { $(b).classList.add("hidden"); }

function setAvatar(el, p) {
  el.textContent = p.emoji || "✉️";
  el.style.background = `color-mix(in srgb, ${p.color || "var(--accent)"} 22%, var(--card))`;
}

function openCompose(peerId, focusNote) {
  const p = state.peers.get(peerId);
  if (!p) return;
  state.composeTarget = peerId;
  setAvatar($("#composeAvatar"), p);
  $("#composeName").textContent = p.name;
  $("#composeText").innerHTML = "";
  $("#composeFiles").value = "";
  show("#composeBackdrop");
  if (focusNote) setTimeout(() => $("#composeText").focus(), 50);
}
$("#composeClose").addEventListener("click", () => hide("#composeBackdrop"));
$("#composeFiles").addEventListener("change", (e) => {
  const files = [...e.target.files];
  if (files.length && state.composeTarget) { sendFiles(state.composeTarget, files); hide("#composeBackdrop"); }
});
$("#composeFolderBtn").addEventListener("click", () => $("#composeFolder").click());
$("#composeFolder").addEventListener("change", async (e) => {
  const target = state.composeTarget;
  if (!target || !e.target.files.length) return;
  toast("Zipping folder…");
  try {
    const zip = await fileListToZipFile(e.target.files);
    if (zip) { sendFiles(target, [zip]); hide("#composeBackdrop"); }
  } catch { toast("Couldn't zip that folder"); }
  finally { e.target.value = ""; }
});
$("#composeSend").addEventListener("click", () => {
  if (state.composeTarget) sendNote(state.composeTarget, $("#composeText"));
  hide("#composeBackdrop");
});
$("#composeText").addEventListener("paste", (e) => {
  const html = e.clipboardData && e.clipboardData.getData("text/html");
  if (!html) return; // let the browser's default plain-text paste happen
  e.preventDefault();
  document.execCommand("insertHTML", false, sanitizeHtml(html));
});
const cz = $("#composeDrop");
cz.addEventListener("dragover", (e) => { e.preventDefault(); cz.classList.add("drag"); });
cz.addEventListener("dragleave", () => cz.classList.remove("drag"));
cz.addEventListener("drop", async (e) => {
  e.preventDefault(); cz.classList.remove("drag");
  const target = state.composeTarget;
  const files = await filesFromDrop(e.dataTransfer);
  if (files.length && target) { sendFiles(target, files); hide("#composeBackdrop"); }
});

let pendingAcceptId = null;
function showAccept(peer, d, t) {
  pendingAcceptId = t.id;
  setAvatar($("#acceptAvatar"), peer);
  $("#acceptName").textContent = peer.name;
  $("#acceptSummary").textContent =
    `${d.files.length} item${d.files.length > 1 ? "s" : ""} · ${fmtBytes(d.totalBytes)}`;
  const list = $("#acceptList"); list.textContent = "";
  for (const f of d.files) {
    const row = document.createElement("div"); row.className = "file-row";
    const nm = document.createElement("span"); nm.className = "nm"; nm.textContent = f.name;
    const sz = document.createElement("span"); sz.className = "sz"; sz.textContent = fmtBytes(f.size);
    row.append(nm, sz); list.appendChild(row);
  }
  show("#acceptBackdrop");
  const close = () => { hide("#acceptBackdrop"); pendingAcceptId = null; };
  $("#acceptBtn").onclick = () => {
    close(); t.status = "accepting"; renderTransfer(t);
    signalTo(t.peerId, { kind: "accept", transferId: t.id });
  };
  $("#declineBtn").onclick = () => {
    close(); signalTo(t.peerId, { kind: "decline", transferId: t.id });
    state.transfers.delete(t.id);
  };
}

/* --------------------------------------------------------- invite + QR */
function inviteUrl() {
  const u = new URL(location.href);
  if (state.room !== "lobby") u.searchParams.set("room", state.room); else u.searchParams.delete("room");
  return u.toString();
}
function openInvite() {
  const url = inviteUrl();
  $("#inviteUrl").value = url;
  const qr = $("#qr"); qr.textContent = "";
  if (typeof qrcode === "function") {
    try {
      const q = qrcode(0, "M"); q.addData(url); q.make();
      qr.innerHTML = q.createSvgTag({ cellSize: 5, margin: 1, scalable: true });
    } catch { qr.textContent = "—"; }
  }
  const host = location.host;
  $("#inviteHint").textContent = location.protocol === "https:"
    ? "Both devices must be on the same Wi-Fi."
    : `Both devices must be on the same Wi-Fi. Tip: open http://${host} on the other device.`;
  show("#inviteBackdrop");
}
$("#inviteBtn").addEventListener("click", openInvite);
$("#emptyInvite").addEventListener("click", openInvite);
$("#inviteClose").addEventListener("click", () => hide("#inviteBackdrop"));
$("#copyUrl").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(inviteUrl()); $("#copyUrl").textContent = "Copied!"; }
  catch { $("#inviteUrl").select(); document.execCommand && document.execCommand("copy"); $("#copyUrl").textContent = "Copied!"; }
  setTimeout(() => ($("#copyUrl").textContent = "Copy"), 1400);
});

/* --------------------------------------------------------------- theme */
function applyTheme() {
  const t = localStorage.getItem("lpo-theme") || "auto";
  document.documentElement.setAttribute("data-theme", t);
}
$("#themeBtn").addEventListener("click", () => {
  const order = ["auto", "light", "dark"];
  const cur = localStorage.getItem("lpo-theme") || "auto";
  const next = order[(order.indexOf(cur) + 1) % order.length];
  localStorage.setItem("lpo-theme", next); applyTheme();
  toast("Theme: " + next);
});
applyTheme();

/* ----------------------------------------------------------- rename me */
$("#meCard").addEventListener("click", () => {
  const cur = state.me ? state.me.name : "";
  const name = prompt("Your display name on the network:", cur);
  if (name === null) return;
  const trimmed = name.trim().slice(0, 32);
  if (trimmed) { localStorage.setItem("lpo-name", trimmed); sigSend({ type: "rename", name: trimmed });
    if (state.me) { state.me.name = trimmed; renderMe(); } }
  else { localStorage.removeItem("lpo-name"); }
});

/* ------------------------------------------------------- global paste */
window.addEventListener("paste", (e) => {
  const items = e.clipboardData;
  if (!items) return;
  const files = [...(items.files || [])];
  const peers = [...state.peers.values()];
  if (files.length && peers.length === 1) { sendFiles(peers[0].peerId, files); toast(`Pasted → ${peers[0].name}`); }
  else if (files.length && peers.length > 1) toast("Tap a mailbox, then paste in the note box");
});

/* ----------------------------------------------------------- toasts */
function toast(msg) {
  const el = document.createElement("div");
  el.className = "toast"; el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; el.style.transition = "opacity .3s"; setTimeout(() => el.remove(), 300); }, 2600);
}

/* ---------------------------------------------------- LAN awareness scan */
$("#scanBtn").addEventListener("click", scanLan);
async function scanLan() {
  const btn = $("#scanBtn");
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "Scanning…";
  $("#lanList").innerHTML = '<div class="aware-loading"><span class="spinner"></span> Scanning your network…</div>';
  try {
    const r = await fetch("/lan-scan", { cache: "no-store" });
    const j = await r.json();
    if (j.hosted) { $(".lan-aware").classList.add("hidden"); return; }
    renderLan(j.devices || []);
  } catch { toast("Scan failed"); $("#lanList").textContent = ""; }
  finally { btn.disabled = false; btn.textContent = label; }
}
function renderLan(devices) {
  const list = $("#lanList");
  list.textContent = "";
  const seen = devices.filter((d) => !d.hasApp);
  const appCount = devices.length - seen.length;
  if (!devices.length) {
    const e = document.createElement("div");
    e.className = "aware-empty";
    e.textContent = "No other devices found on your network.";
    list.appendChild(e);
  }
  for (const d of seen) {
    const row = document.createElement("div");
    row.className = "lan-item";
    const ic = document.createElement("span");
    ic.className = "lan-ic"; ic.textContent = "📶";
    const meta = document.createElement("div"); meta.className = "lan-meta";
    const nm = document.createElement("div"); nm.className = "lan-name";
    nm.textContent = d.vendor && !d.vendor.startsWith("Private") ? d.vendor : "Unknown device";
    const sub = document.createElement("div"); sub.className = "lan-sub";
    sub.textContent = `${d.ip} · ${d.vendor || "MAC " + d.mac}`;
    meta.append(nm, sub);
    const tag = document.createElement("span"); tag.className = "lan-tag"; tag.textContent = "no app";
    row.append(ic, meta, tag);
    list.appendChild(row);
  }
  $("#awareSub").innerHTML =
    `${seen.length} device${seen.length === 1 ? "" : "s"} seen without PostOffice open` +
    (appCount ? ` · ${appCount} already shown as mailbox${appCount === 1 ? "" : "es"} above` : "") +
    `. To send to one, open the app on it — tap <b>＋ Invite</b> for the QR.`;
}

/* close dialogs on backdrop click / Escape */
for (const b of ["#composeBackdrop", "#inviteBackdrop"]) {
  $(b).addEventListener("click", (e) => { if (e.target === $(b)) hide(b); });
}
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") ["#composeBackdrop", "#inviteBackdrop"].forEach(hide);
});

connect();
