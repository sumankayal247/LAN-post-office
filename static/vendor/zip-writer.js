/* Minimal client-side ZIP writer — store-only (no compression), pure browser APIs.
   Used to bundle a dropped/selected folder into a single .zip before it's sent
   over the existing P2P file-transfer pipeline. No third-party code. */
"use strict";

(function (global) {
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(bytes) {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  const DOS_DATE = 0x21; // 1980-01-01
  const DOS_TIME = 0x00;

  /**
   * entries: [{ name: "folder/sub/file.txt", data: Uint8Array }]
   * returns: Blob (application/zip)
   */
  function makeZip(entries) {
    const enc = new TextEncoder();
    const locals = [];
    const centrals = [];
    let offset = 0;

    for (const { name, data } of entries) {
      const nameBytes = enc.encode(name.replace(/\\/g, "/"));
      const crc = crc32(data);
      const size = data.length;

      const lh = new Uint8Array(30 + nameBytes.length);
      const ldv = new DataView(lh.buffer);
      ldv.setUint32(0, 0x04034b50, true);
      ldv.setUint16(4, 20, true);
      ldv.setUint16(6, 0x0800, true); // UTF-8 filenames
      ldv.setUint16(8, 0, true);      // stored, no compression
      ldv.setUint16(10, DOS_TIME, true);
      ldv.setUint16(12, DOS_DATE, true);
      ldv.setUint32(14, crc, true);
      ldv.setUint32(18, size, true);
      ldv.setUint32(22, size, true);
      ldv.setUint16(26, nameBytes.length, true);
      ldv.setUint16(28, 0, true);
      lh.set(nameBytes, 30);
      locals.push(lh, data);

      const ch = new Uint8Array(46 + nameBytes.length);
      const cdv = new DataView(ch.buffer);
      cdv.setUint32(0, 0x02014b50, true);
      cdv.setUint16(4, 20, true);
      cdv.setUint16(6, 20, true);
      cdv.setUint16(8, 0x0800, true);
      cdv.setUint16(10, 0, true);
      cdv.setUint16(12, DOS_TIME, true);
      cdv.setUint16(14, DOS_DATE, true);
      cdv.setUint32(16, crc, true);
      cdv.setUint32(20, size, true);
      cdv.setUint32(24, size, true);
      cdv.setUint16(28, nameBytes.length, true);
      cdv.setUint16(30, 0, true);
      cdv.setUint16(32, 0, true);
      cdv.setUint16(34, 0, true);
      cdv.setUint16(36, 0, true);
      cdv.setUint32(38, 0, true);
      cdv.setUint32(42, offset, true);
      ch.set(nameBytes, 46);
      centrals.push(ch);

      offset += lh.length + size;
    }

    const centralStart = offset;
    const centralSize = centrals.reduce((a, p) => a + p.length, 0);

    const end = new Uint8Array(22);
    const edv = new DataView(end.buffer);
    edv.setUint32(0, 0x06054b50, true);
    edv.setUint16(4, 0, true);
    edv.setUint16(6, 0, true);
    edv.setUint16(8, entries.length, true);
    edv.setUint16(10, entries.length, true);
    edv.setUint32(12, centralSize, true);
    edv.setUint32(16, centralStart, true);
    edv.setUint16(20, 0, true);

    return new Blob([...locals, ...centrals, end], { type: "application/zip" });
  }

  global.makeZip = makeZip;
})(window);
