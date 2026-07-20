"use strict";
(function () {
  const id = location.hash.slice(1);
  let note = null;
  try { note = JSON.parse(sessionStorage.getItem("lpo-note-" + id) || "null"); } catch {}

  const titleEl = document.getElementById("noteTitle");
  const bodyEl = document.getElementById("noteBody");
  const copyBtn = document.getElementById("copyBtn");

  if (!note) {
    document.title = "Note not found — LAN PostOffice";
    titleEl.textContent = "Note";
    bodyEl.innerHTML = '<div class="note-missing">This note link has expired — go back and tap it again.</div>';
    copyBtn.remove();
    return;
  }

  document.title = note.title + " — LAN PostOffice";
  titleEl.textContent = note.title;
  bodyEl.innerHTML = note.html;

  copyBtn.addEventListener("click", async () => {
    try {
      if (navigator.clipboard && window.ClipboardItem) {
        await navigator.clipboard.write([new ClipboardItem({
          "text/plain": new Blob([bodyEl.innerText], { type: "text/plain" }),
          "text/html": new Blob([bodyEl.innerHTML], { type: "text/html" }),
        })]);
      } else {
        await navigator.clipboard.writeText(bodyEl.innerText);
      }
      copyBtn.textContent = "Copied";
    } catch {
      copyBtn.textContent = "Failed";
    }
    setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
  });
})();
