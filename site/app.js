(function () {
  "use strict";

  var manifest = window.EYEOF_MANIFEST || { files: [] };
  var cards = document.getElementById("cards");
  var verify = document.getElementById("verify");
  var note = document.getElementById("arch-note");
  var home = document.getElementById("home");
  var downloadsView = document.getElementById("downloads-view");

  function setView() {
    var name = (location.hash || "").replace("#", "") === "downloads" ? "downloads" : "home";
    if (home) home.classList.toggle("active", name === "home");
    if (downloadsView) downloadsView.classList.toggle("active", name === "downloads");
    window.scrollTo(0, 0);
  }
  setView();
  window.addEventListener("hashchange", setView);

  function esc(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function humanSize(bytes) {
    if (!bytes || bytes < 0) return "unknown size";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  if (note) note.textContent = "Match the architecture to `uname -m` — all packages are prebuilt.";
  if (!cards) return;

  if (!manifest.files.length) {
    cards.innerHTML = '<div class="card"><h3>No packages published yet</h3>' +
      '<p class="meta">Run <code>./site/generate.sh</code> after building packages.</p></div>';
    verify.textContent = "# no checksums available yet";
    return;
  }

  var html = "";
  var checksumLines = [];

  manifest.files.forEach(function (f) {
    var href = "downloads/" + encodeURIComponent(f.file);
    var shortHash = f.sha256 ? f.sha256.slice(0, 16) + "…" : "not available";
    html += '<article class="card">'
      + '<div class="card-top"><h3>' + esc(f.label) + '</h3><span class="arch">' + esc(f.arch) + '</span></div>'
      + '<p class="file">' + esc(f.file) + '</p>'
      + '<p class="meta">' + humanSize(f.size) + ' · SHA-256</p>'
      + '<div class="hash" title="' + esc(f.sha256) + '"><span>sha256:</span> ' + esc(shortHash) + '</div>'
      + '<div class="cmd"><code id="cmd-' + esc(f.id) + '">' + esc(f.install) + '</code>'
      + '<button class="copy" type="button" data-copy="cmd-' + esc(f.id) + '">COPY</button></div>'
      + '<a class="button primary dl" href="' + href + '" download>Download ' + esc(f.file) + ' ↓</a>'
      + '</article>';
    if (f.sha256) checksumLines.push(f.sha256 + "  " + f.file);
  });

  cards.innerHTML = html;
  verify.textContent = "# From the folder containing the downloaded file:\n"
    + checksumLines.join("\n")
    + "\n\n# Or check automatically:\nsha256sum -c <(printf '%s\\n' \\\n"
    + checksumLines.map(function (l) { return "  '" + l + "'"; }).join(" \\\n")
    + ")";

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var target = document.getElementById(button.getAttribute("data-copy"));
      if (!target) return;
      var text = target.textContent;
      var done = function () {
        var old = button.textContent;
        button.textContent = "COPIED";
        window.setTimeout(function () { button.textContent = old; }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
      } else {
        fallbackCopy(text, done);
      }
    });
  });

  function fallbackCopy(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
    done();
  }
}());
