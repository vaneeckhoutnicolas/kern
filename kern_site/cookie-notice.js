/*
 * kern.brussels privacy notice
 * --------------------------------------------------------------------------
 * A small, self-contained transparency notice. The site is fully static and
 * sets no cookies and runs no trackers or analytics, so this is NOT a consent
 * banner (there is nothing to consent to) but a one-line disclosure.
 *
 * Dismissal is remembered with sessionStorage, which is temporary client-side
 * state cleared when the browser tab is closed. It is not a cookie and is
 * never transmitted to any server. Remove the storage block below if you want
 * the notice to appear on every page load with zero storage of any kind.
 *
 * Drop-in: add `<script defer src="cookie-notice.js"></script>` before </body>.
 * No dependencies. Brand colours are inlined so it matches the site on its own.
 */
(function () {
  "use strict";

  var KEY = "kern-privacy-notice-dismissed";
  var ID = "kern-privacy-notice";

  // Already dismissed this session, or already injected: do nothing.
  try {
    if (sessionStorage.getItem(KEY) === "1") return;
  } catch (e) {
    /* sessionStorage unavailable (e.g. strict private mode): show the notice */
  }
  if (document.getElementById(ID)) return;

  function init() {
    if (document.getElementById(ID)) return;

    var style = document.createElement("style");
    style.textContent = [
      "#" + ID + "{",
      "  position:fixed;left:0;right:0;bottom:0;z-index:2147483000;",
      "  background:#0E1A2B;color:#FAFAF7;border-top:1px solid #C2885E;",
      "  box-shadow:0 -6px 24px rgba(14,26,43,.28);",
      "  font-family:'Instrument Sans',-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif;",
      "  transform:translateY(100%);transition:transform .35s ease;",
      "}",
      "#" + ID + ".kp-show{transform:translateY(0);}",
      "#" + ID + " .kp-inner{",
      "  max-width:1080px;margin:0 auto;padding:14px 22px;",
      "  display:flex;align-items:center;gap:18px;flex-wrap:wrap;",
      "}",
      "#" + ID + " .kp-text{flex:1 1 300px;min-width:240px;font-size:13.5px;line-height:1.5;color:#E7EAEF;}",
      "#" + ID + " .kp-tag{",
      "  font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,monospace;",
      "  font-size:10px;letter-spacing:1.8px;text-transform:uppercase;color:#C2885E;",
      "  display:block;margin-bottom:3px;",
      "}",
      "#" + ID + " .kp-btn{",
      "  flex:0 0 auto;appearance:none;cursor:pointer;",
      "  background:#C2885E;color:#0E1A2B;border:0;border-radius:999px;",
      "  font:600 13px/1 'Instrument Sans',-apple-system,Arial,sans-serif;",
      "  padding:9px 18px;transition:background .18s,transform .18s;",
      "}",
      "#" + ID + " .kp-btn:hover{background:#D29B72;transform:translateY(-1px);}",
      "#" + ID + " .kp-btn:focus-visible{outline:2px solid #FAFAF7;outline-offset:2px;}",
      "@media (max-width:560px){",
      "  #" + ID + " .kp-inner{padding:13px 16px;gap:12px;}",
      "  #" + ID + " .kp-btn{width:100%;padding:11px 18px;}",
      "}",
      "@media (prefers-reduced-motion:reduce){",
      "  #" + ID + "{transition:none;}",
      "}"
    ].join("");
    document.head.appendChild(style);

    var bar = document.createElement("div");
    bar.id = ID;
    bar.setAttribute("role", "region");
    bar.setAttribute("aria-label", "Privacy notice");

    var inner = document.createElement("div");
    inner.className = "kp-inner";

    var text = document.createElement("p");
    text.className = "kp-text";
    text.innerHTML =
      '<span class="kp-tag">Privacy</span>' +
      "kern.brussels is a static site. It sets no cookies and runs no trackers " +
      "or analytics, and it collects no personal data.";

    var btn = document.createElement("button");
    btn.className = "kp-btn";
    btn.type = "button";
    btn.textContent = "Got it";
    btn.setAttribute("aria-label", "Dismiss privacy notice");

    btn.addEventListener("click", function () {
      bar.classList.remove("kp-show");
      try {
        sessionStorage.setItem(KEY, "1");
      } catch (e) {
        /* ignore: storage unavailable */
      }
      var remove = function () {
        if (bar && bar.parentNode) bar.parentNode.removeChild(bar);
      };
      // Remove after the slide-out, with a fallback if transitionend never fires.
      bar.addEventListener("transitionend", remove, { once: true });
      setTimeout(remove, 500);
    });

    inner.appendChild(text);
    inner.appendChild(btn);
    bar.appendChild(inner);
    document.body.appendChild(bar);

    // Trigger the slide-up on the next frame so the transition runs.
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        bar.classList.add("kp-show");
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
