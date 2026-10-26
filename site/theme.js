// Light/dark theme: follows the system setting until the visitor picks one with the header button.
// The choice is kept in localStorage (best effort; works without it). Loaded in <head> so there is no flash.
(function () {
  var KEY = "cvea-theme";
  var root = document.documentElement;
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function saved() {
    try { var v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : null; } catch (e) { return null; }
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    var color = theme === "dark" ? "#1e293b" : "#ffffff";
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) metas[i].setAttribute("content", color);
    var btn = document.getElementById("themeBtn");
    if (btn) {
      var label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
      btn.setAttribute("aria-label", label);
      btn.setAttribute("title", label);
    }
  }

  apply(saved() || (mq && mq.matches ? "dark" : "light"));

  document.addEventListener("DOMContentLoaded", function () {
    apply(root.getAttribute("data-theme"));
    var btn = document.getElementById("themeBtn");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      try { localStorage.setItem(KEY, next); } catch (e) { /* private mode: still switches for this visit */ }
      apply(next);
    });
  });

  if (mq && mq.addEventListener) {
    mq.addEventListener("change", function (e) { if (!saved()) apply(e.matches ? "dark" : "light"); });
  }
})();
