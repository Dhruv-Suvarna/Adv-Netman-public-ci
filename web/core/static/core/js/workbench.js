/* Automation workbench helpers (Configuration Changes / Remove Configuration).
 * DOM-only conveniences: no network request is ever made here; every form submits normally to the server,
 * which re-derives and re-validates everything.  Works without JavaScript (the server renders all states). */
(function () {
  "use strict";
  document.querySelectorAll("[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () { if (select.form) { select.form.submit(); } });
  });

  // Supporting-config widget switcher: only the chosen fieldset is enabled (disabled inputs are never submitted).
  var opSelect = document.querySelector("[data-op-select]");
  if (opSelect) {
    var sync = function () {
      document.querySelectorAll("fieldset.op-fields").forEach(function (fs) {
        var active = fs.getAttribute("data-op") === opSelect.value;
        fs.hidden = !active;
        fs.querySelectorAll("input, select").forEach(function (el) { el.disabled = !active; });
      });
    };
    opSelect.addEventListener("change", sync);
    sync();
  }

  // Line-range selection: click a line number for "From", shift-click for "Through".
  var from = document.querySelector("[data-range='from']");
  var to = document.querySelector("[data-range='to']");
  if (from && to) {
    document.querySelectorAll(".running-config .rc-line").forEach(function (line) {
      line.querySelector(".rc-no").addEventListener("click", function (event) {
        var number = line.getAttribute("data-line");
        if (event.shiftKey && from.value) { to.value = number; } else { from.value = number; to.value = number; }
        document.querySelectorAll(".rc-line--sel").forEach(function (el) { el.classList.remove("rc-line--sel"); });
        var a = parseInt(from.value, 10), b = parseInt(to.value, 10);
        for (var n = Math.min(a, b); n <= Math.max(a, b); n++) {
          var el = document.getElementById("L" + n);
          if (el) { el.classList.add("rc-line--sel"); }
        }
      });
    });
  }
})();
