// Small, focused interactivity: dropdown toggles + mobile sidebar collapse.
// No frontend framework, no state beyond simple open/closed toggles. Theme
// persistence itself is a server-set cookie (see core/views.py:set_theme);
// this file has no role in persisting it.
(function () {
  function closeAllDropdowns(except) {
    document.querySelectorAll("[data-dropdown-panel]").forEach(function (panel) {
      if (panel !== except) panel.setAttribute("hidden", "");
    });
  }

  document.querySelectorAll("[data-dropdown-trigger]").forEach(function (trigger) {
    trigger.addEventListener("click", function (event) {
      event.stopPropagation();
      var targetId = trigger.getAttribute("data-dropdown-trigger");
      var panel = document.getElementById(targetId);
      if (!panel) return;
      var isHidden = panel.hasAttribute("hidden");
      closeAllDropdowns(isHidden ? panel : null);
      if (isHidden) {
        panel.removeAttribute("hidden");
      } else {
        panel.setAttribute("hidden", "");
      }
    });
  });

  document.addEventListener("click", function () {
    closeAllDropdowns(null);
  });

  // Notification detail: opening the page never mutates state by itself
  // (plain GET). If the notification is unread, this fires a background
  // POST (CSRF-protected, same endpoint the visible "Mark as read" button
  // uses) so opening it behaves like "mark read" without a page reload.
  // With JavaScript disabled, the visible button is the only way to mark
  // it read -- see docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md.
  var markReadForm = document.getElementById("mark-read-form");
  if (markReadForm && window.fetch) {
    var csrfInput = markReadForm.querySelector('input[name="csrfmiddlewaretoken"]');
    var actionUrl = markReadForm.getAttribute("action");
    if (csrfInput && actionUrl) {
      window.fetch(actionUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrfInput.value },
        body: new FormData(markReadForm),
      }).catch(function () {});
    }
  }

  var sidebar = document.querySelector("[data-sidebar]");
  var sidebarToggle = document.querySelector("[data-sidebar-toggle]");
  if (sidebar && sidebarToggle) {
    sidebarToggle.addEventListener("click", function (event) {
      event.stopPropagation();
      sidebar.classList.toggle("is-open");
    });
    document.addEventListener("click", function (event) {
      if (sidebar.classList.contains("is-open") && !sidebar.contains(event.target)) {
        sidebar.classList.remove("is-open");
      }
    });
  }
})();
