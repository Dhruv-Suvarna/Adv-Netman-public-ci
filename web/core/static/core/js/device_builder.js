/*
 * Phase 9 Device Builder client-side draft state.
 *
 * Contract (see docs/DEVICE_BUILDER_FOUNDATION.md):
 *   - Typing (handleFieldInput) mutates ONLY local state and the preview.
 *     It never makes a network request, never submits a form, never
 *     persists anything.
 *   - Only an explicit Enter/Ctrl+Enter/Commit-button action (commitField)
 *     makes a network request -- the one POST to bootstrap.commitUrl.
 *   - The preview is reconstructed by substituting draft values into the
 *     "slot" descriptors the Python renderer already produced (path +
 *     template string) -- this file never invents vendor CLI syntax itself,
 *     including the header banner text, which always comes from the
 *     server's candidate.header_lines rather than a hardcoded string here.
 *   - Phase 20.5: "collection" forms (Add/Remove Interface, Address, Static
 *     Route, BGP/OSPF/etc instance, FHRP/NAT/ACL/PBR/DHCP object, ...) are
 *     ordinary server-rendered Django forms -- there is no second client-side
 *     copy of their behavior. They are submitted asynchronously instead of a
 *     full browser navigation, and the server's own re-rendered editor
 *     fragment replaces this page's content in place, so Basic/Advanced mode,
 *     scroll position and the current interface/routing selection all survive
 *     (see views._collection_redirect, which is what makes the fetched page
 *     reflect the right mode/selection in the first place).
 */
(function () {
  "use strict";

  var root = document.querySelector("[data-device-builder-root]");
  if (!root) return;

  var bootstrap, csrfToken, previewEl, headerLines, candidateDescriptors, state;

  // Reads the current DOM's bootstrap JSON / CSRF token / candidate preview
  // element into the variables above. Called once on load and again after
  // every collection-form swap, since that swap replaces the DOM nodes these
  // were read from.
  function readBootstrap() {
    var bootstrapEl = document.getElementById("device-builder-bootstrap");
    if (!bootstrapEl) return false;
    bootstrap = JSON.parse(bootstrapEl.textContent);

    var csrfCarrier = document.getElementById("device-builder-csrf");
    var csrfInput = csrfCarrier ? csrfCarrier.querySelector('input[name="csrfmiddlewaretoken"]') : null;
    csrfToken = csrfInput ? csrfInput.value : "";

    previewEl = root.querySelector("[data-candidate-preview]");
    headerLines = (bootstrap.candidate && bootstrap.candidate.header_lines) || [];
    candidateDescriptors = (bootstrap.candidate && bootstrap.candidate.descriptors) || [];

    // Each entry: { draftValue, acceptedValue, dirty, validationState, validationMessage }
    state = {};
    Object.keys(bootstrap.fieldStates || {}).forEach(function (path) {
      var fieldState = bootstrap.fieldStates[path];
      state[path] = {
        draftValue: fieldState.draftValue,
        acceptedValue: fieldState.acceptedValue,
        dirty: fieldState.dirty,
        validationState: fieldState.validationState,
        validationMessage: fieldState.validationMessage,
      };
    });
    return true;
  }

  if (!readBootstrap()) return;

  function lineTextFromDescriptor(descriptor, valuesByPath) {
    if (descriptor.kind === "static") {
      return descriptor.text;
    }
    var value = valuesByPath[descriptor.path];
    if (value === undefined || value === null || value === "") {
      value = descriptor.value || "";
    }
    if (!value && descriptor.omit_if_empty) return null;
    return descriptor.template.replace("{value}", value);
  }

  // --- browser-side preview: substitutes DRAFT values into server slots ----
  function renderPreviewFromDraft() {
    if (!previewEl) return;
    var valuesByPath = {};
    Object.keys(state).forEach(function (path) {
      valuesByPath[path] = state[path].draftValue;
    });
    var lines = headerLines.concat([""]);
    candidateDescriptors.forEach(function (descriptor) {
      var text = lineTextFromDescriptor(descriptor, valuesByPath);
      if (text !== null) lines.push(text);
    });
    previewEl.textContent = lines.join("\n");
  }

  // --- after a successful commit, reconcile with the Python-authoritative render
  function setAuthoritativeCandidate(candidate) {
    headerLines = candidate.header_lines || headerLines;
    candidateDescriptors = candidate.descriptors || [];
    if (previewEl) previewEl.textContent = candidate.text;
  }

  function fieldStatusLabel(path) {
    var field = state[path];
    if (!field) return "ACCEPTED";
    if (field.validationState === "INVALID") return "INVALID / ROLLED BACK";
    if (field.dirty) return "DRAFT / UNCOMMITTED";
    if (/^(interfaces|routing|fhrp|nat|services|security|policy)\./.test(path) && field.validationState === "VALID") return "SYNTAX ACCEPTED";
    return "ACCEPTED";
  }

  function updateFieldUI(path) {
    var row = root.querySelector('[data-field-row="' + path + '"]');
    if (!row) return;
    var statusEl = row.querySelector("[data-field-status]");
    var messageEl = row.querySelector("[data-field-message]");
    var field = state[path];
    if (statusEl) {
      var label = fieldStatusLabel(path);
      statusEl.textContent = label;
      var statusClass = "field-status--accepted";
      if (label.indexOf("INVALID") === 0) statusClass = "field-status--invalid";
      else if (label.indexOf("DRAFT") === 0) statusClass = "field-status--draft";
      statusEl.className = "badge field-status " + statusClass;
    }
    if (messageEl) {
      messageEl.textContent = field ? field.validationMessage : "";
    }
  }

  // --- typing: local state + preview ONLY, no network call whatsoever -----
  function handleFieldInput(event) {
    var el = event.target;
    var path = el.getAttribute("data-field-path");
    if (!path || !state[path]) return;
    state[path].draftValue = el.value;
    state[path].dirty = state[path].draftValue !== state[path].acceptedValue;
    renderPreviewFromDraft();
    updateFieldUI(path);
    if (el.hasAttribute("data-address-source-select")) {
      syncAddressSource(el.closest("[data-address-id]"), el.value);
    }
  }

  // --- the ONLY function in this file that makes a network request --------
  function commitField(path) {
    var field = state[path];
    if (!field) return;
    fetch(bootstrap.commitUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
      body: JSON.stringify({ path: path, value: field.draftValue, revisionId: bootstrap.revisionId }),
    })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        field.acceptedValue = data.acceptedValue;
        field.draftValue = data.draftValue;
        field.dirty = false;
        field.validationState = data.validationState;
        field.validationMessage = data.validationMessage;
        var input = root.querySelector('[data-field-path="' + path + '"]');
        if (input) input.value = data.draftValue;
        if (data.candidate) setAuthoritativeCandidate(data.candidate);
        if (data.interfaceTypeChoices) updateInterfaceTypeChoices(data.interfaceTypeChoices);
        if (data.newInterfaceTypeChoices) updateNewInterfaceTypeChoices(data.newInterfaceTypeChoices);
        if (data.platformWarning) {
          var warning = root.querySelector("[data-platform-warning]");
          if (warning) warning.hidden = false;
        }
        // A platform commit changes several server-owned capability selectors.
        // Reload only after that explicit commit so all future-object controls
        // are rebuilt from the authoritative capability registry.
        if (path === "device.platform" && data.ok) {
          window.location.reload();
          return;
        }
        updateFieldUI(path);
        if (input && input.hasAttribute("data-address-source-select")) {
          syncAddressSource(input.closest("[data-address-id]"), input.value);
        }
      })
      .catch(function () {
        field.validationState = "INVALID";
        field.validationMessage = "The commit request failed; accepted state is unchanged.";
        updateFieldUI(path);
      });
  }

  function updateInterfaceTypeChoices(choicesByInterface) {
    Object.keys(choicesByInterface).forEach(function (interfaceId) {
      var select = root.querySelector('[data-interface-kind-select="' + interfaceId + '"]');
      if (!select) return;
      var current = select.value;
      select.textContent = "";
      choicesByInterface[interfaceId].forEach(function (choice) {
        var option = document.createElement("option");
        option.value = choice.value;
        option.textContent = choice.label;
        option.selected = choice.value === current;
        select.appendChild(option);
      });
    });
  }

  function updateNewInterfaceTypeChoices(choices) {
    var select = root.querySelector("[data-new-interface-kind-select]");
    if (!select) return;
    select.textContent = "";
    choices.forEach(function (choice) {
      var option = document.createElement("option");
      option.value = choice.value;
      option.textContent = choice.label;
      select.appendChild(option);
    });
  }

  function syncAddressSource(card, source) {
    if (!card) return;
    var manual = card.querySelector("[data-address-manual]");
    var automatic = card.querySelector("[data-address-auto]");
    if (manual) manual.hidden = source === "AUTO";
    if (automatic) automatic.hidden = source !== "AUTO";
  }

  // Explicit read-only IPAM action. This is never called by typing,
  // preview rendering, or an unrelated field commit.
  function requestIpamPrefixes(button) {
    var card = button.closest("[data-address-id]");
    var input = card ? card.querySelector("[data-ipam-prefix-input]") : null;
    var list = input ? document.getElementById(input.getAttribute("list")) : null;
    var message = card ? card.querySelector("[data-ipam-message]") : null;
    fetch(button.getAttribute("data-ipam-url"), {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken },
    })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (!data.ok) throw new Error(data.message || "Prefix lookup failed.");
        if (list) {
          list.textContent = "";
          data.prefixes.forEach(function (prefix) {
            var option = document.createElement("option");
            option.value = prefix;
            list.appendChild(option);
          });
        }
        if (message) message.textContent = data.message;
      })
      .catch(function (error) {
        if (message) message.textContent = error.message || "Prefix lookup failed.";
      });
  }

  function handleFieldKeydown(event) {
    var el = event.target;
    var path = el.getAttribute("data-field-path");
    if (!path) return;
    var isMultiline = el.tagName === "TEXTAREA";
    if (isMultiline) {
      if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        commitField(path);
      }
      return; // plain Enter inserts a newline in a multiline field, by design
    }
    if (event.key === "Enter") {
      event.preventDefault();
      commitField(path);
    }
  }

  function handleCommitButtonClick(event) {
    var ipamButton = event.target.closest("[data-ipam-prefixes]");
    if (ipamButton) {
      requestIpamPrefixes(ipamButton);
      return;
    }
    // Delegated (not a one-time querySelector binding) so this keeps working
    // after a collection-form swap replaces the button's DOM node.
    var copyButton = event.target.closest("[data-copy-candidate]");
    if (copyButton) {
      copyCandidate();
      return;
    }
    var button = event.target.closest("[data-commit-field]");
    if (!button) return;
    commitField(button.getAttribute("data-commit-field"));
  }

  function copyCandidate() {
    var text = previewEl ? previewEl.textContent : "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(function () { fallbackCopy(text); });
    } else {
      fallbackCopy(text);
    }
  }

  function initializeView() {
    renderPreviewFromDraft();
    Object.keys(state).forEach(updateFieldUI);
    root.querySelectorAll("[data-address-id]").forEach(function (card) {
      var source = card.querySelector("[data-address-source-select]");
      if (source) syncAddressSource(card, source.value);
    });
  }

  // --- collection forms: async submission instead of a full-page navigation
  // Enter inside a plain input with no data-field-path (e.g. "Add Interface"
  // name field) falls through to the browser's native "submit the nearest
  // form" behavior, which dispatches this same "submit" event -- so this one
  // handler also fixes the accidental-Enter-submits-the-whole-page regression
  // for every collection form, not just an explicit button click.
  function handleCollectionFormSubmit(event) {
    var form = event.target.closest(".collection-form");
    if (!form || form.tagName !== "FORM") return;
    event.preventDefault();
    var scrollPosition = window.scrollY;
    fetch(form.getAttribute("action"), {
      method: "POST",
      credentials: "same-origin",
      body: new FormData(form),
    })
      .then(function (response) {
        if (!response.ok) throw new Error("collection request failed");
        return response.text().then(function (html) {
          return { html: html, url: response.url };
        });
      })
      .then(function (result) {
        var parsed = new DOMParser().parseFromString(result.html, "text/html");
        var newRoot = parsed.querySelector("[data-device-builder-root]");
        var newBootstrapEl = parsed.getElementById("device-builder-bootstrap");
        if (!newRoot || !newBootstrapEl) {
          window.location.href = result.url;
          return;
        }
        root.innerHTML = newRoot.innerHTML;
        var bootstrapEl = document.getElementById("device-builder-bootstrap");
        if (bootstrapEl) bootstrapEl.textContent = newBootstrapEl.textContent;
        var newCsrfEl = parsed.getElementById("device-builder-csrf");
        var csrfEl = document.getElementById("device-builder-csrf");
        if (csrfEl && newCsrfEl) csrfEl.innerHTML = newCsrfEl.innerHTML;
        window.history.replaceState(window.history.state, "", result.url);
        readBootstrap();
        initializeView();
        window.scrollTo(0, scrollPosition);
      })
      .catch(function () {
        // Progressive-enhancement fallback: a real navigation still works
        // exactly as before fetch was introduced. form.submit() bypasses the
        // "submit" event entirely, so this cannot re-trigger this handler.
        form.submit();
      });
  }

  root.addEventListener("input", handleFieldInput);
  root.addEventListener("keydown", handleFieldKeydown);
  root.addEventListener("click", handleCommitButtonClick);
  root.addEventListener("submit", handleCollectionFormSubmit);

  function fallbackCopy(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand("copy");
    } catch (err) {
      /* clipboard unavailable in this browser context -- no-op */
    }
    document.body.removeChild(textarea);
  }

  // --- warn on navigating away with uncommitted draft fields --------------
  window.addEventListener("beforeunload", function (event) {
    var hasDirty = Object.keys(state).some(function (path) { return state[path].dirty; });
    if (hasDirty) {
      event.preventDefault();
      event.returnValue = "";
    }
  });

  initializeView();
})();
