"""Static contract for ``device_builder.js`` (the browser side of the editor).

The project has no JS test framework, so the file is treated as text: a named
function's body is located by slicing between its ``function name(`` line and
the next top-level ``function`` declaration, then asserted on.

This is the ONE place the browser contract lives.  It replaces the per-phase
JS-contract copies (Phase 9/10/11/12) whose assertions overlapped: typing is
browser-local, only an explicit commit/IPAM refresh touches the network, and
the browser never becomes a second vendor renderer.  Do not add a new
per-phase JS test -- extend a case here.
"""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

JS_PATH = Path(__file__).resolve().parents[1] / "static" / "core" / "js" / "device_builder.js"

# Vendor syntax the browser must never contain: Python (platform drivers +
# Jinja feature templates) is the only renderer.  Grouped by the phase that
# introduced the feature so a failure names the family.
VENDOR_CLI_TOKENS = {
    "interfaces": ("switchport", "encapsulation dot1q", "ip link add"),
    "routing": (
        "router bgp", "router ospf", "router rip", "router isis", "router eigrp", "ip route", "ipv6 route",
        "remote-as", "neighbor ", "address-family", "passive-interface", "exit-address-family",
    ),
    "services_policy": ("ip virtual-router address", "masquerade", "ip access-list", "ip helper-address", "set ip next-hop"),
}
# The browser is a pure DOM/Clipboard client: it never names a backend system.
FORBIDDEN_SYSTEM_REFERENCES = ("netbox", "pynetbox", "netmiko", "paramiko", "github", "git ", "ssh")


def function_body(source: str, name: str) -> str:
    marker = f"function {name}("
    start = source.index(marker)
    rest = source[start + len(marker):]
    next_function = rest.find("\n  function ")
    return rest[:next_function] if next_function >= 0 else rest


class DeviceBuilderJavaScriptContractTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = JS_PATH.read_text(encoding="utf-8")

    def test_typing_is_browser_local(self):
        typing = function_body(self.source, "handleFieldInput")
        self.assertNotIn("fetch(", typing)
        self.assertNotIn(".submit(", typing)
        self.assertNotIn("requestIpamPrefixes", typing)  # AUTO source change must not trigger a refresh
        self.assertIn("draftValue", typing)
        self.assertIn("renderPreviewFromDraft", typing)
        # generic over data-field-path: no namespace-specific branching or literals
        self.assertIn("data-field-path", self.source)
        self.assertNotIn('"routing.', self.source)
        self.assertNotIn('path.startsWith("routing', self.source)
        self.assertNotIn("path.startsWith('routing", self.source)
        # draft/accepted are separate, with explicit status labels and dirty-navigation protection
        for token in ("draftValue", "acceptedValue", "DRAFT / UNCOMMITTED", "INVALID / ROLLED BACK", "ACCEPTED",
                      "beforeunload", "hasDirty"):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_only_commit_ipam_refresh_and_collection_forms_reach_the_network(self):
        # Phase 20.5 added one more legitimate network call: collection-form
        # submission (Add/Remove Interface, Address, routing instance,
        # FHRP/NAT/ACL/PBR/DHCP object, ...), replacing a full-page POST with
        # fetch() so Basic/Advanced mode and the current selection survive.
        self.assertEqual(self.source.count("fetch("), 3)
        for name in ("commitField", "requestIpamPrefixes"):
            with self.subTest(function=name):
                body = function_body(self.source, name)
                self.assertIn("fetch(", body)
                self.assertIn('method: "POST"', body)
                self.assertIn("X-CSRFToken", body)
        # Collection forms carry their own {% csrf_token %} hidden field
        # inside the submitted FormData -- Django's CSRF check accepts that
        # in place of the X-CSRFToken header the JSON-body calls above use.
        collection = function_body(self.source, "handleCollectionFormSubmit")
        self.assertIn("fetch(", collection)
        self.assertIn('method: "POST"', collection)
        self.assertIn("new FormData(form)", collection)
        self.assertIn("credentials: \"same-origin\"", collection)

    def test_commit_gestures_are_explicit(self):
        single = function_body(self.source, "handleFieldKeydown")
        self.assertIn('event.key === "Enter"', single)
        self.assertIn("commitField(path)", single)
        self.assertIn("isMultiline", single)
        self.assertIn("event.ctrlKey || event.metaKey", single)
        self.assertIn("plain Enter inserts a newline", single)
        self.assertIn("data-commit-field", self.source)
        self.assertIn("commitField(", function_body(self.source, "handleCommitButtonClick"))

    def test_commit_reconciles_from_python_state(self):
        commit = function_body(self.source, "commitField")
        for token in ("setAuthoritativeCandidate", "updateNewInterfaceTypeChoices", "syncAddressSource"):
            with self.subTest(token=token):
                self.assertIn(token, commit)
        # a platform change reloads so capability-filtered selectors come from the server
        self.assertIn('path === "device.platform"', self.source)
        self.assertIn("window.location.reload()", self.source)
        # the preview is built from server-provided descriptors and header lines only
        preview = function_body(self.source, "renderPreviewFromDraft")
        self.assertIn("candidateDescriptors", preview)
        self.assertIn("lineTextFromDescriptor", preview)
        self.assertIn("candidate.descriptors", self.source)
        self.assertIn("candidate.header_lines", self.source)
        self.assertNotIn('"! Candidate Configuration"', self.source)

    def test_browser_is_never_a_second_vendor_renderer_or_backend_client(self):
        lowered = self.source.lower()
        for family, tokens in VENDOR_CLI_TOKENS.items():
            for token in tokens:
                with self.subTest(family=family, token=token):
                    self.assertNotIn(token, lowered)
        for token in FORBIDDEN_SYSTEM_REFERENCES:
            with self.subTest(reference=token):
                self.assertNotIn(token, lowered)

    def test_collection_forms_never_cause_a_full_page_reload_on_success(self):
        handler = function_body(self.source, "handleCollectionFormSubmit")
        self.assertIn("event.preventDefault()", handler)
        self.assertIn("root.innerHTML", handler)
        self.assertIn("history.replaceState", handler)
        self.assertIn("readBootstrap()", handler)
        self.assertIn("initializeView()", handler)
        self.assertIn(".catch(", handler)
        self.assertIn("form.submit()", handler)  # network-failure fallback only
        self.assertIn('root.addEventListener("submit", handleCollectionFormSubmit)', self.source)

    def test_copy_candidate_survives_a_collection_form_dom_swap(self):
        # A one-time querySelector+addEventListener on the copy button would
        # stop working once handleCollectionFormSubmit replaces root's DOM;
        # it must be reached through the same delegated click handler as
        # every other root-scoped control.
        self.assertNotIn("var copyButton = root.querySelector", self.source)
        click_handler = function_body(self.source, "handleCommitButtonClick")
        self.assertIn("data-copy-candidate", click_handler)
        self.assertIn("copyCandidate()", click_handler)

    def test_copy_candidate_is_client_side(self):
        self.assertIn("navigator.clipboard.writeText", self.source)
        self.assertIn('execCommand("copy")', self.source)
