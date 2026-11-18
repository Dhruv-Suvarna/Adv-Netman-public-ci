"""No-network tests for the pinned public-document research broker."""

import socket
from unittest import mock

from django.test import SimpleTestCase

from core.services.troubleshooting.research import ResearchBroker, ResearchRefused


class FakeTransport:
    def __init__(self, responses=None):
        self.responses = list(responses or [(200, {"content-type": "text/plain"}, b"vendor documentation")])
        self.calls = []

    def request(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


class ResearchBrokerTests(SimpleTestCase):
    def broker(self, *, answers=("93.184.216.34",), transport=None, audit=None):
        return ResearchBroker(allowed_destinations={"docs.vendor.example": ("93.184.216.34",),
                                                    "www.rfc-editor.org": ("104.18.20.81",)},
                              resolver=lambda _host: answers, transport=transport or FakeTransport(), audit=audit)

    def denied(self, code, url, *, answers=("93.184.216.34",), transport=None):
        with self.assertRaises(ResearchRefused) as caught:
            self.broker(answers=answers, transport=transport).fetch(url, purpose="diagnose protocol behavior", principal="agent-1")
        self.assertEqual(caught.exception.code, code)

    def test_approved_public_document_is_bounded_and_labelled_untrusted(self):
        transport = FakeTransport()
        result = self.broker(transport=transport).fetch("https://docs.vendor.example/guide?q=ospf",
                                                        purpose="diagnose OSPF adjacency", principal="agent-1")
        self.assertTrue(result.untrusted_external_content)
        self.assertEqual(result.body, "vendor documentation")
        self.assertEqual(transport.calls[0]["ip"], "93.184.216.34")
        self.assertEqual(transport.calls[0]["max_bytes"], 262_144)

    def test_http_ip_literal_unlisted_host_userinfo_and_nonstandard_port_are_denied(self):
        for url in ("http://docs.vendor.example/", "https://93.184.216.34/", "https://evil.example/",
                    "https://user:pass@docs.vendor.example/", "https://docs.vendor.example:8443/"):
            self.denied("DESTINATION_REFUSED" if "user:pass" not in url else "INVALID_URL", url)

    def test_private_loopback_link_local_metadata_and_ipv6_ula_are_denied(self):
        for address in ("10.0.0.4", "127.0.0.1", "169.254.169.254", "192.168.200.6", "fc00::5", "fe80::1"):
            self.denied("NON_PUBLIC_DESTINATION", "https://docs.vendor.example/", answers=(address,))

    def test_ipv4_mapped_ipv6_bypass_is_denied(self):
        self.denied("NON_PUBLIC_DESTINATION", "https://docs.vendor.example/", answers=("::ffff:127.0.0.1",))

    def test_dns_reresolution_change_is_denied_before_transport(self):
        answers = iter((("93.184.216.34",), ("127.0.0.1",)))
        broker = ResearchBroker(allowed_destinations={"docs.vendor.example": ("93.184.216.34",)},
                                resolver=lambda _host: next(answers),
                                transport=FakeTransport())
        with self.assertRaises(ResearchRefused) as caught:
            broker.fetch("https://docs.vendor.example/", purpose="diagnose protocol behavior", principal="agent-1")
        self.assertEqual(caught.exception.code, "DNS_CHANGED")

    def test_public_but_unreviewed_dns_answer_is_denied_before_transport(self):
        self.denied("DNS_ADDRESS_NOT_APPROVED", "https://docs.vendor.example/", answers=("93.184.216.35",))

    def test_system_resolution_queries_only_reviewed_address_families(self):
        answer = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        with mock.patch("core.services.troubleshooting.research.socket.getaddrinfo", return_value=[answer]) as resolver:
            broker = ResearchBroker(allowed_destinations={"docs.vendor.example": ("93.184.216.34",)},
                                    transport=FakeTransport())
            self.assertEqual(broker._pin("docs.vendor.example"), "93.184.216.34")
        self.assertEqual(resolver.call_count, 2)
        self.assertTrue(all(call.kwargs["family"] == socket.AF_INET for call in resolver.call_args_list))

    def test_redirect_is_reauthorized_and_private_or_unlisted_redirect_is_denied(self):
        transport = FakeTransport([(302, {"location": "https://evil.example/private"}, b"")])
        self.denied("DESTINATION_REFUSED", "https://docs.vendor.example/", transport=transport)

    def test_credential_like_query_and_write_methods_are_denied(self):
        self.denied("CREDENTIAL_MATERIAL_REFUSED", "https://docs.vendor.example/?api_token=secret")
        with self.assertRaises(ResearchRefused) as caught:
            self.broker().fetch("https://docs.vendor.example/", purpose="diagnose protocol behavior",
                                principal="agent-1", method="POST")
        self.assertEqual(caught.exception.code, "METHOD_REFUSED")

    def test_binary_and_oversized_documents_are_denied(self):
        self.denied("CONTENT_TYPE_REFUSED", "https://docs.vendor.example/",
                    transport=FakeTransport([(200, {"content-type": "application/octet-stream"}, b"binary")]))
        self.denied("RESPONSE_TOO_LARGE", "https://docs.vendor.example/",
                    transport=FakeTransport([(200, {"content-type": "text/plain", "content-length": "999999"}, b"")]))
        self.denied("EXECUTABLE_CONTENT_REFUSED", "https://docs.vendor.example/",
                    transport=FakeTransport([(200, {"content-type": "text/x-shellscript"}, b"#!/bin/sh")]))
        self.denied("EXECUTABLE_CONTENT_REFUSED", "https://docs.vendor.example/",
                    transport=FakeTransport([(200, {"content-type": "text/plain", "content-disposition": "attachment; filename=x"}, b"data")]))

    def test_audit_omits_query_and_content(self):
        events = []
        self.broker(audit=events.append).fetch("https://docs.vendor.example/guide?q=bgp",
                                               purpose="diagnose BGP behavior", principal="agent-1")
        self.assertNotIn("?", events[0]["destination"])
        self.assertNotIn("vendor documentation", str(events[0]))
