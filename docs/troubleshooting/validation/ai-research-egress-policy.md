# AI research egress policy

## Purpose and separation

Troubleshooter agents may retrieve public vendor documentation, RFCs, protocol specifications, public software documentation and known-issue material as evidence. Research is not a device-management transport, does not confer target authority, and cannot execute or install what it retrieves.

Model-provider, Slack and AI gateway traffic remains on the existing orchestration/provider broker. Those endpoints are not automatically research destinations and never managed devices.

## Application broker

Implementation: `web/core/services/troubleshooting/research.py`; AI entry point: `research_public_document` in `ai.py`.

The broker enforces:

- operator-curated exact hostname-to-literal-address mapping; empty by default;
- HTTPS only, destination port 443 only, methods GET and HEAD only;
- no IP-literal URL, URL user information or fragment;
- no Authorization/Cookie input and no request body/API that can upload lab data;
- rejection of credential-like query parameter names;
- two DNS resolutions immediately before connection; both complete answer sets must be identical and every answer must belong to the reviewed address set for that hostname;
- rejection if any answer is non-global, private, loopback, link-local, shared, reserved/test, multicast, ULA, IPv4-mapped IPv6, NAT64 well-known, 6to4 or other explicitly blocked space;
- connection to the validated pinned IP literal while TLS verifies the original hostname with SNI;
- complete hostname/DNS/address policy replay on each redirect, with at most three redirects by default;
- no proxy environment processing;
- 2-30 second configurable timeout (8 seconds default), maximum response size (256 KiB default, hard ceiling 2 MiB), textual media types only and identity encoding;
- sanitized audit containing principal, bounded purpose, scheme/host/path, decision/result; query, content and credentials are omitted;
- returned `untrusted_external_content=true`, content SHA-256 and byte count.

The AI tool remains subject to handoff registration, nonce/idempotency, total byte/call/time budgets and audit. An external page stating “ignore policy,” naming a command, asking for Docker/SSH, or claiming approval is data only; it cannot add tools, targets, permissions or approvals.

## Kernel/network boundary (staged)

`deploy/sandbox/nmas-research-broker.service.in` runs the future broker under a dedicated `nmas-research` UID with no capabilities, home access, device access, writeable system, mount/module/reboot or broad syscall authority.

`deploy/sandbox/research-egress.nft.in` is intended for `/run/netns/nmas-ts-research` only—not the VM-wide firewall. It:

- defaults output to drop;
- permits loopback and established/related flows;
- permits UDP/TCP 53 only to explicitly reviewed resolver addresses;
- drops private, loopback, link-local, shared, documentation/test, multicast/reserved IPv4 ranges;
- drops unspecified, loopback, IPv4-mapped, NAT64 well-known, discard, documentation, ORCHID, 6to4, ULA, link-local and multicast IPv6 ranges;
- permits TCP/443 only to the exact reviewed literal destination tuples; all other public addresses are denied.

The application hostname/pinning layer and namespace address layer are intentionally independent. Neither is sufficient alone if the worker has shell, root or Docker access.

## Privacy/data handling

- The tool accepts only URL and troubleshooting purpose. There is no POST/upload method.
- URLs with credential-like parameters are rejected; audit removes all query strings.
- Retrieved content stays in bounded tool results/checkpoints and undergoes existing NMAS redaction and total handoff byte caps.
- Agents must not embed configurations, credentials, inventory exports, customer data or lab evidence in public URLs.
- Downloads are never written, imported, sourced, executed or passed to a shell.

## Tests

`test_troubleshooting_research.py` covers allowed public textual retrieval, private/loopback/link-local/metadata/ULA denial, IPv4-mapped bypass, DNS re-resolution change, unlisted redirect, IP literal, userinfo, nonstandard port, credential query, write method, binary/oversize response and sanitized audit.

`test_troubleshooting_ai.py` covers unavailable-by-default behavior and a prompt-injected external document that cannot create a remediation, execution or authorization.

`test_troubleshooting_sandbox_artifacts.py` asserts dual-stack namespace blocks and exact service restrictions without touching the live firewall.

No real unauthorized destination was contacted. The allowed-fetch test uses an injected fake resolver/transport. Live public-document validation belongs in the separately approved research-namespace activation window.

## Activation requirements

1. University/operator approve exact resolver addresses and hostname-to-address mapping.
2. Create dedicated unprivileged UID, root-owned configuration and audit directory.
3. Create isolated namespace and load the rendered namespace-only nft rules.
4. Validate DNS, public HTTPS, redirect and IPv4/IPv6 denial fixtures inside the namespace.
5. Confirm Slack/model/gateway paths remain on their existing broker and are not routed through this worker.
6. Enable `NMAS_TS_RESEARCH_ALLOWED_DESTINATIONS` only after the namespace policy is active.

Until those steps, research code is implemented and testable but production research remains unavailable; ordinary existing internet/model workflows are not blocked or rerouted.

## Standalone worker revision

Research now runs only through `research_worker.py` on its own authenticated Unix socket. The AI runtime has no in-process HTTP fallback. The worker does not initialize Django or mount the production DB, inventory, device credentials or diagnostic state. Requests are peer-UID checked, HMAC authenticated, expiring and replay protected; responses are signed.

The broker connects to the validated reviewed IP literal while retaining TLS hostname verification, repeats DNS resolution, reauthorizes redirects, ignores proxy variables, permits GET/HEAD and a small documentation MIME set, and refuses attachments/executable types. Namespace and host nftables permit reviewed DNS on 53 and only reviewed `address . 443` tuples after explicit dual-stack private/reserved/mapped drops. Namespace activation creates an exact namespace-specific `resolv.conf` and rollback removes it.

Disposable namespace tests proved public-shaped IPv4/IPv6 port 443 allowed and RFC1918/ULA peers denied. Live retrieval is deliberately deferred to activation. Slack/model connectivity remains Zone 5 and confers no research or device authority.
