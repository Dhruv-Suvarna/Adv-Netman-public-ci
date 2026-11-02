# Human MFA central AAA bundle (isolated from device rollout)

This directory is an isolated deployment source. It is not included in the
normal monitoring compose project. Runtime deployment/validation, when
authorized, uses ignored material under `monitoring/runtime/human-mfa/`; it
does not by itself authorize any network-device AAA change.

The selected backend is FreeRADIUS 3 plus privacyIDEA 3.13.4. FreeRADIUS is the
EOS-facing RADIUS server. Its `rlm_rest` module sends the single SSH password
field to privacyIDEA's `/validate/radiuscheck` endpoint. Human input is the
memorized password immediately followed by a six-digit RFC 6238 TOTP.
privacyIDEA policy `otppin=userstore` independently checks both portions.

Why `rlm_rest`: this design needs a one-shot password+TOTP decision, not an
Access-Challenge. The known `rlm_rest` limitations (no RADIUS challenge/response
or privacyIDEA attribute mapping) therefore do not affect authentication.
FreeRADIUS adds the EOS role VSA only after privacyIDEA returns success.

The privacyIDEA source/deployment is not copied into this repository. The later
rollout must use the upstream Docker deployment at immutable commit
`9688ada43e30b7c97b126f460aa75b92315e1dd8` (release v3.13.4), attach its TLS
endpoint to external Docker network `nmas-human-mfa-backend`, then build this
FreeRADIUS image. This keeps upstream security code upstream while pinning the
reviewed source.

For FreeRADIUS 3.2.1 the REST module must use `ca_info_file` for the private CA
trust bundle. `ca_file` maps to libcurl's issuer-certificate option and does not
establish trust. Both `check_cert` and `check_cert_cn` remain enabled.

The pinned privacyIDEA frontend lockfile's npm findings, including exact
build-time versus runtime applicability, are recorded in
`docs/PHASE_24_R1_PILOT_REMEDIATION.md`. They must be reviewed when rebuilding;
they are not dismissed merely because their critical paths are dev dependencies.

Runtime-only inputs belong below `monitoring/runtime/human-mfa/`:

- privacyIDEA database, encryption key, pepper, Flask key and audit keys;
- the human password user store and encrypted TOTP token seeds;
- TLS private keys and the trusted privacyIDEA CA;
- per-device RADIUS shared secrets in `freeradius/clients.conf`;
- backup/recovery material.

`render_radius_clients.py` builds the ignored `freeradius/clients.conf` for
only the explicitly selected, approved cEOS and R3/R4 devices, while always
preserving the protected localhost fixture client. Device names are the only argv
values; each unique shared secret is read from
`secrets/radius_<device>_secret` (and `radius_fixture_secret`), retained in process memory, and atomically
written to a mode-0600 file. Add the next device only as part of that device's
approved one-at-a-time migration; do not pre-authorize the whole fleet.

The tracked `clients.conf.example` contains deliberately fake values. Do not
place passwords, seeds, OTPs, shared secrets, QR images or recovery codes in
Git, command arguments, logs or JSON evidence.

No command in this directory is a live rollout instruction. See
`docs/PHASE_24_HUMAN_2FA_MICROSOFT_AUTHENTICATOR.md` for gates and rollback.
