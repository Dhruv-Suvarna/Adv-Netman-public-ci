"""The portable template package: ONE deterministic YAML document (no archive, so no member paths to traverse).

    kind: nmas-configuration-template
    schema_version: 1
    manifest:       template_id, name, family, origin, description, version, created_by, created_at, digest (sha256)
    compatibility:  platforms, required_features, constraints
    provenance:     source devices, running-config digests, extraction time, repository HEAD, derivation
    parameters / parameter_sets / intent / exclusions / notes
    rendering:      engine + the project-owned Jinja2 feature templates the intent renders through (REFERENCES only)

``content_digest`` covers everything that defines the template's meaning; the same version always exports the same
bytes.  ``load`` validates untrusted input completely before anything is stored: size, YAML safety (no aliases / tags),
kind, schema version, structure, placeholder integrity, secret scan, template-reference safety and the digest.
"""

from __future__ import annotations

import re

import yaml

from ..bundles import canonical
from . import schema, secret_scan

KIND = "nmas-configuration-template"
MAX_PACKAGE_BYTES = 1024 * 1024
FILE_SUFFIX = ".nmas-template.yaml"
_DIGEST_DOMAIN = "nmas-template-v1"
_TEMPLATE_ID_RE = re.compile(r"^TPL-[A-Z0-9][A-Z0-9-]{3,35}$")
_TEMPLATE_REF_RE = re.compile(r"^[a-z0-9_]+/[a-z0-9_]+\.j2$")
_CONTENT_KEYS = ("family", "intent", "parameters", "parameter_sets", "platforms", "required_features", "constraints",
                 "provenance", "exclusions", "notes")


class PackageError(ValueError):
    """A rejected package.  ``code`` is stable; ``problems`` are operator-facing and never contain a secret value."""

    def __init__(self, code: str, problems):
        self.code = code
        self.problems = [str(p) for p in ([problems] if isinstance(problems, str) else problems)]
        super().__init__(f"{code}: {'; '.join(self.problems)}")


def content_digest(content: dict) -> str:
    """SHA-256 over the canonical JSON of the meaning-bearing content (domain-separated, schema-versioned)."""
    body = {key: content.get(key) for key in _CONTENT_KEYS}
    return canonical.text_hash(canonical.canonical_json(
        {"domain": _DIGEST_DOMAIN, "schema_version": int(content.get("schema_version") or schema.SCHEMA_VERSION), "content": body}))


def version_content(version) -> dict:
    return {
        "schema_version": version.schema_version, "family": str(version.template.family), "intent": version.intent,
        "parameters": version.parameters, "parameter_sets": version.parameter_sets, "platforms": version.platforms,
        "required_features": version.required_features, "constraints": version.constraints, "provenance": version.provenance,
        "exclusions": version.exclusions, "notes": version.notes,
    }


def build_document(version, *, feature_templates: list[str]) -> dict:
    template = version.template
    return {
        "kind": KIND, "schema_version": version.schema_version,
        "manifest": {
            "template_id": template.template_id, "name": template.name, "family": str(template.family), "origin": str(template.origin),
            "description": template.description, "version": version.version, "created_by": version.created_by,
            "created_at": version.created_at.isoformat() if version.created_at else "",
            "digest_algorithm": "sha256", "digest": version.digest,
        },
        "compatibility": {"platforms": version.platforms, "required_features": version.required_features, "constraints": version.constraints},
        "provenance": version.provenance, "parameters": version.parameters, "parameter_sets": version.parameter_sets,
        "intent": version.intent, "exclusions": version.exclusions, "notes": version.notes,
        "rendering": {"engine": "jinja2", "pipeline": "template intent -> Device Builder semantic candidate -> platform feature templates",
                      "feature_templates": sorted(feature_templates)},
    }


def dump(document: dict) -> bytes:
    """Deterministic bytes: sorted keys, block style, no aliases."""
    class _NoAlias(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    return yaml.dump(document, Dumper=_NoAlias, sort_keys=True, default_flow_style=False, allow_unicode=False, width=120).encode("utf-8")


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that additionally refuses aliases (expansion bombs); SafeLoader already refuses arbitrary tags."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("aliases are not allowed in a template package")
        return super().compose_node(parent, index)


def _require(mapping, key, kind, problems, where):
    value = mapping.get(key) if isinstance(mapping, dict) else None
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        problems.append(f"{where}.{key} is missing or has the wrong type.")
        return kind()
    return value


def load(data: bytes) -> dict:
    """Validate an UNTRUSTED package.  -> normalized {"manifest", "content", "digest", "feature_templates"} or PackageError."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise PackageError("EMPTY_PACKAGE", "The package is empty.")
    if len(data) > MAX_PACKAGE_BYTES:
        raise PackageError("PACKAGE_TOO_LARGE", f"The package exceeds {MAX_PACKAGE_BYTES} bytes.")
    try:
        text = bytes(data).decode("utf-8")
        document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - _StrictLoader is a SafeLoader subclass
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError):
        raise PackageError("MALFORMED_PACKAGE", "The package is not valid UTF-8 YAML (aliases and custom tags are not allowed).") from None
    if not isinstance(document, dict) or document.get("kind") != KIND:
        raise PackageError("NOT_A_TEMPLATE_PACKAGE", f"The document is not a {KIND!r} package.")
    version_number = document.get("schema_version")
    if not isinstance(version_number, int) or isinstance(version_number, bool) or version_number not in schema.SUPPORTED_SCHEMA_VERSIONS:
        raise PackageError("UNSUPPORTED_SCHEMA_VERSION",
                           f"Schema version {str(version_number)[:20]!r} is not supported (supported: {sorted(schema.SUPPORTED_SCHEMA_VERSIONS)}).")
    problems: list[str] = []
    unknown = set(document) - {"kind", "schema_version", "manifest", "compatibility", "provenance", "parameters", "parameter_sets",
                               "intent", "exclusions", "notes", "rendering"}
    if unknown:
        problems.append(f"Unknown top-level key(s): {sorted(str(k)[:40] for k in unknown)}.")
    manifest = _require(document, "manifest", dict, problems, "package")
    compatibility = _require(document, "compatibility", dict, problems, "package")
    template_id = _require(manifest, "template_id", str, problems, "manifest")
    name = _require(manifest, "name", str, problems, "manifest")
    family = _require(manifest, "family", str, problems, "manifest")
    version = _require(manifest, "version", int, problems, "manifest")
    digest = _require(manifest, "digest", str, problems, "manifest")
    if template_id and not _TEMPLATE_ID_RE.match(template_id):
        problems.append("manifest.template_id is not a valid template identifier.")
    if name and (len(name) > 120 or re.search(r"[\x00-\x1f<>]", name)):
        problems.append("manifest.name is invalid.")
    if isinstance(version, int) and not 1 <= version <= 100000:
        problems.append("manifest.version is out of range.")
    if manifest.get("digest_algorithm") != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        problems.append("manifest.digest must be a sha256 hex digest.")
    content = {
        "schema_version": version_number, "family": family, "intent": document.get("intent"),
        "parameters": document.get("parameters") or {}, "parameter_sets": document.get("parameter_sets") or {},
        "platforms": compatibility.get("platforms") or [], "required_features": compatibility.get("required_features") or [],
        "constraints": compatibility.get("constraints") or {}, "provenance": document.get("provenance") or {},
        "exclusions": document.get("exclusions") or [], "notes": document.get("notes") or "",
    }
    for key, kind in (("parameter_sets", dict), ("platforms", list), ("required_features", list), ("constraints", dict),
                      ("provenance", dict), ("exclusions", list), ("notes", str)):
        if not isinstance(content[key], kind):
            problems.append(f"{key} has the wrong type.")
    if not all(isinstance(p, str) and re.fullmatch(r"[a-z0-9_]{1,32}", p) for p in content["platforms"] if isinstance(content["platforms"], list)):
        problems.append("compatibility.platforms contains an invalid platform identifier.")
    problems.extend(schema.validate_intent(content["intent"], content["parameters"]))
    references = (document.get("rendering") or {}).get("feature_templates") or [] if isinstance(document.get("rendering") or {}, dict) else None
    if not isinstance(references, list):
        problems.append("rendering.feature_templates must be a list.")
        references = []
    for reference in references:
        if not isinstance(reference, str) or ".." in reference or reference.startswith(("/", "\\")) or not _TEMPLATE_REF_RE.match(reference):
            raise PackageError("UNSAFE_TEMPLATE_REFERENCE", "rendering.feature_templates contains an unsafe path (only '<platform>/<name>.j2' is allowed).")
    if problems:
        raise PackageError("INVALID_PACKAGE", problems[:25])
    findings = secret_scan.scan({k: content[k] for k in ("intent", "parameters", "parameter_sets", "constraints", "exclusions", "notes")})
    findings += secret_scan.scan({"manifest": {k: v for k, v in manifest.items() if k != "digest"}, "provenance": _without_digests(content["provenance"])})
    if findings:
        raise PackageError("SECRET_MATERIAL_REFUSED", [f"{f['path']}: {f['pattern']}" for f in findings[:25]])
    if content_digest(content) != digest:
        raise PackageError("DIGEST_MISMATCH", "The package content does not match its manifest digest (altered or corrupted).")
    return {"manifest": {"template_id": template_id, "name": name, "family": family, "version": version,
                         "origin": str(manifest.get("origin") or "")[:16], "description": str(manifest.get("description") or "")[:2000],
                         "created_by": str(manifest.get("created_by") or "")[:150], "created_at": str(manifest.get("created_at") or "")[:40]},
            "content": content, "digest": digest, "feature_templates": references,
            "package_sha256": canonical.text_hash(text)}


def _without_digests(value):
    """Provenance legitimately carries SHA-256 digests / commit ids; they are not secrets and are excluded from the value scan."""
    if isinstance(value, dict):
        return {k: _without_digests(v) for k, v in value.items()
                if not (isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", v))}
    if isinstance(value, list):
        return [_without_digests(v) for v in value]
    return value
