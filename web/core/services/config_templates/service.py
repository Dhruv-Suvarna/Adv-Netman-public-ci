"""Template library operations: extract, version, publish, export, import, retire.  (Cloning lives in ``clone``.)

Everything that reads a device goes through the ONE existing read-only capture (``config_workbench.snapshots``); nothing
here sends configuration anywhere.  Every operation writes an AuditEvent (the authenticated website user is attached by
the Phase 1 request context) whose metadata names identifiers and digests only -- never intent values.
"""

from __future__ import annotations

import json
import uuid

from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from .. import nsot_git
from ..capabilities import evidence as capability_evidence
from ..config_import import parser_ceos, parser_frr
from ..config_workbench import snapshots
from . import features, normalize, package, schema, secret_scan, working_intent

LIVE_EXTRACTION_PLATFORMS = (models.Platform.ARISTA_CEOS, models.Platform.UBUNTU_FRR)
_PARSER_VERSIONS = {models.Platform.ARISTA_CEOS: parser_ceos.PARSER_VERSION, models.Platform.UBUNTU_FRR: parser_frr.PARSER_VERSION}
MAX_VERSION_RETRIES = 10


class TemplateError(ValueError):
    """An operator-facing refusal.  ``code`` is stable; ``problems`` never contain a secret value."""

    def __init__(self, code: str, problems):
        self.code = code
        self.problems = [str(p) for p in ([problems] if isinstance(problems, str) else problems)]
        super().__init__(f"{code}: {'; '.join(self.problems)}")


def _audit(event_type, summary, *, actor="", template=None, version=None, change=None, metadata=None):
    target = version or template
    models.AuditEvent.objects.create(
        event_type=event_type, change=change, actor=actor[:150], summary=summary[:255],
        object_type=type(target).__name__ if target is not None else "ConfigurationTemplate",
        object_id=(version.ref if version is not None else getattr(template, "template_id", ""))[:64],
        metadata=metadata or {},
    )


def repository_head() -> str:
    state = nsot_git.get_repo_state()
    return str(state.get("head_commit") or "") if state.get("status") == "available" else ""


def new_template_id() -> str:
    return f"TPL-{uuid.uuid4().hex[:12].upper()}"


# --- reading -----------------------------------------------------------------------------------------------------------
def list_templates(*, family: str = "", platform: str = "", origin: str = "", query: str = "", include_retired: bool = False):
    """Library rows: [{"template", "latest" (newest version of any status), "published" (newest published)}]."""
    queryset = models.ConfigurationTemplate.objects.prefetch_related("versions")
    if family:
        queryset = queryset.filter(family=family)
    if origin:
        queryset = queryset.filter(origin=origin)
    if query:
        queryset = queryset.filter(name__icontains=query[:80])
    if not include_retired:
        queryset = queryset.filter(retired_at__isnull=True)
    rows = []
    for template in queryset:
        versions = sorted(template.versions.all(), key=lambda v: -v.version)
        if not versions:
            continue
        published = next((v for v in versions if v.is_published), None)
        shown = published or versions[0]
        if platform and platform not in (shown.platforms or []):
            continue
        rows.append({"template": template, "latest": versions[0], "published": published, "shown": shown, "version_count": len(versions)})
    return rows


def get_template(template_id: str):
    return models.ConfigurationTemplate.objects.filter(template_id=template_id).first()


def get_version(template_id: str, version: int):
    return models.ConfigurationTemplateVersion.objects.select_related("template").filter(
        template__template_id=template_id, version=version).first()


# --- creating versions -------------------------------------------------------------------------------------------------
def build_content(*, family: str, intent: dict, parameters: dict, parameter_sets: dict | None = None, provenance: dict | None = None,
                  exclusions: list | None = None, notes: str = "", constraints: dict | None = None, platforms: list | None = None) -> dict:
    required = features.required_features(intent)
    constraints = dict(constraints or {})
    if platforms is None:
        platforms = [] if constraints.get("deployable") is False else features.supported_platforms(required)
    return {"schema_version": schema.SCHEMA_VERSION, "family": str(getattr(family, "value", family)), "intent": intent, "parameters": parameters,
            "parameter_sets": parameter_sets or {}, "platforms": sorted(platforms), "required_features": required,
            "constraints": constraints, "provenance": provenance or {}, "exclusions": exclusions or [], "notes": notes}


def create_template(*, name: str, family: str, origin: str, description: str = "", actor: str = "", template_id: str = "", metadata=None):
    family, origin = str(getattr(family, "value", family)), str(getattr(origin, "value", origin))    # plain strings: YAML-safe
    if family not in models.TemplateFamily.values or origin not in models.TemplateOrigin.values:
        raise TemplateError("INVALID_TEMPLATE", "Unknown template family or origin.")
    name = (name or "").strip()[:120]
    if not name:
        raise TemplateError("INVALID_TEMPLATE", "A template name is required.")
    template = models.ConfigurationTemplate.objects.create(
        template_id=template_id or new_template_id(), name=name, family=family, origin=origin, description=description[:2000],
        created_by=actor[:150], metadata=metadata or {})
    _audit(models.AuditEventType.TEMPLATE_CREATED, f"Template {template.template_id} created ({family})", actor=actor, template=template,
           metadata={"template_id": template.template_id, "family": family, "origin": origin})
    return template


def create_version(template, content: dict, *, actor: str = "", source_version=None, version_number: int | None = None):
    """Append a DRAFT version (content is frozen from here on: a draft can only be published or discarded)."""
    content = json.loads(json.dumps(content))      # plain JSON / YAML-safe data only (e.g. TextChoices members become strings)
    digest = package.content_digest(content)
    for _ in range(MAX_VERSION_RETRIES):
        number = version_number or ((template.versions.order_by("-version").values_list("version", flat=True).first() or 0) + 1)
        try:
            with transaction.atomic():
                version = models.ConfigurationTemplateVersion.objects.create(
                    template=template, version=number, schema_version=content["schema_version"], intent=content["intent"],
                    parameters=content["parameters"], parameter_sets=content["parameter_sets"], platforms=content["platforms"],
                    required_features=content["required_features"], constraints=content["constraints"], provenance=content["provenance"],
                    exclusions=content["exclusions"], notes=content["notes"], digest=digest, created_by=actor[:150], source_version=source_version)
        except IntegrityError:
            if version_number:
                raise TemplateError("VERSION_EXISTS", f"Version {version_number} already exists.") from None
            continue
        _audit(models.AuditEventType.TEMPLATE_VERSION_CREATED, f"Template {version.ref} created as a draft", actor=actor, version=version,
               metadata={"template_id": template.template_id, "version": number, "digest": digest})
        return version
    raise TemplateError("VERSION_ALLOCATION_FAILED", "Could not allocate a version number.")


def publication_problems(version) -> list[str]:
    """Everything that must hold before a version becomes an immutable, exportable, clonable artifact."""
    content = package.version_content(version)
    problems = list(schema.validate_intent(version.intent, version.parameters))
    problems += [f"Secret-shaped content at {f['path']} ({f['pattern']})." for f in secret_scan.scan(
        {k: content[k] for k in ("intent", "parameters", "parameter_sets", "constraints", "exclusions", "notes")})]
    problems += [f"Unknown capability feature {key!r}." for key in features.unknown_features(version.required_features)]
    if sorted(version.required_features) != features.required_features(version.intent if isinstance(version.intent, dict) else {}):
        problems.append("required_features does not match the intent.")
    deployable = (version.constraints or {}).get("deployable") is not False
    if deployable and not version.platforms:
        problems.append("No platform can render every required feature of this intent.")
    for platform in version.platforms or []:
        if platform not in models.Platform.values:
            problems.append(f"Unknown platform {str(platform)[:32]!r}.")
            continue
        gaps = features.platform_gaps(version.required_features, platform)
        if gaps:
            problems.append(f"Platform {platform} cannot render: {', '.join(gaps)}.")
    if not problems:
        for name, values in sorted((version.parameter_sets or {}).items()):
            _intent, _values, set_problems = schema.resolve(version.intent, version.parameters, values)
            problems += [f"Parameter set {name}: {p}" for p in set_problems]
    if package.content_digest(content) != version.digest:
        problems.append("The stored digest does not match the content.")
    return problems


def publish(version, *, actor: str = ""):
    if version.is_published:
        return version
    problems = publication_problems(version)
    if problems:
        raise TemplateError("PUBLICATION_REFUSED", problems[:25])
    version.status = models.TemplateVersionStatus.PUBLISHED
    version.published_by = actor[:150]
    version.published_at = timezone.now()
    version.save()
    _audit(models.AuditEventType.TEMPLATE_PUBLISHED, f"Template {version.ref} published (immutable)", actor=actor, version=version,
           metadata={"template_id": version.template.template_id, "version": version.version, "digest": version.digest})
    return version


def discard_draft(version, *, actor: str = "") -> None:
    if version.is_published:
        raise TemplateError("IMMUTABLE_VERSION", "A published template version cannot be discarded.")
    template, ref = version.template, version.ref
    with transaction.atomic():
        version.delete()
        _audit(models.AuditEventType.TEMPLATE_DRAFT_DISCARDED, f"Template draft {ref} discarded", actor=actor, template=template,
               metadata={"template_id": template.template_id, "ref": ref})
        if not template.versions.exists():
            template.delete()


def retire(template, *, actor: str = ""):
    """Retirement hides a template from new use; every version stays (immutable history)."""
    if template.retired_at:
        return template
    template.retired_at, template.retired_by = timezone.now(), actor[:150]
    template.save(update_fields=["retired_at", "retired_by"])
    _audit(models.AuditEventType.TEMPLATE_RETIRED, f"Template {template.template_id} retired; versions retained", actor=actor, template=template,
           metadata={"template_id": template.template_id})
    return template


# --- extraction --------------------------------------------------------------------------------------------------------
def parse_capture(platform: str, sections: dict):
    """Sanitized capture sections -> importer records.  ``sections``: {command_key: sanitized text}."""
    if platform == models.Platform.ARISTA_CEOS:
        return parser_ceos.parse(sections.get("running_config", ""))
    if platform == models.Platform.UBUNTU_FRR:
        return parser_frr.parse(sections.get("frr_config", ""), addr_json=sections.get("addr", ""), nft_text=sections.get("nft", ""))
    raise TemplateError("UNSUPPORTED_PLATFORM", f"Template extraction is not available for platform {platform!r} (cEOS and Ubuntu/FRR only).")


def snapshot_sections(snapshot) -> dict:
    return {snapshots.PRIMARY_SECTION[key]: snapshot.text for key, value in snapshots.PLATFORMS.items() if value == snapshot.platform}


def device_intent(snapshot, sections: dict | None = None) -> tuple[dict, list[dict], dict]:
    """One captured device -> (cleaned intent, exclusions, provenance source row).  Pure given the capture."""
    sections = sections or snapshot_sections(snapshot)
    intent, exclusions = schema.from_parsed(parse_capture(snapshot.platform, sections))
    intent, more = normalize.clean(intent, snapshot.platform)
    partial = snapshot.platform == models.Platform.UBUNTU_FRR and "addr" not in sections
    source = {"device": snapshot.device_name, "platform": snapshot.platform, "snapshot_id": str(snapshot.snapshot_id),
              "running_config_digest": snapshot.digest, "captured_at": snapshot.captured_at.isoformat(), "transport": snapshot.source,
              "parser_version": _PARSER_VERSIONS.get(snapshot.platform, ""), "redacted_lines": snapshot.redacted_lines}
    if partial:
        source["note"] = "Stored snapshot only: Linux interface addresses and NAT rules need a live capture."
    return intent, [{**e, "device": snapshot.device_name} for e in exclusions + more], source


def extraction_content(captures: list[tuple], *, family: str, method: str, notes: str = "", constraints=None) -> dict:
    """[(snapshot, sections|None)] of ONE role -> template content (intent generalized over the sources)."""
    per_device, exclusions, sources = {}, [], []
    for snapshot, sections in captures:
        intent, excluded, source = device_intent(snapshot, sections)
        per_device[snapshot.device_name] = intent
        exclusions += excluded
        sources.append(source)
    generalized = normalize.generalize(per_device)
    provenance = {"method": method, "source_devices": [s["device"] for s in sources], "sources": sources,
                  "platforms": sorted({s["platform"] for s in sources}), "extracted_at": max(s["captured_at"] for s in sources),
                  "repository_head": repository_head(), "differences": generalized["differences"]}
    return build_content(family=family, intent=generalized["intent"], parameters=generalized["parameters"],
                         parameter_sets=generalized["parameter_sets"], provenance=provenance, exclusions=exclusions, notes=notes,
                         constraints=constraints)


def _record_extraction_evidence(version, *, actor: str, live: bool) -> None:
    axes = ("PARSER_IMPORT", "LIVE_READ") if live else ("PARSER_IMPORT",)
    for platform in (version.provenance or {}).get("platforms", []):
        for feature in version.required_features:
            for axis in axes:
                capability_evidence.record_evidence(
                    platform=platform, feature=feature, axis=axis, status="VERIFIED", source="template-extraction",
                    detail=f"Extracted into template intent from {', '.join((version.provenance or {}).get('source_devices', []))}.",
                    evidence_ref=version.ref, recorded_by=actor, evidence_type="LIVE" if live else "FIXTURE")


def extract_from_device(device_name: str, *, actor: str = "", name: str = "", family: str = models.TemplateFamily.CUSTOM,
                        session_factory=None, now=None):
    """Operator pull: ONE read-only capture of a managed device -> a DRAFT template (v1).  Never mutates the device."""
    outcome, sections = snapshots.capture_with_sections(device_name, actor=actor, session_factory=session_factory, now=now)
    if outcome.snapshot is None:
        raise TemplateError(outcome.code or "RETRIEVAL_FAILED", outcome.message or "The running configuration could not be captured.")
    return _draft_from_capture(outcome.snapshot, sections, actor=actor, name=name, family=family, method="live-read-only-capture", live=True)


def extract_from_snapshot(snapshot, *, actor: str = "", name: str = "", family: str = models.TemplateFamily.CUSTOM):
    """The same extraction from an ALREADY captured, sanitized snapshot (no device contact)."""
    if snapshot.platform not in LIVE_EXTRACTION_PLATFORMS:
        raise TemplateError("UNSUPPORTED_PLATFORM", "Template extraction is available for cEOS and Ubuntu/FRR captures only.")
    return _draft_from_capture(snapshot, None, actor=actor, name=name, family=family, method="stored-running-config-snapshot", live=False)


def _draft_from_capture(snapshot, sections, *, actor, name, family, method, live):
    with transaction.atomic():
        content = extraction_content([(snapshot, sections)], family=family, method=method)
        template = create_template(name=name or f"{snapshot.device_name} extracted template", family=family,
                                   origin=models.TemplateOrigin.EXTRACTED, actor=actor,
                                   description=f"Extracted from the running configuration of {snapshot.device_name}.")
        version = create_version(template, content, actor=actor)
        _audit(models.AuditEventType.TEMPLATE_EXTRACTED, f"Template {version.ref} extracted from {snapshot.device_name}", actor=actor, version=version,
               metadata={"template_id": template.template_id, "device": snapshot.device_name, "platform": snapshot.platform,
                         "running_config_digest": snapshot.digest, "snapshot_id": str(snapshot.snapshot_id), "method": method})
        _record_extraction_evidence(version, actor=actor, live=live)
    return version


def version_from_revision(revision, *, actor: str = "", name: str = ""):
    """A Device Builder working revision -> a DRAFT template version.

    The revision's own template (if it was cloned from a non-baseline one) receives the next version; a clone of a
    BASELINE or imported template -- or a revision with no template -- becomes a NEW derived template, so a published
    baseline is never altered.
    """
    intent_row = revision.device_intent
    hostname = intent_row.device_name
    intent, _excluded = normalize.clean(working_intent.intent_from_sections(revision.sections, hostname=hostname), intent_row.platform)
    generalized = normalize.generalize({hostname: intent})
    clone = (revision.metadata or {}).get("template_clone") or {}
    source = get_version(clone.get("template_id", ""), int(clone.get("version") or 0)) if clone else None
    provenance = {"method": "device-builder-working-intent", "source_devices": [hostname], "platforms": [intent_row.platform],
                  "extracted_at": timezone.now().isoformat(), "repository_head": repository_head(),
                  "working_intent": {"change_id": intent_row.change.change_id, "device": hostname, "revision": revision.revision},
                  "derived_from": {"template_id": source.template.template_id, "version": source.version, "digest": source.digest} if source else {}}
    with transaction.atomic():
        same_template = source is not None and source.template.origin in (models.TemplateOrigin.EXTRACTED, models.TemplateOrigin.DERIVED) \
            and not source.template.retired_at
        if same_template:
            template = source.template
        else:
            template = create_template(name=name or f"{hostname} working intent", family=source.template.family if source else models.TemplateFamily.CUSTOM,
                                       origin=models.TemplateOrigin.DERIVED, actor=actor,
                                       description=f"Derived from the Device Builder working intent of {hostname} ({intent_row.change.change_id}).")
        content = build_content(family=template.family, intent=generalized["intent"], parameters=generalized["parameters"],
                                parameter_sets=generalized["parameter_sets"], provenance=provenance)
        return create_version(template, content, actor=actor, source_version=source)


# --- export / import ---------------------------------------------------------------------------------------------------
def export_package(version, *, actor: str = "") -> tuple[str, bytes]:
    """-> (filename, deterministic YAML bytes).  Only an immutable, validated version is exported."""
    if not version.is_published:
        raise TemplateError("NOT_PUBLISHED", "Only a published template version can be exported.")
    problems = publication_problems(version)
    if problems:
        raise TemplateError("EXPORT_REFUSED", problems[:25])
    document = package.build_document(version, feature_templates=features.feature_templates(version.required_features, version.platforms))
    data = package.dump(document)
    _audit(models.AuditEventType.TEMPLATE_EXPORTED, f"Template {version.ref} exported", actor=actor, version=version,
           metadata={"template_id": version.template.template_id, "version": version.version, "digest": version.digest, "bytes": len(data)})
    return f"{version.template.template_id}-v{version.version}{package.FILE_SUFFIX}", data


def import_package(data: bytes, *, actor: str = "", trusted_baseline: bool = False):
    """Register an exported package.  -> (version, created).  Nothing is executed; the version is immutable from the start.

    Identity: the package's template id is kept when it is free or when it names the same lineage here; a version number
    that already exists with DIFFERENT content never overwrites -- the package is registered under a new local identity.
    """
    try:
        loaded = package.load(data)
    except package.PackageError as exc:
        _audit(models.AuditEventType.TEMPLATE_IMPORT_REJECTED, f"Template package rejected: {exc.code}", actor=actor,
               metadata={"code": exc.code, "problem_count": len(exc.problems), "bytes": len(data) if isinstance(data, (bytes, bytearray)) else 0})
        raise TemplateError(exc.code, exc.problems) from None
    manifest, content = loaded["manifest"], loaded["content"]
    if content["family"] not in models.TemplateFamily.values:
        raise TemplateError("INVALID_PACKAGE", "Unknown template family.")
    existing = get_template(manifest["template_id"])
    same = existing.versions.filter(version=manifest["version"]).first() if existing else None
    if same is not None and same.digest == loaded["digest"]:
        return same, False
    origin = models.TemplateOrigin.BASELINE if trusted_baseline and manifest["origin"] == models.TemplateOrigin.BASELINE else models.TemplateOrigin.IMPORTED
    reuse = existing is not None and same is None and existing.family == content["family"] and existing.origin == origin
    imported = {"imported_at": timezone.now().isoformat(), "imported_by": actor[:150], "package_sha256": loaded["package_sha256"],
                "original_template_id": manifest["template_id"], "original_version": manifest["version"], "original_origin": manifest["origin"],
                "original_created_by": manifest["created_by"], "original_created_at": manifest["created_at"], "content_digest": loaded["digest"],
                "local_identity": "kept" if existing is None or reuse else "reassigned"}
    with transaction.atomic():
        if existing is None:
            template = create_template(name=manifest["name"], family=content["family"], origin=origin, description=manifest["description"],
                                       actor=actor, template_id=manifest["template_id"], metadata={"import": imported})
        elif reuse:
            template = existing
        else:
            template = create_template(name=f"{manifest['name']} (imported copy)"[:120], family=content["family"], origin=origin,
                                       description=manifest["description"], actor=actor, metadata={"import": imported})
        version = create_version(template, content, actor=actor, version_number=manifest["version"])
        if version.digest != loaded["digest"]:
            raise TemplateError("DIGEST_MISMATCH", "The stored content does not reproduce the package digest.")
        template.metadata = {**(template.metadata or {}), "imports": [*(template.metadata or {}).get("imports", []), {"version": version.version, **imported}][-50:]}
        template.save(update_fields=["metadata"])
        publish(version, actor=actor)
        _audit(models.AuditEventType.TEMPLATE_IMPORTED, f"Template package registered as {version.ref}", actor=actor, version=version,
               metadata={"template_id": template.template_id, "version": version.version, "digest": version.digest,
                         "original_template_id": manifest["template_id"], "package_sha256": loaded["package_sha256"],
                         "local_identity": imported["local_identity"]})
    return version, True


def import_metadata(version) -> dict:
    """The import provenance of one version (kept on the template: a version's own content must reproduce the package digest)."""
    for row in (version.template.metadata or {}).get("imports", []):
        if row.get("version") == version.version:
            return row
    return {}
