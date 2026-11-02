"""
Configlet + dependency service. Structure only: no config rendering (
rendered_config/rollback_config stay empty), no deployment, no NetBox write.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction

from .. import models
from . import secret_policy

MAX_SEQUENCE_RETRIES = 10


def create_configlet(
    *,
    change: models.Change,
    target_device: str,
    feature_namespace: str,
    operation_type: str,
    deployment_priority: int,
    description: str = "",
    device_intent: models.DeviceIntent | None = None,
    previous_state_ref: dict | None = None,
    desired_state_ref: dict | None = None,
    verification_spec: dict | None = None,
    metadata: dict | None = None,
) -> models.Configlet:
    if feature_namespace not in models.FeatureNamespace.values:
        raise ValueError(f"Unknown feature_namespace {feature_namespace!r}")
    if operation_type not in models.ConfigletOperationType.values:
        raise ValueError(f"Unknown operation_type {operation_type!r}")
    if deployment_priority not in models.DeploymentPriority.values:
        raise ValueError(f"Unknown deployment_priority {deployment_priority!r}")

    previous_state_ref = secret_policy.assert_no_secret_shaped_keys(
        dict(previous_state_ref or {}), context="Configlet previous_state_ref"
    )
    desired_state_ref = secret_policy.assert_no_secret_shaped_keys(
        dict(desired_state_ref or {}), context="Configlet desired_state_ref"
    )
    verification_spec = secret_policy.assert_no_secret_shaped_keys(
        dict(verification_spec or {}), context="Configlet verification_spec"
    )
    metadata = secret_policy.assert_no_secret_shaped_keys(dict(metadata or {}), context="Configlet metadata")

    for _ in range(MAX_SEQUENCE_RETRIES):
        last = change.configlets.filter(plan__isnull=True).order_by("-sequence").first()
        next_sequence = (last.sequence + 1) if last else 1
        cfg_id = f"CFG-{next_sequence:03d}"
        try:
            with transaction.atomic():
                configlet = models.Configlet.objects.create(
                    change=change,
                    cfg_id=cfg_id,
                    sequence=next_sequence,
                    target_device=target_device,
                    device_intent=device_intent,
                    feature_namespace=feature_namespace,
                    description=description,
                    operation_type=operation_type,
                    deployment_priority=deployment_priority,
                    previous_state_ref=previous_state_ref,
                    desired_state_ref=desired_state_ref,
                    verification_spec=verification_spec,
                    metadata=metadata,
                )
                models.AuditEvent.objects.create(
                    event_type=models.AuditEventType.CONFIGLET_CREATED,
                    change=change,
                    object_type="Configlet",
                    object_id=configlet.cfg_id,
                    summary=f"{configlet.full_identifier} created",
                )
            return configlet
        except IntegrityError:
            continue
    raise RuntimeError("Could not allocate a unique configlet sequence after several attempts.")


def add_configlet_dependency(
    *, configlet: models.Configlet, depends_on: models.Configlet
) -> models.ConfigletDependency:
    """Same-Change directed dependency only. Self-dependency and cross-Change
    dependencies raise ValueError (from ConfigletDependency.save()); a
    duplicate edge raises ValueError translated from the DB uniqueness
    constraint."""
    try:
        with transaction.atomic():
            return models.ConfigletDependency.objects.create(configlet=configlet, depends_on=depends_on)
    except IntegrityError as exc:
        raise ValueError(
            f"{configlet.cfg_id} already depends on {depends_on.cfg_id}."
        ) from exc
