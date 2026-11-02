"""Candidate (single DeviceIntent + revision) builders for Device Builder tests.

One home for what used to be ``phase10_helpers`` / ``phase11_helpers`` /
``phase12_helpers``: the three overlapped (11 and 12 simply re-exported 10) and
differed only in which intent service they wrapped.  Multi-device Change
fixtures with fake sources live in ``helpers.validation``.
"""

from __future__ import annotations

from core import models
from core.services import (
    change_service,
    field_commit_service,
    intent_service,
    interface_intent_service,
    routing_intent_service,
    service_policy_intent_service,
)


def make_candidate(*, platform=models.Platform.ARISTA_CEOS, device_name="R1", target_type=None):
    change = change_service.create_change(title="Device Builder fixture")
    extra = {"target_type": target_type} if target_type else {}
    intent, _ = intent_service.create_or_get_device_intent(
        change=change, device_name=device_name, platform=platform, **extra
    )
    revision = intent_service.create_candidate_revision(device_intent=intent)
    field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
    return change, intent, revision


def commit(change, intent, revision, path, value):
    return field_commit_service.commit_field(
        change=change, intent=intent, revision=revision, path=path, raw_value=value
    )


# --- interfaces -------------------------------------------------------------------------------
def add_interface(revision, *, kind="ROUTED_PHYSICAL", name="Ethernet1"):
    return interface_intent_service.add_interface(revision=revision, kind=kind, name=name)


# --- routing ----------------------------------------------------------------------------------
def add_static_route(revision, *, family="IPV4"):
    return routing_intent_service.add_static_route(revision=revision, family=family)


def add_instance(revision, *, family, **kwargs):
    return routing_intent_service.add_protocol_instance(revision=revision, family=family, **kwargs)


def add_binding(revision, *, family, instance_id, interface_id):
    return routing_intent_service.add_interface_binding(
        revision=revision, family=family, instance_id=instance_id, interface_id=interface_id
    )


def add_bgp_neighbor(revision, *, instance_id, peer_address, remote_asn):
    return routing_intent_service.add_bgp_neighbor(
        revision=revision, instance_id=instance_id, peer_address=peer_address, remote_asn=remote_asn
    )


def add_bgp_network(revision, *, instance_id, family, cidr):
    return routing_intent_service.add_bgp_network(revision=revision, instance_id=instance_id, family=family, cidr=cidr)


# --- services / security / policy -------------------------------------------------------------
def add_fhrp(revision, interface_id, *, family="IPV4"):
    return service_policy_intent_service.add_fhrp_instance(
        revision=revision, protocol="VARP", interface_id=interface_id, address_family=family
    )


def add_acl(revision, *, name="EDGE-IN"):
    return service_policy_intent_service.add_acl(revision=revision, name=name, family="IPV4", acl_type="EXTENDED")
