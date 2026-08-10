"""Unit tests for config dataclasses + validation."""

from __future__ import annotations

import pytest

from dbx_netpolicy.config import ApplyOptions, IngressConfig, validate_apply


def test_ingress_scope_properties():
    assert IngressConfig(scoping_mode="ip_only").scope_destination is False
    assert IngressConfig(scoping_mode="ip_only").scope_identity is False
    c = IngressConfig(scoping_mode="ip_identity_and_destination")
    assert c.scope_destination and c.scope_identity
    assert IngressConfig(scoping_mode="ip_and_identity").scope_identity
    assert IngressConfig(scoping_mode="ip_and_destination").scope_destination


def test_policy_mode_target_maps_to_block():
    assert IngressConfig(policy_mode="dry_run").policy_mode_target == "ingress_dry_run"
    assert IngressConfig(policy_mode="enforce").policy_mode_target == "ingress"


def test_validate_apply_noop_when_not_creating():
    # propose-only, or create_new — nothing to validate.
    validate_apply(ApplyOptions(create_policy=False, policy_action="add_to_existing"),
                   "per_workspace", "egress")
    validate_apply(ApplyOptions(create_policy=True, policy_action="create_new"),
                   "per_workspace", "egress")


def test_validate_apply_requires_existing_id():
    with pytest.raises(ValueError, match="existing-policy-id"):
        validate_apply(ApplyOptions(create_policy=True, policy_action="add_to_existing"),
                       "single", "egress")


def test_validate_apply_requires_single_scope():
    with pytest.raises(ValueError, match="single"):
        validate_apply(
            ApplyOptions(create_policy=True, policy_action="add_to_existing", existing_policy_id="p"),
            "per_workspace", "egress")


def test_validate_apply_ok_single_with_id():
    validate_apply(
        ApplyOptions(create_policy=True, policy_action="add_to_existing", existing_policy_id="p"),
        "single", "egress")
