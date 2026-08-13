"""Unit tests for config dataclasses + validation."""

from __future__ import annotations

import pytest

from dbx_nwp_helper.config import (
    ApplyOptions,
    IngressConfig,
    validate_apply,
    validate_disable_ip_acls,
    validate_policy_name,
)


def test_ingress_scope_properties():
    assert IngressConfig(scoping_mode="ip_only").scope_destination is False
    assert IngressConfig(scoping_mode="ip_only").scope_identity is False
    c = IngressConfig(scoping_mode="ip_identity_and_destination")
    assert c.scope_destination and c.scope_identity
    assert IngressConfig(scoping_mode="ip_and_identity").scope_identity
    assert IngressConfig(scoping_mode="ip_and_destination").scope_destination


def test_include_account_level_defaults_false():
    # Account-level (workspace_id=0) rows are account console / SCIM traffic, not workspace-scoped,
    # so they're excluded by default.
    assert IngressConfig().include_account_level is False


def test_name_prefix_default_aligns_with_command():
    # migrate-acl no longer has a name_prefix (it names the policy directly); ingress/egress keep it.
    from dbx_nwp_helper.config import DEFAULT_NAME_PREFIX, EgressConfig
    assert DEFAULT_NAME_PREFIX == "dbx-nwp"
    assert IngressConfig().name_prefix == "dbx-nwp"
    assert EgressConfig().name_prefix == "dbx-nwp"


def test_policy_scope_defaults_to_current_workspace():
    from dbx_nwp_helper.config import EgressConfig
    assert IngressConfig().policy_scope == "current_workspace"
    assert EgressConfig().policy_scope == "current_workspace"


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
                       "current_workspace", "egress")


def test_validate_apply_rejects_per_workspace():
    with pytest.raises(ValueError, match="per_workspace"):
        validate_apply(
            ApplyOptions(create_policy=True, policy_action="add_to_existing", existing_policy_id="p"),
            "per_workspace", "egress")


def test_validate_apply_ok_single_scopes_with_id():
    # both single-policy scopes are valid targets for add_to_existing
    for scope in ("current_workspace", "all_workspaces"):
        validate_apply(
            ApplyOptions(create_policy=True, policy_action="add_to_existing", existing_policy_id="p"),
            scope, "egress")


def test_validate_disable_ip_acls_noop_when_disabled():
    # not requested — never validated, regardless of create/assign.
    validate_disable_ip_acls(False, create_policy=False, auto_assign=False)


def test_validate_disable_ip_acls_requires_create_and_assign():
    # requested without both create AND assign would leave the workspace unprotected -> reject.
    with pytest.raises(ValueError, match="creates AND assigns"):
        validate_disable_ip_acls(True, create_policy=True, auto_assign=False)
    with pytest.raises(ValueError, match="creates AND assigns"):
        validate_disable_ip_acls(True, create_policy=False, auto_assign=True)
    with pytest.raises(ValueError, match="creates AND assigns"):
        validate_disable_ip_acls(True, create_policy=False, auto_assign=False)


def test_validate_disable_ip_acls_ok_with_create_and_assign():
    validate_disable_ip_acls(True, create_policy=True, auto_assign=True)


def test_disable_existing_ip_acls_defaults_false():
    from dbx_nwp_helper.config import AclConfig
    assert IngressConfig().disable_existing_ip_acls is False
    assert AclConfig().disable_existing_ip_acls is False


def test_validate_policy_name_noop_when_blank():
    validate_policy_name("", "per_workspace", "add_to_existing")  # nothing set -> no validation


def test_validate_policy_name_rejects_add_to_existing():
    with pytest.raises(ValueError, match="existing-policy-id"):
        validate_policy_name("my-pol", "current_workspace", "add_to_existing")


def test_validate_policy_name_rejects_per_workspace():
    with pytest.raises(ValueError, match="per_workspace"):
        validate_policy_name("my-pol", "per_workspace", "create_new")


def test_validate_policy_name_ok_single_scope_create_new():
    for scope in ("current_workspace", "all_workspaces"):
        validate_policy_name("my-pol", scope, "create_new")


def test_policy_name_defaults_blank():
    from dbx_nwp_helper.config import AclConfig, EgressConfig
    assert IngressConfig().policy_name == ""
    assert EgressConfig().policy_name == ""
    assert AclConfig().policy_name == ""
