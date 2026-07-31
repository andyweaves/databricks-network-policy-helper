# CBI network-policy SDK schema

Verified against `databricks-sdk` **0.113.0** by introspection (not from docs/memory). The notebook
pins `databricks-sdk>=0.113.0` at the top because serverless/older DBRs bundle a version without
these dataclasses.

## Client & methods

- Client: **`AccountClient`** (account-level; not `WorkspaceClient`). Requires account admin.
- Service: `a.network_policies` → `NetworkPoliciesAPI` in `databricks.sdk.service.settings`.
- Methods (update is a **full replace**, not a patch):
  - `create_network_policy_rpc(network_policy: AccountNetworkPolicy)`
  - `get_network_policy_rpc(network_policy_id: str)`
  - `update_network_policy_rpc(network_policy_id: str, network_policy: AccountNetworkPolicy)`
  - `list_network_policies_rpc()`
  - `delete_network_policy_rpc(network_policy_id: str)`

## Object model

```
AccountNetworkPolicy
├── account_id: str
├── network_policy_id: str
├── ingress:         CustomerFacingIngressNetworkPolicy   # ENFORCED — blocks non-matching source IPs
├── ingress_dry_run: CustomerFacingIngressNetworkPolicy   # LOG-ONLY — records, never blocks
└── egress:          NetworkPolicyEgress                  # SEG; preserved verbatim on update

CustomerFacingIngressNetworkPolicy
├── public_access:          CustomerFacingIngressNetworkPolicyPublicAccess
├── private_access:         ...
└── cross_workspace_access: ...

CustomerFacingIngressNetworkPolicyPublicAccess
├── restriction_mode: {FULL_ACCESS | RESTRICTED_ACCESS}   # helper always uses RESTRICTED_ACCESS
├── allow_rules: [CustomerFacingIngressNetworkPolicyPublicIngressRule]   # the suggested allow-list
└── deny_rules:  [CustomerFacingIngressNetworkPolicyPublicIngressRule]   # optional threat-intel deny rules
                                                                          # (same rule shape; origin CIDRs only)

PublicIngressRule
├── label: str
├── origin:         PublicRequestOrigin   # the IPs
├── destination:    RequestDestination    # optional — what they may reach
└── authentication: Authentication        # optional — who

PublicRequestOrigin
├── included_ip_ranges: IpRanges(ip_ranges: List[str])   # IPv4 CIDR only
├── excluded_ip_ranges: IpRanges
└── all_ip_ranges: bool

RequestDestination  (set exactly one shape)
├── all_destinations: bool
├── apps_runtime:     AppsRuntimeDestination(all_destinations=True)
├── lakebase_runtime: LakebaseRuntimeDestination(all_destinations=True)
├── workspace_ui / workspace_api / account_ui / account_api / account_databricks_one: ...

Authentication
├── identity_type: {IDENTITY_TYPE_ALL_USERS | IDENTITY_TYPE_ALL_SERVICE_PRINCIPALS | IDENTITY_TYPE_SELECTED_IDENTITIES}
└── identities: [AuthenticationIdentity]   # only with SELECTED_IDENTITIES

AuthenticationIdentity
├── principal_id: int                       # NUMERIC account principal id — NOT the email
└── principal_type: {PRINCIPAL_TYPE_USER | PRINCIPAL_TYPE_SERVICE_PRINCIPAL}
```

## Gotchas baked into the notebook

- **`included_ip_ranges` is an `IpRanges` object**, not a bare list — wrap: `IpRanges(ip_ranges=[...])`.
- **IPv4 only** — the schema comment says "We only support IPv4 ... CIDR notation for now". IPv6
  framings are dropped before building a policy.
- **`principal_id` is `int`.** The audit log only has string emails/subject_names — there is no
  numeric id in `system.access.audit`. Identity scoping therefore resolves emails→ids via account
  SCIM (`AccountClient.users.list(filter='userName eq "..."')` /
  `service_principals.list(filter='applicationId eq "..."')`, taking `.id`).
- **No groups** — only USER and SERVICE_PRINCIPAL principal types exist.
- **Dry-run vs enforce are separate blocks**, not an enforcement flag: write `ingress_dry_run` to
  trial (log-only), `ingress` to enforce (blocking). Update replaces the whole policy, so the
  notebook reads the existing policy and re-sends the untouched blocks.
