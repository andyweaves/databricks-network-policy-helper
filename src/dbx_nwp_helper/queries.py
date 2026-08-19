"""SQL against the Databricks system tables.

The query text is ported verbatim from the notebooks — the DBSQL built-ins (`try_ip_host`,
`ip_version`, `ip_cidr_contains`, `try_ip_cidr`) run identically on a SQL warehouse. The notebook
staged an `audit_recent` temp view and read it repeatedly; over a stateless SQL connection we inline
that as a CTE / base subquery instead, so each query is self-contained.
"""

from __future__ import annotations

# The base audit projection the notebook exposed as the `audit_recent` temp view.
_AUDIT_RECENT = """
    SELECT
      event_date, event_time, workspace_id, audit_level, service_name, action_name,
      COALESCE(user_identity.email, user_identity.subject_name, 'UNKNOWN') AS principal,
      user_identity.email AS principal_email,
      user_identity.subject_name AS subject_name,
      source_ip_address,
      try_ip_host(source_ip_address) AS normalized_ip,
      ip_version(try_ip_host(source_ip_address)) AS ip_version,
      user_agent,
      response.status_code AS status_code,
      session_id, request_id
    FROM system.access.audit
    WHERE event_date >= current_date() - INTERVAL {lookback_days} DAYS
"""


def audit_row_count(lookback_days: int) -> str:
    return f"SELECT COUNT(*) AS n FROM ({_AUDIT_RECENT.format(lookback_days=lookback_days)})"


# The private/reserved-range exclusion used by frequent_public_ips — factored out so the diagnostic
# funnel counts "public" identically to the candidate query.
_NOT_PRIVATE = """NOT (
      ip_version = 4 AND (
        ip_cidr_contains('10.0.0.0/8', normalized_ip)
        OR ip_cidr_contains('172.16.0.0/12', normalized_ip)
        OR ip_cidr_contains('192.168.0.0/16', normalized_ip)
        OR ip_cidr_contains('127.0.0.0/8', normalized_ip)
        OR ip_cidr_contains('169.254.0.0/16', normalized_ip)
        OR ip_cidr_contains('100.64.0.0/10', normalized_ip)
        OR ip_cidr_contains('192.0.2.0/24', normalized_ip)
        OR ip_cidr_contains('198.18.0.0/15', normalized_ip)
        OR ip_cidr_contains('198.51.100.0/24', normalized_ip)
        OR ip_cidr_contains('203.0.113.0/24', normalized_ip)
        OR normalized_ip = '0.0.0.0'
      ))"""


def candidate_funnel(lookback_days: int, treat_null_status_as_success: bool) -> str:
    """A single-row diagnostic showing how many audit rows survive each successive filter the
    candidate query applies — so an empty candidate set can be explained (private IPs? all
    account-level? nothing successful?). Independent of the include_* toggles: it always reports
    each dimension so the user can see which toggle would help."""
    null_status_ok = "TRUE" if treat_null_status_as_success else "FALSE"
    return f"""
    WITH a AS ({_AUDIT_RECENT.format(lookback_days=lookback_days)})
    SELECT
      COUNT(*) AS total_rows,
      SUM(CASE WHEN normalized_ip IS NOT NULL THEN 1 ELSE 0 END) AS with_source_ip,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 THEN 1 ELSE 0 END) AS ipv4,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND ip_version = 6 THEN 1 ELSE 0 END) AS ipv6,
      SUM(CASE WHEN normalized_ip IS NOT NULL
               AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
               THEN 1 ELSE 0 END) AS successful,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND CAST(workspace_id AS STRING) <> '0'
               THEN 1 ELSE 0 END) AS workspace_level,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND CAST(workspace_id AS STRING) = '0'
               THEN 1 ELSE 0 END) AS account_level,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 AND {_NOT_PRIVATE}
               THEN 1 ELSE 0 END) AS public_ipv4,
      COUNT(DISTINCT CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 AND {_NOT_PRIVATE}
               AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
               THEN normalized_ip END) AS distinct_public_ok,
      COUNT(DISTINCT CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 AND {_NOT_PRIVATE}
               AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
               AND CAST(workspace_id AS STRING) <> '0'
               THEN normalized_ip END) AS distinct_public_ok_ws
    FROM a
    """


def surface_summary(lookback_days: int) -> str:
    return f"""
    WITH audit_recent AS ({_AUDIT_RECENT.format(lookback_days=lookback_days)})
    SELECT service_name, action_name,
      COUNT(*) AS events,
      COUNT(DISTINCT principal) AS principals,
      COUNT(DISTINCT normalized_ip) AS distinct_ips,
      COUNT(DISTINCT session_id) AS sessions,
      MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
    FROM audit_recent
    GROUP BY ALL
    ORDER BY events DESC, principals DESC
    LIMIT 100
    """


def principal_network_diversity(lookback_days: int) -> str:
    return f"""
    WITH audit_recent AS ({_AUDIT_RECENT.format(lookback_days=lookback_days)}),
    principal_networks AS (
      SELECT principal,
        COUNT(*) AS events,
        COUNT(DISTINCT normalized_ip) AS distinct_ips,
        COUNT(DISTINCT CASE
          WHEN ip_version = 4 THEN try_ip_cidr(CONCAT(normalized_ip, '/24'))
          WHEN ip_version = 6 THEN try_ip_cidr(CONCAT(normalized_ip, '/48'))
        END) AS distinct_networks,
        COUNT(DISTINCT user_agent) AS distinct_user_agents,
        COUNT(DISTINCT service_name) AS distinct_services,
        MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
      FROM audit_recent
      WHERE normalized_ip IS NOT NULL
      GROUP BY principal
    )
    SELECT * FROM principal_networks
    ORDER BY distinct_networks DESC, distinct_ips DESC, events DESC
    LIMIT 100
    """


def frequent_public_ips(
    lookback_days: int,
    min_events: int,
    include_ipv6: bool,
    treat_null_status_as_success: bool,
    include_account_level: bool,
    only_workspace_id: int | None = None,
) -> str:
    ipv6_predicate = "OR ip_version = 6" if include_ipv6 else ""
    # workspace_id is a STRING column in system.access.audit; comparing to the integer 0 matches no
    # rows (silently excluding all workspace-level traffic), so compare against the string '0'.
    if only_workspace_id is not None:
        # current_workspace scope: restrict to this workspace's traffic. (Overrides the account-level
        # toggle — an explicit workspace id is never account-level.)
        account_level_predicate = f"AND CAST(workspace_id AS STRING) = '{int(only_workspace_id)}'"
    elif include_account_level:
        account_level_predicate = ""
    else:
        account_level_predicate = "AND CAST(workspace_id AS STRING) <> '0'"
    null_status_ok = "TRUE" if treat_null_status_as_success else "FALSE"
    return f"""
    WITH audit_recent AS ({_AUDIT_RECENT.format(lookback_days=lookback_days)}),
    successful AS (
      SELECT workspace_id, principal, principal_email, subject_name,
        service_name, action_name,
        normalized_ip AS public_ip, ip_version, event_date, session_id
      FROM audit_recent
      WHERE normalized_ip IS NOT NULL
        AND (ip_version = 4 {ipv6_predicate})
        AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
        {account_level_predicate}
        AND NOT (
          ip_version = 4 AND (
            ip_cidr_contains('10.0.0.0/8', normalized_ip)
            OR ip_cidr_contains('172.16.0.0/12', normalized_ip)
            OR ip_cidr_contains('192.168.0.0/16', normalized_ip)
            OR ip_cidr_contains('127.0.0.0/8', normalized_ip)
            OR ip_cidr_contains('169.254.0.0/16', normalized_ip)
            OR ip_cidr_contains('100.64.0.0/10', normalized_ip)
            OR ip_cidr_contains('192.0.2.0/24', normalized_ip)
            OR ip_cidr_contains('198.18.0.0/15', normalized_ip)
            OR ip_cidr_contains('198.51.100.0/24', normalized_ip)
            OR ip_cidr_contains('203.0.113.0/24', normalized_ip)
            OR normalized_ip = '0.0.0.0'
          )
        )
    )
    SELECT public_ip,
      ANY_VALUE(ip_version) AS ip_version,
      COUNT(*) AS events,
      COUNT(DISTINCT principal) AS principals,
      COUNT(DISTINCT service_name) AS services,
      COUNT(DISTINCT action_name) AS actions,
      COUNT(DISTINCT event_date) AS active_days,
      COUNT(DISTINCT session_id) AS sessions,
      MIN(event_date) AS first_active_date, MAX(event_date) AS last_active_date,
      sort_array(collect_set(principal)) AS principal_list,
      sort_array(collect_set(principal_email)) AS principal_emails,
      sort_array(collect_set(subject_name)) AS subject_names,
      sort_array(collect_set(service_name)) AS service_list,
      sort_array(collect_set(workspace_id)) AS workspace_ids
    FROM successful
    GROUP BY public_ip
    HAVING COUNT(*) >= {min_events}
    ORDER BY events DESC, principals DESC
    """


def denied_requests(lookback_days: int) -> str:
    return f"""
    WITH audit_recent AS ({_AUDIT_RECENT.format(lookback_days=lookback_days)})
    SELECT normalized_ip AS source_ip,
      COUNT(*) AS denied_events,
      COUNT(DISTINCT principal) AS principals,
      sort_array(collect_set(principal)) AS principal_list,
      MIN(event_date) AS first_denied, MAX(event_date) AS last_denied
    FROM audit_recent
    WHERE (action_name = 'IpAccessDenied' OR status_code = 403)
      AND normalized_ip IS NOT NULL
    GROUP BY normalized_ip
    ORDER BY denied_events DESC
    """


def observed_egress(
    lookback_days: int, min_events: int, source_type_filter: str, only_workspace_id: int | None = None
) -> str:
    # Escape single quotes so a value containing one can't break (or inject into) the query.
    src_filter = (
        f"AND network_source_type = '{source_type_filter.replace(chr(39), chr(39) * 2)}'"
        if source_type_filter
        else ""
    )
    ws_filter = (
        f"AND CAST(workspace_id AS STRING) = '{int(only_workspace_id)}'"
        if only_workspace_id is not None
        else ""
    )
    return f"""
    SELECT
      COALESCE(dns_event.domain_name, storage_event.hostname, destination) AS destination,
      destination_type,
      COUNT(*) AS events,
      COUNT(DISTINCT access_type) AS distinct_access_types,
      sort_array(collect_set(access_type)) AS access_types,
      sort_array(collect_set(network_source_type)) AS source_types,
      sort_array(collect_set(workspace_id)) AS workspace_ids,
      sort_array(array_distinct(flatten(collect_list(dns_event.rdata)))) AS resolved_ips,
      MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
    FROM system.access.outbound_network
    WHERE event_time >= current_date() - INTERVAL {lookback_days} DAYS
      {src_filter}
      {ws_filter}
      AND COALESCE(dns_event.domain_name, storage_event.hostname, destination) IS NOT NULL
    GROUP BY 1, 2
    HAVING COUNT(*) >= {min_events}
    ORDER BY events DESC
    """
