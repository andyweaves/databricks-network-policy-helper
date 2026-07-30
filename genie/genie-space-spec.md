# Genie space spec — CBI Policy Advisor

Spec for a Genie space that lets an operator ask the CBI audit + enrichment data in natural
language. **Build it (via the Genie UI, the Genie REST API, or any Genie authoring tooling) only
after the enrichment tables are persisted** to a stable schema (set the notebook's
`enrichment_schema` widget — do not build over temp views). Suggested schema: `main.network_cbi`.

## Prerequisites (must exist before building)

- `system.access.audit` — readable by the Genie space's runner.
- `<enrichment_schema>.threat_intel_ips` — from the notebook (threat feeds).
- `<enrichment_schema>.cloud_provider_ranges` — from the notebook (cloud ranges).
- Recommended: persist the notebook's candidate/suggestion output as a table too (e.g.
  `frequent_public_ips` and the per-owner suggestions) so Genie can answer without re-deriving.

## Space title & description

- **Title:** CBI Policy Advisor — Ingress Traffic & Threat Enrichment
- **Description:** Ask about public source IPs reaching the workspace, who connects from where, and
  which observed IPs match threat-intel or cloud-provider ranges — the inputs to a context-based
  ingress allow-list.

## Instructions (paste into the space)

```
This space analyses inbound access to Databricks from system.access.audit, enriched with
open threat-intelligence (threat_intel_ips) and cloud-provider IP ranges (cloud_provider_ranges).

Definitions:
- "public source IP" = source_ip_address normalised via try_ip_host, excluding private/loopback/
  link-local/CGNAT/documentation ranges.
- "successful" traffic = response.status_code < 400.
- A "threat match" = an observed IP inside a threat_intel_ips CIDR. Confidence 1 = high.
- "cloud-owned" = an observed IP inside a cloud_provider_ranges CIDR (aws/gcp/oracle/azure).
Always prefer successful traffic and the last 30 days unless the user says otherwise.
Use ip_cidr_contains(range_cidr, observed_ip) to test membership.
CBI policies are IPv4-only; when suggesting allow-list scope, focus on IPv4.
```

## Example SQL (curate these as trusted queries)

**Top public source IPs by successful events (last 30d)**
```sql
SELECT try_ip_host(source_ip_address) AS ip,
       COUNT(*) AS events,
       COUNT(DISTINCT COALESCE(user_identity.email, user_identity.subject_name)) AS principals
FROM system.access.audit
WHERE event_date >= current_date() - INTERVAL 30 DAYS
  AND response.status_code < 400
  AND ip_version(try_ip_host(source_ip_address)) = 4
GROUP BY ip ORDER BY events DESC LIMIT 100;
```

**Observed IPs that match threat intelligence**
```sql
SELECT DISTINCT a_ip AS observed_ip, t.source_feed, t.threat_type, t.confidence, t.source_url
FROM (SELECT DISTINCT try_ip_host(source_ip_address) AS a_ip
      FROM system.access.audit
      WHERE event_date >= current_date() - INTERVAL 30 DAYS) a
JOIN main.network_cbi.threat_intel_ips t
  ON ip_cidr_contains(t.cidr, a.a_ip)
ORDER BY confidence, observed_ip;
```

**Which identities connect from a given IP**
```sql
SELECT COALESCE(user_identity.email, user_identity.subject_name) AS principal,
       COUNT(*) AS events, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM system.access.audit
WHERE event_date >= current_date() - INTERVAL 30 DAYS
  AND try_ip_host(source_ip_address) = :ip
GROUP BY principal ORDER BY events DESC;
```

**Public IPs that are cloud-owned (candidates NOT to allow-list wholesale)**
```sql
SELECT DISTINCT a.a_ip AS observed_ip, c.provider, c.service, c.region
FROM (SELECT DISTINCT try_ip_host(source_ip_address) AS a_ip
      FROM system.access.audit
      WHERE event_date >= current_date() - INTERVAL 30 DAYS
        AND response.status_code < 400) a
JOIN main.network_cbi.cloud_provider_ranges c
  ON ip_cidr_contains(c.cidr, a.a_ip)
ORDER BY provider, observed_ip;
```

**What does each IP connect to (destination scoping input)**
```sql
SELECT try_ip_host(source_ip_address) AS ip,
       sort_array(collect_set(service_name)) AS services
FROM system.access.audit
WHERE event_date >= current_date() - INTERVAL 30 DAYS
  AND response.status_code < 400
GROUP BY ip ORDER BY size(services) DESC LIMIT 100;
```

## Sample NL questions to seed / test the space

- "Which external IPs hit the workspace most in the last 30 days, and are any on a blocklist?"
- "Show me identities connecting from cloud-provider IP ranges."
- "Which IPs only ever connect to Databricks Apps?"
- "List source IPs that matched Spamhaus or FireHOL, with the feed and confidence."
- "Who logged in from <IP> and when?"
- "How many distinct /24 networks does each user connect from?" (roaming / shared-egress signal)

## Build steps (later)

1. Persist enrichment tables (run the notebook with a real `enrichment_schema`).
2. Create the space (Genie UI or REST API) with the title/description/instructions above, add the
   tables, and save the Example SQL as trusted queries.
3. Validate with the sample questions; iterate on instructions until answers are grounded.
