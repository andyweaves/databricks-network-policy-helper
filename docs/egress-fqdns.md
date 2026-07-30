# Egress FQDNs

Hosts the notebook may call out to. If it runs behind egress controls (corporate proxy allow-list
or **Databricks Serverless Egress Control / SEG**), allow the ones matching your widget choices.
Feeds you deselect (`threat_feeds`) or RDAP if disabled (`enable_rdap`) are not called. The notebook
also prints this table at runtime.

| FQDN | Purpose | Triggered by |
|---|---|---|
| `www.spamhaus.org` | Spamhaus DROP v4/v6 | feed `spamhaus_drop` |
| `check.torproject.org` | Tor exit list | feed `tor_exit` |
| `raw.githubusercontent.com` | FireHOL level1 + IPsum | feeds `firehol_level1`, `ipsum` |
| `feeds.dshield.org` | SANS ISC DShield | feed `dshield` |
| `cinsscore.com` | CINS CI Army | feed `cins_ci_army` |
| `ip-ranges.amazonaws.com` | AWS ranges | cloud ranges |
| `www.gstatic.com` | GCP ranges | cloud ranges |
| `docs.oracle.com` | Oracle ranges | cloud ranges |
| `www.microsoft.com` | Azure Service Tags page (URL discovery) | cloud ranges |
| `download.microsoft.com` | Azure Service Tags JSON | cloud ranges |
| `rdap.org` | RDAP bootstrap (redirects to RIR servers) | RDAP enrichment |
| RIR RDAP servers (e.g. `rdap.arin.net`, `rdap.db.ripe.net`) | followed from rdap.org referrals | RDAP enrichment |
| `pypi.org`, `files.pythonhosted.org` | `pip install databricks-sdk` | SDK install cell |

Databricks control-plane / account SDK endpoints are reached over normal workspace/account
connectivity and are not listed here.
