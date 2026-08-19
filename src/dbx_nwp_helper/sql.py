"""SQL warehouse resolution + query execution.

The CLI needs a running SQL warehouse to query the system tables. This module:
  1. Resolves the warehouse http_path — an explicit `--warehouse-http-path`, else it reuses an
     existing warehouse by name, else it creates a small serverless one (and starts it).
  2. Connects with `databricks-sql-connector`, authenticating via the SDK's unified auth (so the
     same profile/env drives both the SDK and the SQL connection — no separate token handling).
  3. Runs a query and returns a pandas DataFrame, with Spark `array<>` columns coming back as plain
     Python lists (the connector already does this via Arrow).
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import pandas as pd
from databricks import sql as dbsql
from databricks.sdk.service.sql import (
    CreateWarehouseRequestWarehouseType,
    EndpointInfoWarehouseType,
    State,
)

from . import auth
from .config import Connection
from .console import banner, status


def _http_path_for(warehouse_id: str) -> str:
    return f"/sql/1.0/warehouses/{warehouse_id}"


def resolve_warehouse(conn: Connection) -> str:
    """Return an http_path to a usable SQL warehouse, creating/starting one if needed.

    Precedence: an explicit http_path on the connection wins; otherwise reuse a warehouse whose
    name matches `conn.warehouse_name`; otherwise create a serverless warehouse with that name."""
    if conn.warehouse_http_path:
        return conn.warehouse_http_path

    w = auth.workspace_client(conn)
    existing = None
    for wh in w.warehouses.list():
        if wh.name == conn.warehouse_name:
            existing = wh
            break

    if existing is not None:
        banner("info", f"Reusing SQL warehouse '{existing.name}' ({existing.id}).")
        if existing.state not in (State.RUNNING, State.STARTING):
            with status(f"Starting warehouse '{existing.name}'…"):
                w.warehouses.start(existing.id).result()
        return _http_path_for(existing.id)

    banner("info", f"No warehouse named '{conn.warehouse_name}' — creating a serverless one.")
    with status("Creating + starting serverless SQL warehouse…"):
        created = w.warehouses.create(
            name=conn.warehouse_name,
            cluster_size="2X-Small",
            max_num_clusters=1,
            auto_stop_mins=10,
            enable_serverless_compute=True,
            warehouse_type=CreateWarehouseRequestWarehouseType.PRO,
        ).result()
    banner("success", f"Created warehouse '{conn.warehouse_name}' ({created.id}).")
    return _http_path_for(created.id)


@contextlib.contextmanager
def connection(conn: Connection, http_path: str) -> Iterator[dbsql.client.Connection]:
    """Open a databricks-sql-connector connection authenticated via unified auth."""
    cfg = auth.workspace_client(conn).config
    hostname = cfg.host.replace("https://", "").replace("http://", "").rstrip("/")
    c = dbsql.connect(
        server_hostname=hostname,
        http_path=http_path,
        # cfg.authenticate is a header factory; the connector calls it per-request.
        credentials_provider=lambda: cfg.authenticate,
    )
    try:
        yield c
    finally:
        c.close()


def query(c: dbsql.client.Connection, sql_text: str) -> pd.DataFrame:
    """Run a query and return a pandas DataFrame (Arrow-backed; array columns become lists)."""
    with c.cursor() as cur:
        cur.execute(sql_text)
        return cur.fetchall_arrow().to_pandas()


def warehouse_is_serverless(wh) -> bool:
    """Best-effort check used only for display."""
    return getattr(wh, "warehouse_type", None) in (
        EndpointInfoWarehouseType.PRO,
        CreateWarehouseRequestWarehouseType.PRO,
    ) and bool(getattr(wh, "enable_serverless_compute", False))
