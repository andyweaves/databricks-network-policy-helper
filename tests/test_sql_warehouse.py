"""Unit tests for warehouse resolution — in particular honouring --warehouse-size when reusing an
existing same-named warehouse (resize, then start). Uses fakes; no Databricks/network."""

from __future__ import annotations

import types

from databricks.sdk.service.sql import State

from dbx_nwp_helper import sql
from dbx_nwp_helper.config import Connection


def _wh(**kw):
    base = dict(
        id="wid",
        name="dbx-nwp-helper",
        state=State.STOPPED,
        cluster_size="2X-Small",
        auto_stop_mins=10,
        min_num_clusters=1,
        max_num_clusters=1,
        enable_photon=None,
        enable_serverless_compute=True,
        spot_instance_policy=None,
        channel=None,
        tags=None,
        instance_profile_arn=None,
        warehouse_type=None,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


class _Wait:
    def __init__(self, on_result=None):
        self._on = on_result

    def result(self):
        if self._on:
            self._on()
        return None


class _WarehousesAPI:
    def __init__(self, wh):
        self._wh = wh
        self.edit_calls = []
        self.start_calls = []

    def list(self):
        return [self._wh]

    def get(self, id):
        return self._wh

    def edit(self, id, **kw):
        self.edit_calls.append((id, kw))
        self._wh.cluster_size = kw.get("cluster_size", self._wh.cluster_size)
        # editing an active warehouse restarts it → RUNNING once the waiter resolves
        return _Wait(lambda: setattr(self._wh, "state", State.RUNNING))

    def start(self, id):
        self.start_calls.append(id)
        return _Wait(lambda: setattr(self._wh, "state", State.RUNNING))


def _patch_ws(monkeypatch, wh):
    api = _WarehousesAPI(wh)
    monkeypatch.setattr(
        "dbx_nwp_helper.auth.workspace_client",
        lambda conn: types.SimpleNamespace(warehouses=api),
    )
    return api


def test_reuse_resizes_stopped_warehouse_then_starts(monkeypatch):
    wh = _wh(state=State.STOPPED, cluster_size="2X-Small")
    api = _patch_ws(monkeypatch, wh)
    path = sql.resolve_warehouse(Connection(warehouse_size="Medium"))
    assert path == "/sql/1.0/warehouses/wid"
    # resized to the requested size...
    assert api.edit_calls and api.edit_calls[0][1]["cluster_size"] == "Medium"
    # ...and started (it was stopped)
    assert api.start_calls == ["wid"]


def test_reuse_resizes_running_warehouse_without_extra_start(monkeypatch):
    # a running warehouse is restarted by the edit; we wait for RUNNING, so no separate start needed
    wh = _wh(state=State.RUNNING, cluster_size="Small")
    api = _patch_ws(monkeypatch, wh)
    sql.resolve_warehouse(Connection(warehouse_size="Medium"))
    assert api.edit_calls[0][1]["cluster_size"] == "Medium"
    assert api.start_calls == []  # edit-restart already left it RUNNING


def test_reuse_same_size_does_not_resize(monkeypatch):
    wh = _wh(state=State.RUNNING, cluster_size="Medium")
    api = _patch_ws(monkeypatch, wh)
    sql.resolve_warehouse(Connection(warehouse_size="Medium"))
    assert api.edit_calls == []  # already the right size
    assert api.start_calls == []  # already running


def test_reuse_resize_failure_falls_back_to_current_size(monkeypatch):
    wh = _wh(state=State.STOPPED, cluster_size="2X-Small")
    api = _WarehousesAPI(wh)

    def boom(id, **kw):
        raise RuntimeError("no permission to edit warehouse")

    api.edit = boom
    monkeypatch.setattr(
        "dbx_nwp_helper.auth.workspace_client", lambda conn: types.SimpleNamespace(warehouses=api)
    )
    # must not raise — resize is best-effort; still returns a usable path and starts the warehouse
    path = sql.resolve_warehouse(Connection(warehouse_size="Medium"))
    assert path == "/sql/1.0/warehouses/wid"
    assert api.start_calls == ["wid"]
