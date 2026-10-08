# -*- coding: utf-8 -*-
"""
mesh/config.py  ―  setting.ini から v2 ルーターを組み立てる

setting.ini [E220-900JP] で使うキー:
    own_address           自ノードのアドレス（必須）
    hop_limit             中継回数の上限（既定 3 = 最大 4 ホップ）
    role                  CLIENT / ROUTER / CLIENT_MUTE（既定 CLIENT）
    node_name             ANNOUNCE で名乗る名前（UTF-8 で 16 バイトまで）
    announce_interval_sec 定期 ANNOUNCE の間隔（既定 900）
    group_key_hex         グループ鍵（64 桁 hex）。空ならブロードキャストを送れない
    group_key_id          グループ鍵の世代（0〜255）
    sf / bw               E220 の拡散率 / 帯域（kHz）。中継の待ち時間の計算に使う
    routing               routed（既定。ACK・経路学習・DIRECT。Phase 4）/ flood（管理型フラッディングのみ。Phase 3）
    airtime_budget_sec    1 時間あたりの送信時間の上限（秒, 既定 360 は仮の値）。80% を超えたら中継を控える
    state_dir             鍵ファイルと NodeDB の置き場所（既定: setting.ini と同じ場所の state/）
"""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from typing import Callable

from .identity import ROLES, Identity, load_group_key
from .nodedb import NodeDB
from .reliable import ReliableRouter
from .router import ManagedFloodRouter

ROUTING = ("routed", "flood")

SECTION = "E220-900JP"


@dataclass
class MeshConfig:
    address: int
    hop_limit: int = 3
    role: str = "CLIENT"
    node_name: str = ""
    announce_interval: float = 900.0
    group_key: bytes | None = None
    group_key_id: int = 0
    sf: int = 7
    bw_hz: int = 125_000
    state_dir: str = "state"
    routing: str = "routed"
    airtime_budget: float = 360.0

    @property
    def identity_path(self) -> str:
        return os.path.join(self.state_dir, "identity.key")

    @property
    def nodedb_path(self) -> str:
        return os.path.join(self.state_dir, "nodedb.json")


def load_mesh_config(cfg: configparser.ConfigParser, config_path: str) -> MeshConfig:
    g = lambda key, default: cfg.get(SECTION, key, fallback=default)  # noqa: E731
    role = g("role", "CLIENT").strip().upper()
    if role not in ROLES:
        raise ValueError("role は {} のいずれか（現在 {}）".format("/".join(ROLES), role))
    routing = g("routing", "routed").strip().lower()
    if routing not in ROUTING:
        raise ValueError("routing は {} のいずれか（現在 {}）".format("/".join(ROUTING), routing))
    gk = load_group_key(g("group_key_hex", ""), int(g("group_key_id", "0")))
    state_dir = g("state_dir", "").strip() or os.path.join(
        os.path.dirname(os.path.abspath(config_path)), "state")
    return MeshConfig(
        address=int(cfg.get(SECTION, "own_address")),
        hop_limit=int(g("hop_limit", "3")),
        role=role,
        node_name=g("node_name", "").strip(),
        announce_interval=float(g("announce_interval_sec", "900")),
        group_key=gk[0] if gk else None,
        group_key_id=gk[1] if gk else 0,
        sf=int(g("sf", "7")),
        bw_hz=int(float(g("bw", "125")) * 1000),
        state_dir=state_dir,
        routing=routing,
        airtime_budget=float(g("airtime_budget_sec", "360")),
    )


def make_router_factory(mc: MeshConfig, on_event: Callable[[str, dict], None] | None = None):
    """(router_factory, identity, nodedb) を返す。鍵ファイルがなければ作る。"""
    identity = Identity.load_or_create(mc.identity_path)
    nodedb = NodeDB(mc.nodedb_path)

    common = dict(identity=identity, nodedb=nodedb, role=mc.role, hop_limit=mc.hop_limit,
                  group_key=mc.group_key, group_key_id=mc.group_key_id, node_name=mc.node_name,
                  announce_interval=mc.announce_interval, sf=mc.sf, bw_hz=mc.bw_hz,
                  on_event=on_event)

    def factory(ctx):
        if mc.routing == "flood":
            return ManagedFloodRouter(ctx, **common)
        return ReliableRouter(ctx, airtime_budget=mc.airtime_budget, **common)

    return factory, identity, nodedb
