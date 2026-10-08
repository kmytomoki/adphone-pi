# -*- coding: utf-8 -*-
"""
mesh/nodedb.py  ―  他ノードの情報（ROUTING_PLAN.md 3.4・4 章）

    addr → 公開鍵・役割・名前・最終受信・何ホップ先か
    addr → 直接届く隣ノードとしての RSSI

鍵は TOFU（Trust On First Use）で固定する: 最初に受け取った鍵を信用し、
同じアドレスから別の鍵の ANNOUNCE が来ても上書きしない（なりすまし対策）。
ノードを入れ替えた・鍵ファイルを作り直した場合は、各ノードで forget する:

    python3 -m mesh.nodedb /var/lib/adren/nodedb.json list
    python3 -m mesh.nodedb /var/lib/adren/nodedb.json forget 5
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass

from .identity import AnnounceInfo

NEIGHBOR_TTL_SEC = 1800.0     # この時間以上聞こえない隣ノードは隣とみなさない


@dataclass
class NodeInfo:
    addr: int
    ed_pub: bytes
    dh_pub: bytes
    role: str = "CLIENT"
    name: str = ""
    last_heard: float = 0.0
    hops_away: int | None = None


@dataclass
class Neighbor:
    rssi: int | None
    last_heard: float


class NodeDB:
    def __init__(self, path: str | None = None):
        self.path = path
        self.nodes: dict[int, NodeInfo] = {}
        self.neighbors: dict[int, Neighbor] = {}
        self.key_conflicts: dict[int, AnnounceInfo] = {}   # TOFU で拒否した ANNOUNCE
        if path and os.path.exists(path):
            self._load()

    # ── 鍵 ──────────────────────────────────────────────────
    def learn(self, addr: int, info: AnnounceInfo, now: float) -> str:
        """ANNOUNCE の内容を登録する。

        Returns: "new"（初めて）/ "known"（同じ鍵）/ "conflict"（別の鍵。登録しない）
        """
        cur = self.nodes.get(addr)
        if cur is None:
            self.nodes[addr] = NodeInfo(addr, info.ed_pub, info.dh_pub, info.role, info.name, now)
            self.save()
            return "new"
        if (cur.ed_pub, cur.dh_pub) != (info.ed_pub, info.dh_pub):
            self.key_conflicts[addr] = info
            return "conflict"
        cur.last_heard = now
        if (cur.role, cur.name) != (info.role, info.name):
            cur.role, cur.name = info.role, info.name
            self.save()
        return "known"

    def forget(self, addr: int) -> bool:
        """登録済みの鍵を消す（次に来た ANNOUNCE を信用する）。"""
        found = self.nodes.pop(addr, None) is not None
        self.key_conflicts.pop(addr, None)
        if found:
            self.save()
        return found

    def get(self, addr: int) -> NodeInfo | None:
        return self.nodes.get(addr)

    # ── 受信のたびの更新 ────────────────────────────────────
    def heard(self, src: int, last_hop: int, hops: int, rssi: int | None, now: float) -> None:
        node = self.nodes.get(src)
        if node is not None:
            stale = now - node.last_heard > 600
            if node.hops_away is None or hops <= node.hops_away or stale:
                node.hops_away = hops
            node.last_heard = now
        self.neighbors[last_hop] = Neighbor(rssi, now)

    def has_router_neighbor(self, now: float) -> bool:
        return any(self.nodes.get(a) is not None and self.nodes[a].role == "ROUTER"
                   and now - n.last_heard < NEIGHBOR_TTL_SEC
                   for a, n in self.neighbors.items())

    # ── 永続化 ──────────────────────────────────────────────
    def save(self) -> None:
        if not self.path:
            return
        data = {str(a): {**asdict(n), "ed_pub": n.ed_pub.hex(), "dh_pub": n.dh_pub.hex()}
                for a, n in self.nodes.items()}
        d = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".nodedb-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def _load(self) -> None:
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        for a, v in data.items():
            v["ed_pub"] = bytes.fromhex(v["ed_pub"])
            v["dh_pub"] = bytes.fromhex(v["dh_pub"])
            self.nodes[int(a)] = NodeInfo(**v)


def _main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("list", "forget"):
        print("使い方: python3 -m mesh.nodedb <nodedb.json> list | forget <addr>")
        return 1
    db = NodeDB(argv[0])
    if argv[1] == "list":
        for a, n in sorted(db.nodes.items()):
            print("0x{:04X}  {:<11} {:<16} 指紋={}".format(a, n.role, n.name, n.ed_pub[:8].hex()))
        return 0
    addr = int(argv[2], 0)
    print("削除しました" if db.forget(addr) else "登録されていません")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
