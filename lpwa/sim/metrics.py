# -*- coding: utf-8 -*-
"""sim/metrics.py  ―  シミュレーション結果の集計"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from mesh.core import Delivery, MessageKey, TxMeta

BROADCAST_ADDR = 0xFFFF


@dataclass
class MessageRecord:
    src: int
    dest: int
    sent_at: float
    expected: frozenset[int]          # 届くべきノード（送信時点で生きている相手）
    hop_distance: int | None          # 宛先までの最短ホップ数（ユニキャストのみ）
    receivers: dict[int, float] = field(default_factory=dict)   # ノード → 受信時刻
    tx_count: int = 0                 # このメッセージのために送られたパケット数（中継・ACK 含む）
    airtime: float = 0.0              # そのパケットの電波の占有時間の合計（秒）

    @property
    def is_broadcast(self) -> bool:
        return self.dest == BROADCAST_ADDR


class Metrics:
    def __init__(self):
        self.messages: dict[MessageKey, MessageRecord] = {}
        self.tx_by_kind: Counter[str] = Counter()
        self.rx_results: Counter[str] = Counter()
        self.airtime_by_node: defaultdict[int, float] = defaultdict(float)
        self.lbt_deferrals = 0

    def on_origin(self, key: MessageKey, record: MessageRecord) -> None:
        self.messages[key] = record

    def on_tx(self, sender: int, meta: TxMeta, airtime: float) -> None:
        self.tx_by_kind[meta.kind] += 1
        self.airtime_by_node[sender] += airtime
        rec = self.messages.get(meta.key) if meta.key else None
        if rec is not None:
            rec.tx_count += 1
            rec.airtime += airtime

    def on_rx_result(self, reason: str) -> None:
        self.rx_results[reason] += 1

    def on_deliver(self, node: int, delivery: Delivery, now: float) -> None:
        rec = self.messages.get(MessageKey(delivery.src, delivery.msg_id))
        if rec is not None:
            rec.receivers.setdefault(node, now)

    def summary(self, duration: float, ttl: int | None = None) -> dict:
        uni = [r for r in self.messages.values() if not r.is_broadcast]
        bc = [r for r in self.messages.values() if r.is_broadcast]
        delivered = [r for r in uni if r.dest in r.receivers]
        latencies = sorted(r.receivers[r.dest] - r.sent_at for r in delivered)
        reach = [len(r.expected & r.receivers.keys()) / len(r.expected) for r in bc if r.expected]
        beyond_ttl = [r for r in uni if ttl is not None and r.hop_distance is not None
                      and r.hop_distance > ttl]
        unreachable = [r for r in uni if r.hop_distance is None]
        within = [r for r in uni if r not in beyond_ttl and r not in unreachable]

        def mean(xs):
            return sum(xs) / len(xs) if xs else None

        def pct(xs, q):
            if not xs:
                return None
            return xs[min(len(xs) - 1, int(q * len(xs)))]

        return {
            "unicast_count": len(uni),
            "unicast_delivery": len(delivered) / len(uni) if uni else None,
            # TTL の圏内にある宛先だけで見た到達率（アルゴリズム自体の性能）
            "unicast_delivery_within_ttl":
                sum(1 for r in within if r.dest in r.receivers) / len(within) if within else None,
            "unicast_beyond_ttl": len(beyond_ttl) / len(uni) if uni else None,
            "unicast_unreachable": len(unreachable) / len(uni) if uni else None,
            "broadcast_count": len(bc),
            "broadcast_reach": mean(reach),
            "tx_per_unicast": mean([r.tx_count for r in uni]),
            "tx_per_broadcast": mean([r.tx_count for r in bc]),
            "airtime_per_unicast": mean([r.airtime for r in uni]),
            "airtime_per_broadcast": mean([r.airtime for r in bc]),
            "latency_p50": pct(latencies, 0.5),
            "latency_p95": pct(latencies, 0.95),
            "tx_by_kind": dict(self.tx_by_kind),
            "rx_results": dict(self.rx_results),
            "collision_rate": (self.rx_results["collision"] / sum(self.rx_results.values())
                               if self.rx_results else None),
            "max_airtime_per_hour": (max(self.airtime_by_node.values()) / duration * 3600
                                     if self.airtime_by_node and duration > 0 else 0.0),
            "lbt_deferrals": self.lbt_deferrals,
        }
