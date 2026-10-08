# -*- coding: utf-8 -*-
"""
mesh/links.py  ―  リンク品質表と最小コスト経路（Phase 4）

見聞きしたパケットの path には「各中継ノードが受信したときの電波の余裕（dB）」が入っている。
それを集めて「ノード a と b の間のリンク品質」の表を作り（指数移動平均）、
送るたびにこの表の上で最小コストの経路をダイクストラ法で求める。

宛先ごとに「どこかのフラッディングが通った道筋」を 1 本覚えるより、別々のパケットで
知ったリンクを組み合わせられるので、経路の質がよい。リンクは双方向で同じ品質とみなす。
"""
from __future__ import annotations

import heapq
from typing import Callable

from .packet import LINK_Q_UNKNOWN

_FAILED = -1.0     # 届かなかったリンクの印（次に観測されるまで経路に使わない）


class LinkTable:
    def __init__(self, ttl: float = 1800.0, alpha: float = 0.3):
        self.ttl = ttl
        self.alpha = alpha
        self._q: dict[tuple[int, int], tuple[float, float]] = {}   # (a, b) a<b → (品質, 更新時刻)
        self._heard: dict[int, float] = {}                          # ノード → 最後に送信を確認した時刻

    @staticmethod
    def _key(a: int, b: int) -> tuple[int, int]:
        return (a, b) if a < b else (b, a)

    def observe(self, a: int, b: int, q: int, now: float) -> None:
        """リンク a–b を品質 q（dB）で使えたことを記録する（a が送信し b が受信した）。"""
        self._heard[a] = now
        if q == LINK_Q_UNKNOWN or a == b:
            return
        k = self._key(a, b)
        cur = self._q.get(k)
        if cur is None or now - cur[1] > self.ttl or cur[0] < 0:
            v = float(q)
        else:
            v = (1 - self.alpha) * cur[0] + self.alpha * q
        self._q[k] = (v, now)

    def fail(self, a: int, b: int, now: float) -> None:
        """リンク a–b で届かなかった。次に使えたと観測されるまで経路に使わない。"""
        k = self._key(a, b)
        if k in self._q:
            self._q[k] = (_FAILED, now)

    def fail_node(self, n: int, now: float) -> None:
        """ノード n が止まったとみなし、n につながるリンクをすべて使わない。"""
        for k in [k for k in self._q if n in k]:
            self._q[k] = (_FAILED, now)

    def last_heard(self, n: int) -> float | None:
        return self._heard.get(n)

    def degrade(self, a: int, b: int, now: float) -> None:
        """どこで失敗したか分からない経路のリンクを、少しずつ悪く見積もる。"""
        k = self._key(a, b)
        cur = self._q.get(k)
        if cur is not None and cur[0] >= 0:
            self._q[k] = (cur[0] * 0.5, cur[1])

    def quality(self, a: int, b: int, now: float) -> float | None:
        cur = self._q.get(self._key(a, b))
        if cur is None or now - cur[1] > self.ttl or cur[0] < 0:
            return None
        return cur[0]

    def __len__(self) -> int:
        return len(self._q)

    def best_path(self, src: int, dst: int, now: float, cost_fn: Callable[[int], float],
                  max_links: int) -> tuple[tuple[int, ...], float] | None:
        """src → dst の最小コスト経路（中継ノード列, コスト）。リンク数が max_links を超えるなら None。"""
        adj: dict[int, list[tuple[int, float]]] = {}
        for (a, b), (v, t) in self._q.items():
            if now - t > self.ttl or v < 0:
                continue
            c = cost_fn(int(round(v)))
            adj.setdefault(a, []).append((b, c))
            adj.setdefault(b, []).append((a, c))
        dist = {src: 0.0}
        prev: dict[int, int] = {}
        pq = [(0.0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if u == dst:
                break
            if d > dist.get(u, float("inf")):
                continue
            for v, c in adj.get(u, ()):
                nd = d + c
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if dst not in dist:
            return None
        nodes = [dst]
        while nodes[-1] != src:
            nodes.append(prev[nodes[-1]])
        nodes.reverse()
        if len(nodes) - 1 > max_links:
            return None
        return tuple(nodes[1:-1]), dist[dst]
