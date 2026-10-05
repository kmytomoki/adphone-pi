# -*- coding: utf-8 -*-
"""
sim/engine.py  ―  離散イベントシミュレータ

各ノードは mesh.core.NodeContext を実装し、その上で Router を動かす。
時刻は仮想時刻なので、数時間分の通信も一瞬で終わる。

送信の流れ（1 ノードは同時に 1 パケットしか送れない）:
    transmit() → 送信キュー → UART 転送 → （キャリアセンス）→ 電波送信
    → 送信終了時に各ノードの受信可否を判定 → UART 転送 → Router.on_receive()
"""
from __future__ import annotations

import heapq
import itertools
import random
from collections import deque
from typing import Callable

from mesh.core import Delivery, RouterFactory, TxMeta

from .metrics import Metrics
from .radio import Medium, RadioParams, Transmission

_LBT_MAX_TRIES = 10


class _Timer:
    __slots__ = ("cancelled",)

    def __init__(self):
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class SimNode:
    """シミュレータ上のノード（NodeContext の実装）。"""

    def __init__(self, sim: "Simulator", address: int, rng: random.Random):
        self.sim = sim
        self.address = address
        self.alive = True
        self.router = None
        self._rng = rng
        self._txq: deque[tuple[bytes, TxMeta]] = deque()
        self._busy = False

    # ── NodeContext ─────────────────────────────────────────
    def now(self) -> float:
        return self.sim.now

    def random(self) -> random.Random:
        return self._rng

    def call_later(self, delay: float, fn: Callable[[], None]) -> _Timer:
        return self.sim.schedule(self.sim.now + max(0.0, delay), lambda: self.alive and fn())

    def transmit(self, pkt: bytes, meta: TxMeta) -> None:
        if not self.alive:
            return
        self._txq.append((pkt, meta))
        self._kick()

    def deliver(self, delivery: Delivery) -> None:
        self.sim.metrics.on_deliver(self.address, delivery, self.sim.now)

    # ── 送受信 ──────────────────────────────────────────────
    def kill(self) -> None:
        self.alive = False
        self._txq.clear()

    def _kick(self) -> None:
        if self._busy or not self._txq:
            return
        self._busy = True
        pkt, meta = self._txq.popleft()
        uart = self.sim.params.uart_time(len(pkt))
        self.sim.schedule(self.sim.now + uart, lambda: self._start_air(pkt, meta, 0))

    def _start_air(self, pkt: bytes, meta: TxMeta, tries: int) -> None:
        if not self.alive:
            self._busy = False
            return
        sim = self.sim
        if tries < _LBT_MAX_TRIES and sim.medium.channel_busy(self.address, sim.now):
            sim.metrics.lbt_deferrals += 1
            sim.schedule(sim.now + self._rng.uniform(0.01, 0.1),
                         lambda: self._start_air(pkt, meta, tries + 1))
            return
        air = sim.params.airtime(len(pkt))
        tx = Transmission(self.address, pkt, meta, sim.now, sim.now + air)
        sim.medium.begin(tx)
        sim.metrics.on_tx(self.address, meta, air)
        sim.schedule(tx.end, lambda: self._end_air(tx))

    def _end_air(self, tx: Transmission) -> None:
        sim = self.sim
        uart = sim.params.uart_time(len(tx.pkt))
        for r, rssi, reason in sim.medium.receptions(tx, lambda a: sim.nodes[a].alive):
            sim.metrics.on_rx_result(reason)
            if rssi is not None:
                node = sim.nodes[r]
                sim.schedule(sim.now + uart,
                             lambda node=node, rssi=rssi: node._on_air_rx(tx.pkt, rssi))
        self._busy = False
        self._kick()

    def _on_air_rx(self, pkt: bytes, rssi: int) -> None:
        if self.alive:
            self.router.on_receive(pkt, rssi)


class Simulator:
    def __init__(self, positions: dict[int, tuple[float, float]], router_factory: RouterFactory,
                 params: RadioParams | None = None, seed: int = 0):
        self.params = params or RadioParams()
        self.now = 0.0
        self.metrics = Metrics()
        rng = random.Random(seed)
        self.medium = Medium(positions, self.params, random.Random(rng.getrandbits(32)))
        self._queue: list[tuple[float, int, _Timer, Callable[[], None]]] = []
        self._seq = itertools.count()
        self.nodes = {a: SimNode(self, a, random.Random(rng.getrandbits(32)))
                      for a in sorted(positions)}
        for node in self.nodes.values():
            node.router = router_factory(node)
        for node in self.nodes.values():
            node.router.start()

    def schedule(self, at: float, fn: Callable[[], None]) -> _Timer:
        timer = _Timer()
        heapq.heappush(self._queue, (at, next(self._seq), timer, fn))
        return timer

    def run(self, until: float) -> None:
        while self._queue and self._queue[0][0] <= until:
            at, _, timer, fn = heapq.heappop(self._queue)
            if timer.cancelled:
                continue
            self.now = at
            fn()
        self.now = until

    def hop_distances(self, src: int) -> dict[int, int]:
        """平均 RSSI が感度以上のリンクだけでたどった、src からの最短ホップ数（生存ノードのみ）。"""
        dist = {src: 0}
        frontier = [src]
        while frontier:
            nxt = []
            for a in frontier:
                for b in self.medium.neighbors(a):
                    if b not in dist and self.nodes[b].alive:
                        dist[b] = dist[a] + 1
                        nxt.append(b)
            frontier = nxt
        return dist
