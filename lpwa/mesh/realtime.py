# -*- coding: utf-8 -*-
"""
mesh/realtime.py  ―  Router を実機（E220-900JP）で動かすためのランタイム

    port = E220Port()
    node = RealtimeNode(port, lambda ctx: FloodRouterV1(ctx), on_deliver=print)
    while True:
        node.poll()

ブリッジ・node_mesh.py はまだこれを使っていない（Phase 3 で切り替える）。
"""
from __future__ import annotations

import heapq
import itertools
import random
import time
from typing import Callable

from .core import Delivery, RadioPort, RouterFactory, TxMeta


class E220Port:
    """lora_e220_b の lora_send / lora_recv を RadioPort として使う。"""

    def __init__(self):
        import lora_e220_b   # 実機でだけ必要（シリアルと setting.ini を読む）
        self._radio = lora_e220_b
        self.address = lora_e220_b.SELF_ADDRESS

    def send(self, pkt: bytes) -> None:
        self._radio.lora_send(pkt)

    def recv(self, timeout: float) -> bytes | None:
        return self._radio.lora_recv(timeout)

    @property
    def last_rssi(self) -> int | None:
        return self._radio.LAST_RSSI


class _Timer:
    __slots__ = ("cancelled",)

    def __init__(self):
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class RealtimeNode:
    """NodeContext の実時間版。poll() を回し続けるとタイマーと受信を処理する。"""

    def __init__(self, port: RadioPort, router_factory: RouterFactory,
                 address: int | None = None,
                 on_deliver: Callable[[Delivery], None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 rng: random.Random | None = None):
        self.port = port
        self.address = address if address is not None else getattr(port, "address")
        self._clock = clock
        self._rng = rng or random.Random()
        self._on_deliver = on_deliver
        self._timers: list[tuple[float, int, _Timer, Callable[[], None]]] = []
        self._seq = itertools.count()
        self.router = router_factory(self)
        self.router.start()

    # ── NodeContext ─────────────────────────────────────────
    def now(self) -> float:
        return self._clock()

    def random(self) -> random.Random:
        return self._rng

    def call_later(self, delay: float, fn: Callable[[], None]) -> _Timer:
        timer = _Timer()
        heapq.heappush(self._timers, (self.now() + max(0.0, delay), next(self._seq), timer, fn))
        return timer

    def transmit(self, pkt: bytes, meta: TxMeta) -> None:
        self.port.send(pkt)

    def deliver(self, delivery: Delivery) -> None:
        if self._on_deliver:
            self._on_deliver(delivery)

    # ── ループ ──────────────────────────────────────────────
    def poll(self, max_wait: float = 0.5) -> None:
        """期限の来たタイマーを実行し、次のタイマーまで（最大 max_wait 秒）受信を待つ。"""
        self._run_due_timers()
        wait = max_wait
        if self._timers:
            wait = min(wait, max(0.0, self._timers[0][0] - self.now()))
        pkt = self.port.recv(wait)
        if pkt:
            self.router.on_receive(pkt, self.port.last_rssi)
        self._run_due_timers()

    def _run_due_timers(self) -> None:
        while self._timers and self._timers[0][0] <= self.now():
            _, _, timer, fn = heapq.heappop(self._timers)
            if not timer.cancelled:
                fn()
