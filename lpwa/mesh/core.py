# -*- coding: utf-8 -*-
"""
mesh/core.py  ―  ルーティング処理の共通インターフェース

ルーティングのアルゴリズム（Router）を、時刻・タイマー・無線・乱数から切り離す。
Router は NodeContext 経由でしか外界に触れないので、同じコードを

    - sim/        : 離散イベントシミュレータ（仮想時刻・仮想無線）
    - realtime.py : 実機（E220-900JP / time.monotonic）

のどちらでも動かせる。Router はイベント駆動で書く:
受信は on_receive()、遅延処理は ctx.call_later()、送信は ctx.transmit()。
ブロッキングする処理（sleep・受信待ち）を Router の中に書かないこと。
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass(frozen=True)
class MessageKey:
    """メッセージの識別子（送信元 + msg_id）。中継されても変わらない。"""
    src: int
    msg_id: int


@dataclass(frozen=True)
class TxMeta:
    """送信パケットの付帯情報。シミュレータの集計に使う（電波には乗らない）。

    kind: "origin"（自分が出したメッセージ）/ "relay"（中継）/ "announce" / "ack" など
    """
    kind: str
    key: MessageKey | None = None


@dataclass(frozen=True)
class Delivery:
    """アプリ層へ渡すメッセージ。"""
    src: int
    dest: int
    msg_id: int
    payload: bytes
    hops: int | None = None   # 何ホップで届いたか（分かる場合）


class TimerHandle(Protocol):
    def cancel(self) -> None: ...


class NodeContext(Protocol):
    """Router から見たノードの環境。"""
    address: int

    def now(self) -> float: ...
    def random(self) -> random.Random: ...
    def call_later(self, delay: float, fn: Callable[[], None]) -> TimerHandle: ...
    def transmit(self, pkt: bytes, meta: TxMeta) -> None: ...
    def deliver(self, delivery: Delivery) -> None: ...


class RadioPort(Protocol):
    """実機の無線（lora_send / lora_recv）を抽象化したもの。"""

    def send(self, pkt: bytes) -> None: ...
    def recv(self, timeout: float) -> bytes | None: ...

    @property
    def last_rssi(self) -> int | None: ...


class Router(Protocol):
    """ルーティングアルゴリズム。ROUTERS に登録して sim / realtime から使う。"""
    name: str

    def start(self) -> None: ...
    def send(self, dest: int, payload: bytes) -> MessageKey: ...
    def on_receive(self, pkt: bytes, rssi: int | None) -> None: ...


RouterFactory = Callable[[NodeContext], Router]
