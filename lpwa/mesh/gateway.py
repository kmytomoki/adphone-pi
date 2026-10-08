# -*- coding: utf-8 -*-
"""
mesh/gateway.py  ―  スマホ（BLE）とメッシュのあいだの処理（Phase 5）

- BLE から来たチャンクを組み立て、MSG はメッシュへ送り、配送状態（STATUS）を返す
- メッシュから届いたメッセージは受信箱（store.inbox）に保存し、MSG としてスマホへ通知する
- スマホは接続直後に HELLO（client_id と最後に受け取った連番）を送る。Pi は INFO・取りこぼした
  メッセージ・そのスマホが送ったメッセージの最新の配送状態を返す
- 届かなかったメッセージは送信箱に残し、間隔を延ばしながら保持期間まで送り直す（蓄積転送）

すべてメッシュのスレッド（RealtimeNode のループ）で動かす。BLE のコールバックからは
RealtimeNode.post() で渡すこと。スマホへの通知は notify(チャンク) を呼ぶだけで、
BLE への書き出し（とその速さの調整）は呼び出し側（ブリッジ）が行う。

時刻: 送信箱・受信箱に残す時刻は時計（wall, 既定 time.time）で記録する（再起動をまたぐため）。
タイマーの予約だけは ctx（単調時計）を使う。
"""
from __future__ import annotations

import json
import logging
import struct
import time
from typing import Callable

from . import bleproto as B
from . import packet as P
from .core import Delivery, NodeContext
from .store import OutboxItem, Store

log = logging.getLogger("mesh.gateway")

_TICK_SEC = 30.0
_PURGE_SEC = 600.0


class MeshGateway:
    def __init__(self, ctx: NodeContext, router, store: Store, notify: Callable[[bytes], None],
                 info: dict | None = None, default_dest: int = B.BROADCAST,
                 retry_base: float = 300.0, retry_max: float = 3600.0, history_limit: int = 50,
                 wall: Callable[[], float] = time.time):
        self.ctx = ctx
        self.wall = wall
        self.router = router
        self.store = store
        self.notify = notify
        self.info = dict(info or {})
        self.default_dest = default_dest
        self.retry_base = retry_base
        self.retry_max = retry_max
        self.history_limit = history_limit
        self._reasm = B.Reassembler()
        self._clients: dict[int, bytes] = {}       # BLE の stream → client_id
        self._key_wait = False
        self._last_purge = -1e9

    @property
    def addr(self) -> int:
        return self.ctx.address

    def start(self) -> None:
        """前回の続き（Pi の再起動前に送れていなかったもの）を整理して、定期処理を始める。"""
        self.store.recover(self.wall())
        self.ctx.call_later(1.0, self._tick)

    # ════════════════════════════════════════════════════════
    #  スマホ → Pi
    # ════════════════════════════════════════════════════════
    def on_ble_write(self, data: bytes) -> None:
        if not B.is_chunk(data):
            # 旧アプリ（UTF-8 の生テキスト）: 既定の宛先へ送るだけ。配送状態は返さない
            self._submit(None, 0, self.default_dest, bytes(data))
            return
        try:
            got = self._reasm.add(bytes(data), self.wall())
            if got is None:
                return
            stream, raw = got
            frame = B.Frame.decode(raw)
        except B.ProtocolError as e:
            log.warning("[BLE] 不正なフレーム: %s", e)
            return
        if frame.kind == B.KIND_MSG:
            self._submit(self._clients.get(stream), frame.msg_id, frame.dest, frame.payload)
        elif frame.kind == B.KIND_HELLO:
            self._on_hello(stream, frame)
        elif frame.kind == B.KIND_NODES_REQ:
            self._send_nodes()

    def _on_hello(self, stream: int, frame: B.Frame) -> None:
        try:
            client_id, since = B.parse_hello(frame)
        except B.ProtocolError as e:
            log.warning("[BLE] HELLO が不正: %s", e)
            return
        self._clients[stream] = client_id
        last = self.store.last_seq()
        if since > last:
            since = 0           # Pi の受信箱が作り直された（または別の Pi の番号）
        self._send(B.Frame(B.KIND_INFO, src=self.addr,
                           payload=json.dumps({**self.info, "addr": self.addr, "last_seq": last},
                                              ensure_ascii=False).encode("utf-8")))
        for item in self.store.inbox_since(since, self.history_limit):
            self._send(B.Frame(B.KIND_MSG, item.seq, item.src, item.dest, item.payload))
        for item in self.store.outbox_for_client(client_id, self.wall() - self.store.hold_sec):
            self._send(B.status_frame(item.app_msg_id, item.state, item.hops))

    def _send_nodes(self) -> None:
        now = self.ctx.now()
        nodes = []
        for a, n in sorted(self.router.nodedb.nodes.items()):
            ago = now - n.last_heard if n.last_heard and now >= n.last_heard else None
            nodes.append({"addr": a, "name": n.name, "role": n.role, "hops": n.hops_away,
                          "heard_sec": None if ago is None else int(ago)})
        self._send(B.Frame(B.KIND_NODES, src=self.addr,
                           payload=json.dumps(nodes, ensure_ascii=False).encode("utf-8")))

    # ── 送信箱 ──────────────────────────────────────────────
    def _submit(self, client_id: bytes | None, app_msg_id: int, dest: int, payload: bytes) -> None:
        if dest == self.addr:
            return
        row_id = self.store.add_outbox(client_id, app_msg_id, dest, payload, self.wall())
        self._send_row(self.store.outbox_get(row_id))

    def _send_row(self, item: OutboxItem) -> None:
        self._key_wait = False
        try:
            key = self.router.send(item.dest, item.payload)
        except (ValueError, P.PacketError) as e:
            log.warning("[MESH] 送れません（%s）: %s", "全体" if item.dest == B.BROADCAST else item.dest, e)
            self._set_state(item, B.ST_FAILED)
            return
        state = B.ST_QUEUED if self._key_wait else B.ST_SENT
        self._set_state(item, state, mesh_msg_id=key.msg_id)
        if item.dest == B.BROADCAST:
            # 同じ Pi につながっている他のスマホにも見せる（受信箱に入れて通知）
            self._store_and_notify(self.addr, B.BROADCAST, key.msg_id, item.payload)

    def _set_state(self, item: OutboxItem, state: int, **fields) -> None:
        self.store.update_outbox(item.id, self.wall(), state=state, **fields)
        if item.app_msg_id:
            self._send(B.status_frame(item.app_msg_id, state, fields.get("hops", item.hops)))

    # ════════════════════════════════════════════════════════
    #  メッシュ → Pi
    # ════════════════════════════════════════════════════════
    def on_deliver(self, d: Delivery) -> None:
        self._store_and_notify(d.src, d.dest, d.msg_id, d.payload)

    def _store_and_notify(self, src: int, dest: int, mesh_msg_id: int, payload: bytes) -> None:
        seq = self.store.add_inbox(src, dest, mesh_msg_id, payload, self.wall())
        if seq is not None:
            self._send(B.Frame(B.KIND_MSG, seq, src, dest, payload))

    def on_event(self, event: str, info: dict) -> None:
        if event == "key_wait":
            self._key_wait = True
            return
        mid = info.get("msg_id")
        item = self.store.outbox_by_mesh_id(mid) if mid is not None else None
        if item is None:
            return
        if event == "key_ready":
            self._set_state(item, B.ST_SENT)
        elif event == "delivered":
            self._set_state(item, B.ST_DELIVERED, hops=info.get("hops"))
        elif event == "broadcast_relayed" and item.state == B.ST_SENT:
            self._set_state(item, B.ST_RELAYED)
        elif event in ("send_failed", "send_expired"):
            delay = min(self.retry_max, self.retry_base * 2 ** item.retries)
            self._set_state(item, B.ST_WAITING, retries=item.retries + 1,
                            next_try_at=self.wall() + delay)

    # ── 定期処理: 送り直し・期限切れ・掃除 ──────────────────
    def _tick(self) -> None:
        now = self.wall()
        for item in self.store.outbox_expired(now):
            self._set_state(item, B.ST_FAILED)
        for item in self.store.outbox_due(now):
            self._send_row(item)
        if now - self._last_purge >= _PURGE_SEC:
            self.store.purge(now)
            self._last_purge = now
        self.ctx.call_later(_TICK_SEC, self._tick)

    # ── 通知 ────────────────────────────────────────────────
    def _send(self, frame: B.Frame) -> None:
        for c in B.chunk(frame.encode()):
            self.notify(c)


def hello_payload(client_id: bytes, since: int) -> bytes:
    """テスト・デバッグ用: HELLO の payload を作る。"""
    return client_id[:8].ljust(8, b"\0") + struct.pack("!I", since)
