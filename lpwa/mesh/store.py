# -*- coding: utf-8 -*-
"""
mesh/store.py  ―  蓄積転送の受信箱と送信箱（SQLite, Phase 5）

受信箱（inbox）
    メッシュから届いたメッセージを Pi ごとの連番（seq）つきで保存する。スマホは接続のたびに
    「最後に受け取った連番」を HELLO で伝え、それより新しいものを受け取る。
    スマホごとの未配信キューを Pi に持たせずに、不在だったスマホが取りこぼしを回収できる。

送信箱（outbox）
    スマホから受け取ったメッセージと、その配送状態（bleproto の ST_*）。届かなかった
    （ST_WAITING）ものは、間隔を延ばしながら保持期間（既定 24 時間）まで送り直す。
    Pi が再起動しても続きから送り直せるよう、状態ごと保存する。

どちらも保持期間と件数の上限を超えたら古いものから消す。
1 つのスレッド（メッシュのループ）からだけ使うこと。
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass

from . import bleproto as B

_SCHEMA = """
CREATE TABLE IF NOT EXISTS inbox (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    src         INTEGER NOT NULL,
    dest        INTEGER NOT NULL,
    mesh_msg_id INTEGER NOT NULL,
    payload     BLOB    NOT NULL,
    received_at REAL    NOT NULL,
    UNIQUE (src, mesh_msg_id)
);
CREATE TABLE IF NOT EXISTS outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   BLOB,
    app_msg_id  INTEGER NOT NULL,
    dest        INTEGER NOT NULL,
    payload     BLOB    NOT NULL,
    created_at  REAL    NOT NULL,
    state       INTEGER NOT NULL,
    mesh_msg_id INTEGER,
    retries     INTEGER NOT NULL DEFAULT 0,
    next_try_at REAL,
    hops        INTEGER,
    updated_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_mesh ON outbox (mesh_msg_id);
CREATE INDEX IF NOT EXISTS outbox_state ON outbox (state, next_try_at);
"""


@dataclass
class InboxItem:
    seq: int
    src: int
    dest: int
    payload: bytes


@dataclass
class OutboxItem:
    id: int
    client_id: bytes | None
    app_msg_id: int
    dest: int
    payload: bytes
    created_at: float
    state: int
    mesh_msg_id: int | None
    retries: int
    next_try_at: float | None
    hops: int | None


class Store:
    def __init__(self, path: str = ":memory:", hold_sec: float = 24 * 3600,
                 max_inbox: int = 500, max_outbox: int = 200):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        self.hold_sec = hold_sec
        self.max_inbox = max_inbox
        self.max_outbox = max_outbox

    # ── 受信箱 ──────────────────────────────────────────────
    def add_inbox(self, src: int, dest: int, mesh_msg_id: int, payload: bytes,
                  now: float) -> int | None:
        """保存して連番を返す。同じメッセージ（送信元 + msg_id）がすでにあれば None。"""
        # INSERT OR IGNORE だと捨てた分も連番を消費するので、先に確かめる
        if self.db.execute("SELECT 1 FROM inbox WHERE src = ? AND mesh_msg_id = ?",
                           (src, mesh_msg_id)).fetchone():
            return None
        cur = self.db.execute(
            "INSERT INTO inbox (src, dest, mesh_msg_id, payload, received_at) VALUES (?, ?, ?, ?, ?)",
            (src, dest, mesh_msg_id, payload, now))
        self.db.commit()
        return cur.lastrowid

    def inbox_since(self, seq: int, limit: int = 50) -> list[InboxItem]:
        """seq より新しいものを古い順に（多すぎるときは新しい limit 件）。"""
        rows = self.db.execute(
            "SELECT seq, src, dest, payload FROM inbox WHERE seq > ? ORDER BY seq DESC LIMIT ?",
            (seq, limit)).fetchall()
        return [InboxItem(*r) for r in reversed(rows)]

    def last_seq(self) -> int:
        row = self.db.execute("SELECT MAX(seq) FROM inbox").fetchone()
        return row[0] or 0

    # ── 送信箱 ──────────────────────────────────────────────
    def add_outbox(self, client_id: bytes | None, app_msg_id: int, dest: int, payload: bytes,
                   now: float) -> int:
        cur = self.db.execute(
            "INSERT INTO outbox (client_id, app_msg_id, dest, payload, created_at, state, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (client_id, app_msg_id, dest, payload, now, B.ST_QUEUED, now))
        self.db.commit()
        return cur.lastrowid

    def update_outbox(self, row_id: int, now: float, **fields) -> None:
        cols = ", ".join("{} = ?".format(k) for k in fields)
        self.db.execute("UPDATE outbox SET {}, updated_at = ? WHERE id = ?".format(cols),
                        (*fields.values(), now, row_id))
        self.db.commit()

    def outbox_by_mesh_id(self, mesh_msg_id: int) -> OutboxItem | None:
        row = self.db.execute(_OUT_SELECT + " WHERE mesh_msg_id = ? ORDER BY id DESC LIMIT 1",
                              (mesh_msg_id,)).fetchone()
        return OutboxItem(*row) if row else None

    def outbox_get(self, row_id: int) -> OutboxItem | None:
        row = self.db.execute(_OUT_SELECT + " WHERE id = ?", (row_id,)).fetchone()
        return OutboxItem(*row) if row else None

    def outbox_due(self, now: float) -> list[OutboxItem]:
        """送り直す時刻が来た「再送待ち」と、送れていない「受付」（Pi の再起動後など）。"""
        rows = self.db.execute(
            _OUT_SELECT + " WHERE (state = ? AND next_try_at <= ?) OR (state = ? AND mesh_msg_id IS NULL)"
            " ORDER BY id", (B.ST_WAITING, now, B.ST_QUEUED)).fetchall()
        return [OutboxItem(*r) for r in rows]

    def outbox_for_client(self, client_id: bytes, since: float) -> list[OutboxItem]:
        rows = self.db.execute(_OUT_SELECT + " WHERE client_id = ? AND updated_at >= ? ORDER BY id",
                               (client_id, since)).fetchall()
        return [OutboxItem(*r) for r in rows]

    def outbox_expired(self, now: float) -> list[OutboxItem]:
        rows = self.db.execute(
            _OUT_SELECT + " WHERE state IN (?, ?) AND created_at < ?",
            (B.ST_QUEUED, B.ST_WAITING, now - self.hold_sec)).fetchall()
        return [OutboxItem(*r) for r in rows]

    def recover(self, now: float) -> None:
        """Pi の再起動後に呼ぶ。ルーターの状態（ACK 待ち・鍵待ち）は消えているので送り直しに回す。"""
        # ACK を待っていたユニキャスト → 再送待ち（すぐ）
        self.db.execute("UPDATE outbox SET state = ?, next_try_at = ? WHERE state = ? AND dest != ?",
                        (B.ST_WAITING, now, B.ST_SENT, B.BROADCAST))
        # 鍵を待っていた受付 → まだ送っていない扱い（outbox_due で拾われる）
        self.db.execute("UPDATE outbox SET mesh_msg_id = NULL WHERE state = ?", (B.ST_QUEUED,))
        self.db.commit()

    # ── 掃除 ────────────────────────────────────────────────
    def purge(self, now: float) -> None:
        horizon = now - self.hold_sec
        self.db.execute("DELETE FROM inbox WHERE received_at < ?", (horizon,))
        self.db.execute("DELETE FROM inbox WHERE seq NOT IN"
                        " (SELECT seq FROM inbox ORDER BY seq DESC LIMIT ?)", (self.max_inbox,))
        # 送信箱: 終わったもので保持期間を過ぎたもの、件数の上限を超えた古いもの
        self.db.execute("DELETE FROM outbox WHERE updated_at < ? AND state NOT IN (?, ?)",
                        (horizon, B.ST_QUEUED, B.ST_WAITING))
        self.db.execute("DELETE FROM outbox WHERE id NOT IN"
                        " (SELECT id FROM outbox ORDER BY id DESC LIMIT ?)", (self.max_outbox,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


_OUT_SELECT = ("SELECT id, client_id, app_msg_id, dest, payload, created_at, state, mesh_msg_id,"
               " retries, next_try_at, hops FROM outbox")
