# -*- coding: utf-8 -*-
"""
sim/radio.py  ―  仮想無線（LoRa / E220-900JP の近似モデル）

再現するもの:
    - 送信時間: Semtech の LoRa time-on-air の式（SF / BW / CR / プリアンブル）
    - UART 転送: 9600bps で E220 とやり取りする時間（送信前・受信後）
    - 電波の届き方: 対数距離減衰 + リンクごとのシャドウイング（固定）
                    + パケットごとのフェージング
    - 衝突: 時間が重なった送信は、強い方が capture_db 以上強くなければ両方失う
    - 半二重: 送信中のノードは受信できない
    - キャリアセンス（任意）: 送信前にチャネルが使用中なら待つ

再現しないもの（必要になったら足す）:
    - E220 のサブパケット分割（subpacket_size を超える長さ）。現行のパケットは 200B 未満
    - モジュール内部のバッファ・送信待ち、周波数ホッピング、地形・建物の影響
    - E220-900JP が実際にキャリアセンスを行うか（未確認のため既定は無効）

数値はデータシートの代表値。実機の測定値が取れたら RadioParams を合わせること。
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

from mesh.airtime import lora_airtime, lora_sensitivity


@dataclass
class RadioParams:
    tx_power_dbm: float = 13.0          # setting.ini transmitting_power
    sf: int = 7                         # setting.ini sf
    bw_hz: int = 125_000                # setting.ini bw
    cr: int = 1                         # 4/5
    preamble: int = 8
    sensitivity_dbm: float | None = None  # None なら SF から決める
    path_loss_exponent: float = 3.0     # 2=見通し, 3〜3.5=市街地
    pl0_db: float = 31.7                # 1m での損失（920MHz の自由空間）
    shadowing_sigma_db: float = 4.0     # リンクごとの固定のばらつき
    fading_sigma_db: float = 2.0        # パケットごとのばらつき
    capture_db: float = 6.0             # これ以上強ければ衝突しても受かる
    interference_margin_db: float = 10.0  # 感度よりこれだけ弱い電波までは干渉とみなす
    packet_error_rate: float = 0.01     # 上記以外の要因による損失
    uart_baud: int = 9600
    e220_header_bytes: int = 3          # Fixed Mode のアドレス + チャネル
    frame_overhead_bytes: int = 7       # lora_e220_b の外層フレーム（magic+ver+len+CRC）
    carrier_sense_dbm: float | None = None  # 例: -80（ARIB STD-T108 のキャリアセンスレベル）

    @property
    def sensitivity(self) -> float:
        if self.sensitivity_dbm is not None:
            return self.sensitivity_dbm
        return lora_sensitivity(self.sf, self.bw_hz)

    def on_air_len(self, pkt_len: int) -> int:
        return pkt_len + self.frame_overhead_bytes + self.e220_header_bytes

    def airtime(self, pkt_len: int) -> float:
        return lora_airtime(self.on_air_len(pkt_len), self.sf, self.bw_hz, self.cr, self.preamble)

    def uart_time(self, pkt_len: int) -> float:
        return self.on_air_len(pkt_len) * 10 / self.uart_baud   # 8N1 = 10 bit/byte

    def path_loss(self, distance_m: float) -> float:
        return self.pl0_db + 10 * self.path_loss_exponent * math.log10(max(1.0, distance_m))

    def nominal_range_m(self, margin_db: float = 6.0) -> float:
        """シャドウイングを除いて、感度 + margin_db で届く距離。"""
        budget = self.tx_power_dbm - self.sensitivity - margin_db - self.pl0_db
        return 10 ** (budget / (10 * self.path_loss_exponent))


@dataclass
class Transmission:
    sender: int
    pkt: bytes
    meta: object
    start: float
    end: float


class Medium:
    """全ノードが共有する 1 チャネル。"""

    def __init__(self, positions: dict[int, tuple[float, float]], params: RadioParams,
                 rng: random.Random):
        self.params = params
        self.rng = rng
        self.positions = dict(positions)
        self._mean: dict[tuple[int, int], float] = {}
        addrs = sorted(positions)
        for i, a in enumerate(addrs):
            for b in addrs[i + 1:]:
                (xa, ya), (xb, yb) = positions[a], positions[b]
                shadow = rng.gauss(0, params.shadowing_sigma_db) if params.shadowing_sigma_db else 0.0
                rssi = params.tx_power_dbm - params.path_loss(math.hypot(xa - xb, ya - yb)) - shadow
                self._mean[(a, b)] = self._mean[(b, a)] = rssi
        self._recent: list[Transmission] = []

    def mean_rssi(self, a: int, b: int) -> float:
        return self._mean[(a, b)]

    def neighbors(self, a: int, margin_db: float = 0.0) -> list[int]:
        """平均 RSSI が感度 + margin_db 以上の相手。"""
        th = self.params.sensitivity + margin_db
        return [b for b in self.positions if b != a and self._mean[(a, b)] >= th]

    def channel_busy(self, node: int, now: float) -> bool:
        cs = self.params.carrier_sense_dbm
        if cs is None:
            return False
        return any(t.start <= now < t.end and t.sender != node and self._mean[(t.sender, node)] >= cs
                   for t in self._recent)

    def begin(self, tx: Transmission) -> None:
        horizon = tx.start - 10.0
        self._recent = [t for t in self._recent if t.end >= horizon]
        self._recent.append(tx)

    def receptions(self, tx: Transmission, is_alive) -> list[tuple[int, int | None, str]]:
        """送信 tx が終わった時点で、各ノードが受信できたかを判定する。

        Returns: [(receiver, 受信 RSSI or None, 理由)]  理由: ok / weak / collision / half_duplex / noise
        """
        p = self.params
        results: list[tuple[int, int | None, str]] = []
        floor = p.sensitivity - 3 * p.fading_sigma_db
        overlapping = [t for t in self._recent
                       if t is not tx and t.start < tx.end and t.end > tx.start]
        for r in self.positions:
            if r == tx.sender or not is_alive(r):
                continue
            mean = self._mean[(tx.sender, r)]
            if mean < floor:
                continue
            rssi = mean + (self.rng.gauss(0, p.fading_sigma_db) if p.fading_sigma_db else 0.0)
            if rssi < p.sensitivity:
                if mean >= p.sensitivity:   # 本来届くリンクがフェージングで落ちたときだけ数える
                    results.append((r, None, "weak"))
                continue
            if any(t.sender == r for t in overlapping):
                results.append((r, None, "half_duplex"))
                continue
            lost = False
            for t in overlapping:
                i_rssi = self._mean[(t.sender, r)]
                if i_rssi >= p.sensitivity - p.interference_margin_db and rssi - i_rssi < p.capture_db:
                    lost = True
                    break
            if lost:
                results.append((r, None, "collision"))
                continue
            if self.rng.random() < p.packet_error_rate:
                results.append((r, None, "noise"))
                continue
            results.append((r, round(rssi), "ok"))
        return results
