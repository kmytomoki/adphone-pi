# -*- coding: utf-8 -*-
"""mesh/airtime.py  ―  LoRa の送信時間と受信感度（ルーターとシミュレータで共用）"""
from __future__ import annotations

import math

# LoRa の受信感度（BW125kHz の代表値, dBm）
_SENSITIVITY_BW125 = {7: -123.0, 8: -126.0, 9: -129.0, 10: -132.0, 11: -134.5, 12: -137.0}


def lora_airtime(payload_len: int, sf: int = 7, bw_hz: int = 125_000, cr: int = 1,
                 preamble: int = 8, explicit_header: bool = True, crc: bool = True,
                 ldro: bool | None = None) -> float:
    """LoRa パケットの送信時間（秒）。Semtech AN1200.13 の式。cr=1 は 4/5。"""
    t_sym = (2 ** sf) / bw_hz
    if ldro is None:
        ldro = t_sym > 0.016
    de = 1 if ldro else 0
    ih = 0 if explicit_header else 1
    t_preamble = (preamble + 4.25) * t_sym
    num = 8 * payload_len - 4 * sf + 28 + (16 if crc else 0) - 20 * ih
    n_payload = 8 + max(math.ceil(num / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return t_preamble + n_payload * t_sym


def lora_sensitivity(sf: int = 7, bw_hz: int = 125_000) -> float:
    """受信感度の代表値（dBm）。"""
    return _SENSITIVITY_BW125.get(sf, -123.0) + 10 * math.log10(bw_hz / 125_000)
