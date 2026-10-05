# -*- coding: utf-8 -*-
"""
ルーティングシミュレータの CLI

    cd Raspberry/lpwa
    python3 -m sim                                  # 全シナリオ × flood_v1 × 5 seed
    python3 -m sim --scenario random20 --seeds 10
    python3 -m sim --ttl 5 --jitter-ms 1000
    python3 -m sim --lbt -80                        # キャリアセンスあり
    python3 -m sim --json baseline.json             # 結果を保存（アルゴリズム比較用）
    python3 -m sim --router managed_v2              # Phase 3 の管理型フラッディング
    python3 -m sim --router managed_v2 --routers 3  # 直接届く相手が多い 3 台を ROUTER 役に
"""
from __future__ import annotations

import argparse
import json
import sys

from mesh import ROUTERS

from .radio import RadioParams
from .scenarios import SCENARIOS, run_scenario

_AVG_KEYS = [
    "unicast_delivery", "unicast_delivery_within_ttl", "unicast_beyond_ttl",
    "broadcast_reach", "tx_per_unicast", "tx_per_broadcast",
    "airtime_per_unicast", "airtime_per_broadcast",
    "latency_p50", "latency_p95", "collision_rate", "max_airtime_per_hour",
]


def _avg(results: list[dict], key: str):
    xs = [r[key] for r in results if r.get(key) is not None]
    return sum(xs) / len(xs) if xs else None


def _fmt(v, kind: str) -> str:
    if v is None:
        return "-"
    if kind == "pct":
        return "{:5.1f}%".format(v * 100)
    if kind == "sec":
        return "{:5.2f}s".format(v)
    return "{:6.1f}".format(v)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m sim", description="ADREN ルーティングシミュレータ")
    ap.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="all")
    ap.add_argument("--router", choices=list(ROUTERS), default="flood_v1")
    ap.add_argument("--seeds", type=int, default=5, help="seed 1〜N で繰り返して平均する")
    g1 = ap.add_argument_group("flood_v1")
    g1.add_argument("--ttl", type=int, default=3)
    g1.add_argument("--jitter-ms", type=int, default=500, help="中継前のランダム遅延の上限")
    g2 = ap.add_argument_group("managed_v2")
    g2.add_argument("--hop-limit", type=int, default=3, help="中継回数の上限（届くのは +1 ホップ）")
    g2.add_argument("--slots-per-neighbor", type=float, default=2.0,
                    help="中継の待ち窓 = スロット × 隣ノード数 × この値")
    g2.add_argument("--rssi-span", type=float, default=3.0,
                    help="電波が強い受信ほど窓を最大 2^この値 倍に広げる")
    g2.add_argument("--cancel", type=int, default=1, help="この回数ほかの中継を聞いたら取りやめる")
    g2.add_argument("--routers", type=int, default=0, help="ROUTER 役にする台数")
    ap.add_argument("--announce-sec", type=float,
                    help="ANNOUNCE 間隔（0 で送らない。既定: flood_v1=300, managed_v2=900）")
    ap.add_argument("--messages", type=int, help="1 回あたりのメッセージ数")
    ap.add_argument("--interval", type=float, help="メッセージ間隔の平均（秒）")
    ap.add_argument("--sf", type=int, default=7)
    ap.add_argument("--lbt", type=float, metavar="DBM", help="キャリアセンスのレベル（例: -80）")
    ap.add_argument("--json", metavar="PATH", help="seed ごとの結果を JSON で保存")
    args = ap.parse_args(argv)

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    radio = RadioParams(sf=args.sf, carrier_sense_dbm=args.lbt)
    if args.router == "flood_v1":
        router_params = {
            "ttl": args.ttl,
            "relay_jitter": args.jitter_ms / 1000.0,
            "announce_interval": 300.0 if args.announce_sec is None else (args.announce_sec or None),
        }
        desc = "ttl={}  jitter={}ms".format(args.ttl, args.jitter_ms)
    else:
        router_params = {
            "hop_limit": args.hop_limit,
            "slots_per_neighbor": args.slots_per_neighbor,
            "rssi_span": args.rssi_span,
            "cancel_threshold": args.cancel,
            "sf": args.sf,
            "group_key": bytes(range(32)),   # シミュレーション用の共通グループ鍵
            "announce_interval": 900.0 if args.announce_sec is None else (args.announce_sec or None),
        }
        desc = "hop_limit={}  slots/neighbor={}  rssi_span={}  cancel={}  routers={}".format(
            args.hop_limit, args.slots_per_neighbor, args.rssi_span, args.cancel, args.routers)

    print("router={}  {}  announce={}s  SF{}  LBT={}  seeds={}".format(
        args.router, desc, router_params["announce_interval"], args.sf,
        args.lbt if args.lbt is not None else "off", args.seeds))
    print("送信時間: {:.0f}ms（v1 の 30 文字 DATA = 130B）/ {:.0f}ms（v2 = 74B）".format(
        radio.airtime(130) * 1000, radio.airtime(74) * 1000))
    print()
    header = ("シナリオ", "台数", "直径", "ユニ到達", "TTL圏内", "TTL圏外",
              "ブロ到達", "送信/ユニ", "送信/ブロ", "占有/ユニ", "占有/ブロ", "遅延p50", "遅延p95", "衝突率", "最大送信s/h")
    print("  ".join("{:>8}".format(h) for h in header))

    all_results = []
    for name in names:
        sc = SCENARIOS[name]
        if args.messages:
            sc.messages = args.messages
        if args.interval:
            sc.mean_interval = args.interval
        results = [run_scenario(sc, args.router, seed, router_params, radio, routers=args.routers)
                   for seed in range(1, args.seeds + 1)]
        all_results.extend(results)
        diam = [r["diameter"] for r in results if r["diameter"] is not None]
        row = [
            name, str(results[0]["nodes"]),
            "{}-{}".format(min(diam), max(diam)) if diam else "-",
            _fmt(_avg(results, "unicast_delivery"), "pct"),
            _fmt(_avg(results, "unicast_delivery_within_ttl"), "pct"),
            _fmt(_avg(results, "unicast_beyond_ttl"), "pct"),
            _fmt(_avg(results, "broadcast_reach"), "pct"),
            _fmt(_avg(results, "tx_per_unicast"), "num"),
            _fmt(_avg(results, "tx_per_broadcast"), "num"),
            _fmt(_avg(results, "airtime_per_unicast"), "sec"),
            _fmt(_avg(results, "airtime_per_broadcast"), "sec"),
            _fmt(_avg(results, "latency_p50"), "sec"),
            _fmt(_avg(results, "latency_p95"), "sec"),
            _fmt(_avg(results, "collision_rate"), "pct"),
            _fmt(_avg(results, "max_airtime_per_hour"), "num"),
        ]
        print("  ".join("{:>8}".format(c) for c in row))

    print()
    print("ユニ到達 = ユニキャストが宛先に届いた割合 / TTL圏内 = 宛先が TTL 以内のホップにある場合の到達率")
    print("TTL圏外 = 宛先が TTL より遠かったメッセージの割合 / ブロ到達 = ブロードキャストが届いたノードの割合")
    print("送信/ユニ・ブロ = 1 メッセージのために送られたパケット数（中継込み）/ 占有 = その電波の占有時間の合計")
    print("衝突率 = 受信判定のうち衝突で失った割合")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"args": vars(args), "results": all_results}, f, ensure_ascii=False, indent=2)
        print("保存: {}".format(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
