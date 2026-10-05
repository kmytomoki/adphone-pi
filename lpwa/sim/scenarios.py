# -*- coding: utf-8 -*-
"""
sim/scenarios.py  ―  トポロジとメッセージの流し方（シナリオ）

    line5    : 5 台を直線に並べる（隣としか届かない）。多段中継と TTL の限界を見る
    grid9    : 3×3 の格子
    random20 : 20 台をランダムに配置（平均で 4〜5 台と直接届く密度）
    churn20  : random20 の途中で 3 台が停止する（経路の切り替わりを見る）

ノード間隔は RadioParams の公称到達距離から決めるので、SF や送信出力を
変えてもトポロジの「形」（誰と誰が直接届くか）はおおむね保たれる。
"""
from __future__ import annotations

import inspect
import math
import random
from dataclasses import dataclass
from typing import Callable

from mesh import ROUTERS
from mesh.core import NodeContext

from .engine import Simulator
from .metrics import BROADCAST_ADDR, MessageRecord
from .radio import Medium, RadioParams

Positions = dict[int, tuple[float, float]]


# ── トポロジ ─────────────────────────────────────────────
def line(n: int, spacing: float) -> Positions:
    return {i + 1: (i * spacing, 0.0) for i in range(n)}


def grid(rows: int, cols: int, spacing: float) -> Positions:
    return {r * cols + c + 1: (c * spacing, r * spacing) for r in range(rows) for c in range(cols)}


def random_connected(n: int, range_m: float, mean_degree: float, params: RadioParams,
                     rng: random.Random, tries: int = 200) -> Positions:
    """平均次数が mean_degree 程度になる正方形にランダム配置する。全体がつながるまで引き直す。"""
    side = math.sqrt(n * math.pi * range_m ** 2 / (mean_degree + 1))
    for _ in range(tries):
        pos = {i + 1: (rng.uniform(0, side), rng.uniform(0, side)) for i in range(n)}
        medium = Medium(pos, params, random.Random(rng.getrandbits(32)))
        if _connected(medium):
            return pos
    raise RuntimeError("つながった配置を作れませんでした（mean_degree を上げてください）")


def _connected(medium: Medium) -> bool:
    addrs = list(medium.positions)
    seen = {addrs[0]}
    stack = [addrs[0]]
    while stack:
        a = stack.pop()
        for b in medium.neighbors(a):
            if b not in seen:
                seen.add(b)
                stack.append(b)
    return len(seen) == len(addrs)


# ── シナリオ ─────────────────────────────────────────────
@dataclass
class Scenario:
    name: str
    description: str
    build: Callable[[RadioParams, random.Random], Positions]
    messages: int = 60
    mean_interval: float = 10.0       # メッセージ間隔の平均（秒, 指数分布）
    unicast_ratio: float = 0.7
    payload_len: int = 30             # 平文の長さ（日本語約 10 文字）
    warmup: float = 90.0              # 起動時の ANNOUNCE（最大 60 秒に分散）が落ち着くまで待つ
    drain: float = 60.0               # 最後のメッセージの後に待つ時間
    failures: int = 0                 # 途中で停止させるノード数
    fixed_shadowing: bool = True      # False ならシャドウイングなし（line5 で形を崩さない）


def _line_spacing(p: RadioParams) -> float:
    """隣とは平均 RSSI が感度 +4dB で届き、2 つ先とは感度 -5dB 程度で届かない間隔。"""
    return p.nominal_range_m(margin_db=4.0)


SCENARIOS: dict[str, Scenario] = {s.name: s for s in [
    Scenario("line5", "5 台を直線に配置（隣のノードとだけ届く）",
             lambda p, rng: line(5, _line_spacing(p)), fixed_shadowing=False),
    Scenario("grid9", "3×3 の格子（縦横の隣と届く。斜めはシャドウイング次第）",
             lambda p, rng: grid(3, 3, _line_spacing(p))),
    Scenario("random20", "20 台をランダム配置（平均 4〜5 台と直接届く）",
             lambda p, rng: random_connected(20, p.nominal_range_m(), 4.5, p, rng)),
    Scenario("churn20", "random20 で、途中に 3 台が停止する",
             lambda p, rng: random_connected(20, p.nominal_range_m(), 4.5, p, rng), failures=3),
]}


def run_scenario(scenario: Scenario, router: str = "flood_v1", seed: int = 1,
                 router_params: dict | None = None, radio: RadioParams | None = None,
                 routers: int = 0) -> dict:
    """シナリオを 1 回実行して集計結果を返す。

    routers: 直接届く相手が多い順に、この台数を ROUTER 役にする（役割を持つルーティングのみ）
    """
    params = radio or RadioParams()
    if not scenario.fixed_shadowing:
        params = RadioParams(**{**params.__dict__, "shadowing_sigma_db": 0.0})
    rng = random.Random(seed)
    positions = scenario.build(params, rng)
    router_cls = ROUTERS[router]
    rparams = dict(router_params or {})

    sim_seed = rng.getrandbits(32)
    if routers and "roles" in inspect.signature(router_cls).parameters:
        medium = Simulator.preview_medium(positions, params, sim_seed)
        by_degree = sorted(positions, key=lambda a: -len(medium.neighbors(a)))
        rparams["roles"] = {a: "ROUTER" for a in by_degree[:routers]}

    def factory(ctx: NodeContext):
        return router_cls(ctx, **rparams)

    sim = Simulator(positions, factory, params, seed=sim_seed)
    addrs = sorted(positions)
    diameter = _diameter(sim)

    # 停止させるノード（送受信の端点には選ばない）
    doomed = rng.sample(addrs, scenario.failures) if scenario.failures else []
    endpoints = [a for a in addrs if a not in doomed]

    t = scenario.warmup
    send_times = []
    for _ in range(scenario.messages):
        t += rng.expovariate(1.0 / scenario.mean_interval)
        send_times.append(t)
    end = send_times[-1] + scenario.drain if send_times else scenario.warmup
    fail_at = scenario.warmup + (end - scenario.warmup) / 3
    for a in doomed:
        sim.schedule(fail_at, sim.nodes[a].kill)

    reach = router_cls.reach_hops(rparams)
    for at in send_times:
        src = rng.choice(endpoints)
        if rng.random() < scenario.unicast_ratio:
            dest = rng.choice([a for a in endpoints if a != src])
        else:
            dest = BROADCAST_ADDR
        payload = bytes(rng.getrandbits(8) for _ in range(scenario.payload_len))
        sim.schedule(at, lambda src=src, dest=dest, payload=payload: _send(sim, src, dest, payload))

    sim.run(end)
    result = sim.metrics.summary(duration=end, ttl=reach)
    result.update({
        "scenario": scenario.name, "router": router, "seed": seed,
        "nodes": len(addrs), "diameter": diameter, "duration": end,
        "router_params": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in rparams.items()
                          if k != "roles"},
        "routers": sorted(rparams.get("roles", {})),
        "router_stats": _router_stats(sim),
    })
    return result


def _send(sim: Simulator, src: int, dest: int, payload: bytes) -> None:
    node = sim.nodes[src]
    if not node.alive:
        return
    dist = sim.hop_distances(src)
    if dest == BROADCAST_ADDR:
        expected = frozenset(a for a in dist if a != src)
        hop = None
    else:
        expected = frozenset([dest])
        hop = dist.get(dest)
    key = node.router.send(dest, payload)
    sim.metrics.on_origin(key, MessageRecord(src, dest, sim.now, expected, hop))


def _diameter(sim: Simulator) -> int | None:
    worst = 0
    for a in sim.nodes:
        dist = sim.hop_distances(a)
        if len(dist) < len(sim.nodes):
            return None
        worst = max(worst, max(dist.values()))
    return worst


def _router_stats(sim: Simulator) -> dict:
    """ルーターが stats を持っていれば全ノード分を合計する。"""
    total: dict[str, int] = {}
    for node in sim.nodes.values():
        st = getattr(node.router, "stats", None)
        if st is None:
            continue
        for k, v in vars(st).items():
            if isinstance(v, int):
                total[k] = total.get(k, 0) + v
    return total
