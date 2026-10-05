# -*- coding: utf-8 -*-
"""ADREN メッシュルーティングのコア（ROUTING_PLAN.md 参照）。"""
from .core import Delivery, MessageKey, NodeContext, RadioPort, Router, RouterFactory, TxMeta
from .flood_v1 import FloodRouterV1
from .router import ManagedFloodRouter

# sim / realtime から名前で選べるルーティング
ROUTERS: dict[str, type] = {
    FloodRouterV1.name: FloodRouterV1,
    ManagedFloodRouter.name: ManagedFloodRouter,
}

__all__ = [
    "Delivery", "MessageKey", "NodeContext", "RadioPort", "Router", "RouterFactory",
    "TxMeta", "FloodRouterV1", "ManagedFloodRouter", "ROUTERS",
]
