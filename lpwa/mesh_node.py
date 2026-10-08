# -*- coding: utf-8 -*-
"""
mesh_node.py  ―  v2 メッシュノード（管理型フラッディング）の対話 CLI

node_mesh.py（v1）の後継。設定は setting.ini（mesh/config.py 参照）。
鍵ファイルと NodeDB は state/ に保存され、再起動しても同じ鍵を使う。

    sudo python3 mesh_node.py

コマンド:
    <addr> <本文>     ユニキャスト（例: 2 こちら避難所A、物資不足）
    all <本文>        グループ鍵でブロードキャスト
    nodes             知っているノードの一覧（指紋つき）
    forget <addr>     そのノードの鍵を忘れる（入れ替えたノードを受け入れるとき）
    announce          今すぐ ANNOUNCE を送る
    stats             中継・取りやめ・鍵の要求・ACK・再送などの回数
    route <addr>      その相手への経路（中継ノード列）。routing=routed のとき
    quit
"""
from __future__ import annotations

import logging
import sys
import threading

import lora_e220_b
from mesh import packet as P
from mesh.config import load_mesh_config, make_router_factory
from mesh.core import Delivery
from mesh.realtime import E220Port, RealtimeNode

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("mesh")


def _on_event(event: str, info: dict) -> None:
    if event == "key_conflict":
        log.warning("[鍵の不一致] 0x%04X が登録済みと違う鍵で名乗っています（指紋 %s）。"
                    "ノードを入れ替えたなら 'forget %d' で受け入れます",
                    info["addr"], info["fingerprint"], info["addr"])
    elif event == "delivered":
        log.info("[届いた] → 0x%04X msg_id=%08X（%d ホップ, %d 回目で）",
                 info["dest"], info["msg_id"], info["hops"], info["attempts"])
    elif event == "send_failed":
        log.warning("[届かず] → 0x%04X msg_id=%08X（再送しても ACK が返りませんでした）",
                    info["dest"], info["msg_id"])
    elif event == "peer":
        log.info("[PEER ] 0x%04X %s %s（指紋 %s）", info["addr"], info["role"], info["name"],
                 info["fingerprint"])
    else:
        log.info("[%s] %s", event, info)


def _on_deliver(d: Delivery) -> None:
    to = "全体" if d.dest == P.BROADCAST_ADDR else "自分"
    log.info("[RECV ] 0x%04X → %s（%d ホップ）: %s", d.src, to, d.hops or 0,
             d.payload.decode("utf-8", errors="replace"))


def main() -> int:
    mc = load_mesh_config(lora_e220_b.load_config_parser(), lora_e220_b.CONFIG_PATH)
    factory, identity, nodedb = make_router_factory(mc, on_event=_on_event)
    node = RealtimeNode(E220Port(), factory, address=mc.address, on_deliver=_on_deliver)
    router = node.router
    log.info("自ノード 0x%04X  役割=%s  経路=%s  hop_limit=%d  指紋=%s  グループ鍵=%s",
             mc.address, mc.role, mc.routing, mc.hop_limit, identity.fingerprint,
             "あり" if mc.group_key else "なし")

    stop = threading.Event()
    loop = threading.Thread(target=node.run_forever, args=(stop,),
                            kwargs={"on_error": lambda e: log.exception("ループでエラー: %s", e)},
                            daemon=True)
    loop.start()

    def send(dest: int, text: str) -> None:
        try:
            key = router.send(dest, text.encode("utf-8"))
            log.info("[SEND ] → %s msg_id=%08X",
                     "全体" if dest == P.BROADCAST_ADDR else "0x{:04X}".format(dest), key.msg_id)
        except (ValueError, P.PacketError) as e:
            log.error("[SEND ] 送れません: %s", e)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        if cmd == "quit":
            break
        if cmd == "all":
            node.post(lambda t=rest: send(P.BROADCAST_ADDR, t))
        elif cmd == "nodes":
            for a, n in sorted(nodedb.nodes.items()):
                print("  0x{:04X}  {:<11} {:<16} {}ホップ  指紋={}".format(
                    a, n.role, n.name, n.hops_away if n.hops_away is not None else "?",
                    n.ed_pub[:8].hex()))
        elif cmd == "forget":
            try:
                addr = int(rest, 0)
            except ValueError:
                print("  使い方: forget <addr>")
                continue
            node.post(lambda a=addr: print("  削除しました" if nodedb.forget(a)
                                           else "  登録されていません"))
        elif cmd == "route":
            try:
                addr = int(rest, 0)
            except ValueError:
                print("  使い方: route <addr>")
                continue
            if hasattr(router, "route_for"):
                path = router.route_for(addr)
                print("  " + ("経路なし（フラッディングで送ります）" if path is None else
                              " → ".join("0x{:04X}".format(a) for a in (mc.address, *path, addr))))
            else:
                print("  routing=flood では経路を使いません")
        elif cmd == "announce":
            node.post(router.announce)
        elif cmd == "stats":
            print("  " + "  ".join("{}={}".format(k, v) for k, v in vars(router.stats).items()))
        else:
            try:
                dest = int(cmd, 0)
            except ValueError:
                print("  不明なコマンド: {}".format(cmd))
                continue
            node.post(lambda d=dest, t=rest: send(d, t))
    stop.set()
    loop.join(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
