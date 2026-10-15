#!/usr/bin/env python3
"""Enable the local Leap relay only after it has caught up to XPR Mainnet."""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path


CHAIN_ID = "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0"
LOCAL_INFO = "http://127.0.0.1:8888/v1/chain/get_info"
REFERENCE_INFO = "https://api.protonnz.com/v1/chain/get_info"
NODE_ROOT = "/data/xpr-mainnet-leap-relay/node"
CONFIG_DIR = "/data/xpr-mainnet-follow-config"
RUNNER = "/home/ubuntu/pulsevm-mainnet-rpc/scripts/run-xpr-mainnet-catchup-amd64.sh"
CONTAINER = "xpr-mainnet-catchup-amd64"
PULSEVM_DROPIN = Path(
    "/etc/systemd/system/pulsevm-xpr-replay.service.d/transaction-relay.conf"
)


def info(url: str) -> dict:
    request = urllib.request.Request(
        url,
        data=b"{}",
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.load(response)
    if value.get("chain_id") != CHAIN_ID:
        raise ValueError(f"{url} reports a different chain id")
    return value


def near_live() -> bool:
    local = info(LOCAL_INFO)
    reference = info(REFERENCE_INFO)
    lag_blocks = int(reference["head_block_num"]) - int(local["head_block_num"])
    local_time = datetime.fromisoformat(local["head_block_time"])
    reference_time = datetime.fromisoformat(reference["head_block_time"])
    lag_seconds = (reference_time - local_time).total_seconds()
    print(
        "Leap head={} time={} lag_blocks={} lag_seconds={:.1f}".format(
            local["head_block_num"], local["head_block_time"], lag_blocks, lag_seconds
        ),
        flush=True,
    )
    return 0 <= lag_blocks <= 10 and 0 <= lag_seconds <= 5


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, env=env)


def wait_for_ready() -> None:
    deadline = time.monotonic() + 180
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            info(LOCAL_INFO)
            return
        except Exception as error:  # nodeos takes time to reopen chainbase
            last_error = error
            time.sleep(3)
    raise TimeoutError(f"Leap RPC did not recover after restart: {last_error}")


def install_pulsevm_relay() -> None:
    content = "[Service]\nEnvironment=XPR_REPLAY_TX_RPC_URL=http://127.0.0.1:8888\n"
    run(["sudo", "install", "-d", "-m", "0755", str(PULSEVM_DROPIN.parent)])
    subprocess.run(
        ["sudo", "tee", str(PULSEVM_DROPIN)],
        input=content,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    run(["sudo", "systemctl", "daemon-reload"])
    run(["sudo", "systemctl", "restart", "pulsevm-xpr-replay.service"])
    result = subprocess.run(
        ["systemctl", "show", "pulsevm-xpr-replay.service", "-p", "Environment", "--value"],
        check=True,
        capture_output=True,
        text=True,
    )
    if "XPR_REPLAY_TX_RPC_URL=http://127.0.0.1:8888" not in result.stdout:
        raise RuntimeError("PulseVM did not load the local Leap relay setting")


def main() -> None:
    print(
        "Waiting for Leap to remain within 10 blocks and 5 seconds of XPR Mainnet",
        flush=True,
    )
    stable_checks = 0
    while stable_checks < 3:
        try:
            stable_checks = stable_checks + 1 if near_live() else 0
        except Exception as error:
            stable_checks = 0
            print(f"Mainnet head check failed: {error}", flush=True)
        if stable_checks < 3:
            time.sleep(5)

    print("Leap is near live head; enabling API and P2P transaction acceptance", flush=True)
    run(["sudo", "docker", "stop", "--time", "60", CONTAINER])
    environment = {
        **os.environ,
        "XPR_CORPUS_NODE_ROOT": NODE_ROOT,
        "XPR_CONFIG_DIR": CONFIG_DIR,
        "XPR_NODEOS_READ_MODE": "head",
        "XPR_API_ACCEPT_TRANSACTIONS": "1",
        "XPR_P2P_ACCEPT_TRANSACTIONS": "1",
        "XPR_WASM_RUNTIME": "eos-vm-jit",
        "XPR_EOS_VM_OC_ENABLE": "all",
    }
    run([RUNNER, "start"], env=environment)
    wait_for_ready()
    if not near_live():
        raise RuntimeError("Leap moved outside the live-head window during restart")

    install_pulsevm_relay()
    print("PulseVM now forwards Mainnet transactions to local Leap", flush=True)


if __name__ == "__main__":
    main()
