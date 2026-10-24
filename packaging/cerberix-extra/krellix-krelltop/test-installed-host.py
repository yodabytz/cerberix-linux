#!/usr/bin/env python3
"""Exercise a candidate plugin against the actual installed Krellix executable."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

candidate = Path(sys.argv[1]).resolve()
connections = []
stop = threading.Event()

def serve(client, index):
    try:
        client.sendall(b'{"type":"hello","hostname":"krelltop-test"}\n')
        for tick in range(25):
            sample = {"type": "sample", "uptime": tick, "cpu": [], "mem": {},
                      "net": [], "disk": [], "proc": {}}
            if index % 3 != 0:
                sample["top"] = [{"pid": 123, "cpu": 12.5, "mem": 1.2,
                                  "rss": 8192, "name": "remote-fixture", "cmd": "fixture"}]
            client.sendall(json.dumps(sample).encode() + b'\n')
            if stop.wait(0.2):
                break
    except OSError:
        pass
    finally:
        client.close()

with tempfile.TemporaryDirectory(prefix="krelltop-test-") as directory:
    root = Path(directory)
    plugins = root / "data/krellix/plugins"
    plugins.mkdir(parents=True)
    # The host loads both search paths, so never load two copies of this plugin.
    installed = Path('/usr/lib/krellix/plugins/libkrelltop.so')
    assert candidate == installed.resolve(), 'test the installed package to avoid duplicate plugin loading'
    config = root / "config/krellix"
    config.mkdir(parents=True)
    (config / "krellix-top-wire-test.ini").write_text(
        "[plugins]\nkrelltop\\enabled=true\n[monitors]\norder=krelltop\n")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.5)

    def accept():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            connections.append(time.monotonic())
            threading.Thread(target=serve, args=(client, len(connections)), daemon=True).start()

    worker = threading.Thread(target=accept, daemon=True)
    worker.start()
    env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"),
               XDG_DATA_HOME=str(root / "data"), QT_QPA_PLATFORM="offscreen")
    with (root / "output.log").open("w+") as log:
        process = subprocess.Popen(["/usr/bin/krellix", "--instance", "top-wire-test",
            "--host", f"127.0.0.1:{listener.getsockname()[1]}", "--monitors", "krelltop"],
            env=env, stdout=log, stderr=log)
        try:
            for _ in range(25):
                time.sleep(1)
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"Krellix exited {process.returncode}: {log.read()}")
            maps = Path(f"/proc/{process.pid}/maps").read_text()
            assert str(candidate) in maps, "candidate was not loaded"
            assert len(connections) >= 6, "remote polling/reconnects did not occur"
            print(f"PASS: candidate loaded; {len(connections)} connections; 25 seconds without crash")
        finally:
            process.terminate()
            process.wait(timeout=10)
            stop.set()
            worker.join(timeout=2)
            listener.close()
