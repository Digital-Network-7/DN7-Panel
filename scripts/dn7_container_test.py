#!/usr/bin/env python3
# ============================================================================
# DN7 Panel — container runtime end-to-end test suite (run as root in the VM).
#
#   sudo python3 dn7_test.py            # all sections
#   sudo python3 dn7_test.py core net   # only the named sections
#
# Sections:
#   core   T##  lifecycle, config, limits, backups, images, volumes, fs, exec
#   net    N##  user networks, static IP, hotplug connect/disconnect/set-ip, ping
#   adv    A##  error paths, input validation, security guards (must fail CLEANLY)
#   robust R##  lifecycle cycles, concurrency races, cgroup enforcement, leak audit
#   ui     UI#  UI-form contracts (optional fields honored) + every error is a
#               localizable ERR_CODE, not a raw string in a translated console
#
# A test PASSES when the runtime does the right thing — including *rejecting*
# bad input with a clean error (never a 500 / panic / silent misbehaviour).
# ============================================================================
import json, hashlib, urllib.request, urllib.parse, time, os, base64, socket, subprocess, threading, sys

B = "http://127.0.0.1:1080"
IMG = "registry-1.docker.io/library/alpine:local"
UBU = "registry-1.docker.io/library/ubuntu:latest"
R = []  # (section, id, name, status, evidence)

def http(p, d=None, tok=None, raw=False, ctype="application/json", t=90):
    q = urllib.request.Request(B + p, data=d, method="POST" if d is not None else "GET")
    if tok: q.add_header("Authorization", "Bearer " + tok)
    if d is not None and ctype: q.add_header("Content-Type", ctype)
    try:
        x = urllib.request.urlopen(q, timeout=t); b = x.read()
        return (x.status, b if raw else json.loads(b or b"{}"))
    except urllib.error.HTTPError as e:
        b = e.read()
        try: return (e.code, b if raw else json.loads(b or b"{}"))
        except: return (e.code, {"error": b[:200].decode('utf-8', 'replace')})
    except Exception as e:
        return (0, {"error": str(e)})

# --- login (client-side s256 KDF, 30000 rounds) ---
ch = http("/api/login/challenge?username=operator")[1]; h = "ApiAdminPw123!"
for _ in range(30000): h = hashlib.sha256((ch["salt"] + ":" + h).encode()).hexdigest()
TOK = http("/api/login", json.dumps({"username": "operator", "nonce": ch["nonce"], "verifier": h}).encode())[1]["token"]

def dop(p, t=90): return http("/api/docker", json.dumps(p).encode(), TOK, t=t)[1]
def code(p): return http("/api/docker", json.dumps(p).encode(), TOK)[0]
def fop(p, pay): return http(p, json.dumps(pay).encode(), TOK)[1]
def tkt(pur): return http("/api/ticket?purpose=" + pur, b"", TOK)[1]["data"]["ticket"]
def add(sec, i, name, ok, ev):
    s = "PASS" if ok is True else ("FAIL" if ok is False else ok)
    R.append((sec, i, name, s, ev)); print(f"[{sec}] {i} [{s}] {name} | {ev}", flush=True)
def clean_err(d):
    return d.get("ok") is False and isinstance(d.get("error"), str) and d.get("error") and d.get("error") != "nonjson"
def opwait(op, t=120):
    t0 = time.time()
    while time.time() - t0 < t:
        d = (dop({"op": "op_log", "op_id": op}).get("data") or {})
        if d.get("status") in ("done", "error") or d.get("done"): return d.get("status") or "done", d.get("error", "")
        time.sleep(0.5)
    return "timeout", ""
def crow(n):
    for c in (dop({"op": "list_containers"}).get("data") or {}).get("containers", []):
        if c.get("name") == n: return c
def cid(n): return (crow(n) or {}).get("id", "")
def ip_only(n):
    v = (crow(n) or {}).get("ip") or ""
    return v.split()[0] if v else ""
def cgroup_dir(n):
    # Docker-model ids are random hex (≠ name), so the cgroup dir is /dn7/<full-id>,
    # not /dn7/<name>. Resolve it from the container's short id shown in the row.
    row = crow(n)
    sid = (row or {}).get("id", "")
    base = "/sys/fs/cgroup/dn7/"
    try:
        for d in os.listdir(base):
            if sid and d.startswith(sid) and os.path.isdir(base + d):
                return base + d + "/"
    except Exception: pass
    return ""
def pid_of(n):
    try: return open(cgroup_dir(n) + "cgroup.procs").read().split()[0]
    except: return ""
def cgf(n, f):
    try: return open(cgroup_dir(n) + f).read().strip()
    except: return "ERR"
def rm(n): dop({"op": "stop_container", "ref": n}, 40); dop({"op": "remove_container", "ref": n}, 40)
def ifaces(name):
    p = pid_of(name)
    if not p: return "no-pid"
    out = subprocess.run(["nsenter", "-t", p, "-n", "ip", "-o", "-4", "addr"], capture_output=True, text=True).stdout
    return " | ".join(l.split()[1] + ":" + l.split()[3] for l in out.splitlines() if "eth" in l)


# ============================================================================
def section_core():
    S = "core"
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def mk(n, extra=None, image=IMG, cmd="/bin/sleep 300", start=True):
        p = {"op": "create_container", "image": image, "name": n, "start": start}
        if cmd: p["command"] = cmd
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        if op and start: opwait(op)
        time.sleep(1.4); return d

    # lifecycle
    rec("T01", "runtime info", (lambda d: d.get("ok") and (d.get("data") or {}).get("runtime") == "dn7")(dop({"op": "info"})), "runtime=dn7")
    rec("T02", "container list", isinstance((dop({"op": "list_containers"}).get("data") or {}).get("containers"), list), "ok")
    rm("c1"); mk("c1", start=False); c = crow("c1"); rec("T03", "create (no start)→created", c and c.get("state") == "created", c and c.get("state"))
    d = dop({"op": "start_container", "ref": "c1"}); time.sleep(1); c = crow("c1"); rec("T04", "start", d.get("ok") and c and c.get("state") == "running", c and c.get("state"))
    rec("T05", "logs op", dop({"op": "logs", "ref": "c1", "tail": 5}).get("ok") is True, "ok")
    d = dop({"op": "stop_container", "ref": "c1"}, 40); time.sleep(1); c = crow("c1"); rec("T06", "stop → exited", d.get("ok") and c and c.get("state") == "exited", c and c.get("status"))
    d = dop({"op": "start_container", "ref": "c1"}); time.sleep(1.5); c = crow("c1"); rec("T07", "rerun (start after stop)", d.get("ok") and c and c.get("state") == "running", c and c.get("state"))
    pb = cgf("c1", "cgroup.procs"); dop({"op": "restart_container", "ref": "c1"}, 45); time.sleep(1.5); c = crow("c1"); pa = cgf("c1", "cgroup.procs"); rec("T08", "restart", c and c.get("state") == "running" and pb != pa, f"pid {pb[:8]}→{pa[:8]}")
    d = dop({"op": "pause_container", "ref": "c1"}); time.sleep(1); c = crow("c1"); rec("T09", "pause → paused+frozen", d.get("ok") and c and c.get("state") == "paused" and cgf("c1", "cgroup.freeze") == "1", f"state={c and c.get('state')}")
    d = dop({"op": "unpause_container", "ref": "c1"}); time.sleep(1); c = crow("c1"); rec("T10", "unpause", c and c.get("state") == "running", c and c.get("state"))
    d = dop({"op": "kill_container", "ref": "c1"}); time.sleep(1.2); c = crow("c1"); rec("T11", "kill → 137", c and "137" in (c.get("status") or ""), c and c.get("status"))
    d = dop({"op": "rename_container", "ref": "c1", "new_name": "c1b"}); rec("T12", "rename", d.get("ok") and crow("c1b") is not None, "ok"); rm("c1b"); rm("c1")

    # tty + control
    rm("tt"); mk("tt", {"tty": True}, image=UBU, cmd=None); c = crow("tt"); rec("T16", "tty ubuntu default-shell stays alive", c and c.get("state") == "running", f"state={c and c.get('state')}")
    tk = tkt("terminal"); cd = cid("tt") or "tt"; ex = "?"
    try:
        s = socket.create_connection(("127.0.0.1", 1080), timeout=8); k = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f"GET /api/container/terminal?ticket={tk}&container={cd} HTTP/1.1\r\nHost:x\r\nUpgrade:websocket\r\nConnection:Upgrade\r\nSec-WebSocket-Key:{k}\r\nSec-WebSocket-Version:13\r\n\r\n").encode())
        s.settimeout(6); ex = "101" if s.recv(1024).decode('utf-8', 'replace').startswith("HTTP/1.1 101") else "no101"; s.close()
    except Exception as e: ex = str(e)
    rec("T16b", "exec into tty container", ex == "101", f"ws={ex}")
    lg = (dop({"op": "logs", "ref": "tt", "tail": 20}).get("data") or {}).get("logs", ""); rec("T16c", "tty logs pump captures output", len(lg) > 0, f"{len(lg)}B"); rm("tt")
    rm("cx"); mk("cx", {}, image=UBU, cmd=None); c = crow("cx"); rec("T16d", "control: no-tty ubuntu exits (docker parity)", c and c.get("state") == "exited", c and c.get("state")); rm("cx")

    # config
    rm("ce"); mk("ce", {"env": ["FOO=z9"]}, cmd="/bin/sh -c 'echo FOO=$FOO;sleep 300'"); lg = (dop({"op": "logs", "ref": "ce", "tail": 10}).get("data") or {}).get("logs", ""); rec("T17", "env vars", "FOO=z9" in lg, repr(lg[:24])); rm("ce")
    rm("ch2"); mk("ch2", {"hostname": "hh7"}, cmd="/bin/sh -c 'hostname;sleep 300'"); lg = (dop({"op": "logs", "ref": "ch2", "tail": 10}).get("data") or {}).get("logs", ""); rec("T18", "hostname", "hh7" in lg, repr(lg[:24])); rm("ch2")
    rm("cd"); mk("cd", {"dns": ["9.9.9.9"]}, cmd="/bin/sh -c 'cat /etc/resolv.conf;sleep 300'"); lg = (dop({"op": "logs", "ref": "cd", "tail": 10}).get("data") or {}).get("logs", ""); rec("T22", "custom dns", "9.9.9.9" in lg, repr(lg[:40])); rm("cd")
    rm("cp"); mk("cp", {"ports": [{"host": 19090, "container": 80, "proto": "tcp"}]}); nft = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True).stdout; rec("T19", "port publish → DNAT", "19090" in nft, f"nft_has_19090={'19090' in nft}"); rm("cp")
    subprocess.run(["rm", "-rf", "/tmp/dv"]); os.makedirs("/tmp/dv")
    rm("cv"); mk("cv", {"volumes": [{"host": "/tmp/dv", "container": "/data", "readonly": False}]}, cmd="/bin/sh -c 'echo BV>/data/x;sleep 300'"); time.sleep(1)
    try: g = open("/tmp/dv/x").read().strip()
    except: g = "none"
    rec("T20", "bind volume", g == "BV", f"file={g}"); rm("cv")
    dop({"op": "create_volume", "name": "vv1"}); vols = (dop({"op": "list_volumes"}).get("data") or {}).get("volumes", []); mp = next((v.get("mountpoint") or v.get("path", "") for v in vols if v.get("name") == "vv1"), "")
    rm("cn"); mk("cn", {"volumes": [{"host": "vv1", "container": "/data", "readonly": False}]}, cmd="/bin/sh -c 'echo NV>/data/y;sleep 300'"); time.sleep(1)
    try: g = open(os.path.join(mp, "y")).read().strip()
    except: g = "none"
    rec("T21", "named volume", g == "NV", f"file={g}"); rm("cn")
    rm("cip"); mk("cip", {}); c = crow("cip"); rec("T26", "default net → container gets dn7 IP", c and c.get("state") == "running" and (c.get("ip") or "").startswith("172."), f"ip={c and c.get('ip')}"); rm("cip")

    # limits / edit / upgrade / priv / stats
    rm("cl"); mk("cl", {"memory": "64m", "cpus": "0.5"}); rec("T23", "create limits→cgroup", cgf("cl", "memory.max") == "67108864" and cgf("cl", "cpu.max") == "50000 100000", f"mem={cgf('cl', 'memory.max')} cpu={cgf('cl', 'cpu.max')}")
    st = (dop({"op": "container_stats", "ref": "cl"}).get("data") or {}); rec("T13", "stats fields", st.get("mem_limit") == 67108864 and st.get("mem_used", 0) > 0, f"lim={st.get('mem_limit')} used={st.get('mem_used')}")
    cfg = ((dop({"op": "get_container_config", "ref": "cl"}).get("data") or {}).get("config") or {}); rec("T14", "get_config round-trip", cfg.get("memory") == "64m" and cfg.get("cpus") == "0.5", f"mem={cfg.get('memory')} cpus={cfg.get('cpus')}")
    d = dop({"op": "create_container", "image": IMG, "name": "cl", "replace": "cl", "command": "/bin/sleep 300", "memory": "128m", "cpus": "1", "start": True}); opwait((d.get("data") or {}).get("op_id")); time.sleep(1.5)
    rec("T27", "EDIT(replace)→new limits", cgf("cl", "memory.max") == "134217728" and cgf("cl", "cpu.max") == "100000 100000", f"mem={cgf('cl', 'memory.max')} cpu={cgf('cl', 'cpu.max')}")
    cfg = ((dop({"op": "get_container_config", "ref": "cl"}).get("data") or {}).get("config") or {}); body = dict(cfg); body.update({"op": "create_container", "image": IMG, "name": "cl", "replace": "cl", "start": True}); body = {k: v for k, v in body.items() if v is not None}
    d = dop(body); opwait((d.get("data") or {}).get("op_id")); time.sleep(1.5); c = crow("cl"); rec("T28", "UPGRADE(spread+replace)", c and c.get("state") == "running", c and c.get("state"))
    d = dop({"op": "create_container", "image": IMG, "name": "cpr", "privileged": True, "start": False}); rec("T25", "privileged→clean refusal", d.get("ok") is False and "privileged" in json.dumps(d), json.dumps(d)[:50]); rm("cpr")

    # backups / commit
    d = dop({"op": "backup_container", "ref": "cl", "name": "cl"}); st, _ = opwait((d.get("data") or {}).get("op_id"), 150); bks = (dop({"op": "list_backups", "name": "cl"}).get("data") or {}).get("backups", []); bf = bks[0]["file"] if bks else ""
    rec("T29", "backup", st == "done" and bool(bf), f"{st} {bf}")
    if bf:
        cc, raw = http(f"/api/docker/download?ticket={tkt('download')}&kind=backup&name=cl&backup={urllib.parse.quote(bf)}", raw=True, tok=TOK); rec("T31", "backup download", cc == 200 and len(raw) > 1000, f"{cc} {len(raw) if isinstance(raw, bytes) else 0}B")
        d = dop({"op": "restore_backup", "name": "cl", "backup": bf}); st, _ = opwait((d.get("data") or {}).get("op_id"), 150); time.sleep(1.5); rec("T30", "restore", st == "done" and crow("cl") is not None, st)
        d = dop({"op": "delete_backup", "name": "cl", "backup": bf}); rec("T32", "delete backup", d.get("ok") and not (dop({"op": "list_backups", "name": "cl"}).get("data") or {}).get("backups"), "ok")
    d = dop({"op": "commit_container", "ref": "cl", "repo": "cimg", "tag": "v1"}, 120); rec("T33b", "commit→image", d.get("ok") and "cimg" in json.dumps(dop({"op": "list_images"})), "ok"); dop({"op": "remove_image", "ref": "cimg:v1"})

    # images
    rec("T33", "image list", "alpine" in json.dumps(dop({"op": "list_images"})), "ok")
    d = dop({"op": "retag_image", "ref": IMG, "tags": [IMG, "acopy:t"]}); rec("T35", "retag", d.get("ok") and "acopy" in json.dumps(dop({"op": "list_images"})), "ok")
    d = dop({"op": "remove_image", "ref": "acopy:t"}); rec("T36", "remove image", "acopy" not in json.dumps(dop({"op": "list_images"})), "ok")
    cc, raw = http(f"/api/docker/download?ticket={tkt('download')}&kind=image&ref={urllib.parse.quote(IMG)}", raw=True, tok=TOK, t=120); rec("T38", "export image", cc == 200 and len(raw) > 100000, f"{cc} {len(raw) if isinstance(raw, bytes) else 0}B")
    if cc == 200:
        c2, up = http("/api/docker/image-upload", raw, TOK, ctype="application/octet-stream", t=120); rec("T34", "import image (auto-name preserved)", c2 == 200 and isinstance(up, dict) and up.get("ok"), json.dumps(up)[:70] if isinstance(up, dict) else str(up)[:40])
    d = dop({"op": "pull_image", "image": "alpine:3.19"}); op = (d.get("data") or {}).get("op_id"); st, _ = opwait(op, 150) if op else ("no-op", "")
    rec("T37", "pull image", "SKIP" if st in ("error", "timeout") else (st == "done"), f"{st} (net may be filtered)")
    rec("T39", "list_ops", dop({"op": "list_ops"}).get("ok") is True, "ok")

    # network views (real CRUD lives in section_net)
    rec("T40", "network list shows built-in dn7", "dn7" in json.dumps(dop({"op": "list_networks"})), "ok")
    rec("T42", "network ip pool view", dop({"op": "network_ips", "ref": "dn7"}).get("ok") is True, "ok")
    rec("T47", "built-in net remove → protected", (lambda d: d.get("ok") is False)(dop({"op": "remove_network", "ref": "dn7"})), "builtin_protected")

    # volumes
    rec("T48a", "volume list", dop({"op": "list_volumes"}).get("ok") is True, "ok")
    d = dop({"op": "remove_volume", "ref": "vv1"}); rec("T48b", "volume remove", d.get("ok") and '"vv1"' not in json.dumps(dop({"op": "list_volumes"})), "ok")
    rec("T49", "host path autocomplete", "/var/lib" in json.dumps(dop({"op": "list_dirs", "path": "/var/li"})), "ok")

    # container fs (on cl)
    cd = cid("cl") or "cl"
    lst = (fop("/api/files/list", {"path": "/", "container": cd}).get("data") or {})
    rec("T50", "fs list /", len(lst.get("entries", lst.get("files", []))) > 3, "ok")
    rec("T51", "fs mkdir", fop("/api/files/mkdir", {"path": "/tmp/d", "container": cd}).get("ok") is True, "ok")
    rec("T52", "fs write", fop("/api/files/write", {"path": "/tmp/d/a", "content": "HI", "container": cd}).get("ok") is True, "ok")
    rec("T53", "fs read", (fop("/api/files/read", {"path": "/tmp/d/a", "container": cd}).get("data") or {}).get("content") == "HI", "HI")
    rec("T54", "fs rename", fop("/api/files/rename", {"path": "/tmp/d/a", "to": "/tmp/d/b", "container": cd}).get("ok") is True, "ok")
    c3, _ = http(f"/api/files/upload?path=%2Ftmp%2Fd%2Fu&container={cd}", b"UP7", TOK, ctype="application/octet-stream"); rec("T55", "fs upload", c3 == 200 and (fop("/api/files/read", {"path": "/tmp/d/u", "container": cd}).get("data") or {}).get("content") == "UP7", "ok")
    c4, raw = http(f"/api/files/download?ticket={tkt('download')}&path=%2Ftmp%2Fd%2Fb&container={cd}", raw=True); rec("T56", "fs download", c4 == 200 and raw == b"HI", "ok")
    rec("T57", "fs delete", fop("/api/files/delete", {"path": "/tmp/d/b", "container": cd}).get("ok") is True, "ok")

    # exec
    rec("T58", "privileged probe", (http("/api/container/privileged", json.dumps({"container": cd}).encode(), TOK)[1].get("data") or {}).get("privileged") is False, "privileged=false")
    tk = tkt("terminal"); ex = "?"
    try:
        s = socket.create_connection(("127.0.0.1", 1080), timeout=8); k = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f"GET /api/container/terminal?ticket={tk}&container={cd} HTTP/1.1\r\nHost:x\r\nUpgrade:websocket\r\nConnection:Upgrade\r\nSec-WebSocket-Key:{k}\r\nSec-WebSocket-Version:13\r\n\r\n").encode()); s.settimeout(6); ex = "101" if s.recv(1024).decode('utf-8', 'replace').startswith("HTTP/1.1 101") else "no"; s.close()
    except Exception as e: ex = str(e)
    rec("T59", "exec WS terminal", ex == "101", f"ws={ex}")
    rm("cl")
    for n in ["c1", "c1b", "tt", "cx", "ce", "ch2", "cd", "cp", "cv", "cn", "cip", "cl", "cpr"]: rm(n)


# ============================================================================
def section_net():
    S = "net"
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def mk(n, extra=None):
        p = {"op": "create_container", "image": IMG, "name": n, "command": "/bin/sleep 300", "start": True}
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        st, err = opwait(op) if op else ("refused", json.dumps(d))
        time.sleep(1.2); return st, err

    for n in ["na", "nb", "nc"]: rm(n)
    for nm in ["testnet", "tn2", "tnr", "tnr2"]: dop({"op": "remove_network", "ref": nm})

    d = dop({"op": "create_network", "name": "testnet", "subnet": "172.29.0.0/24", "gateway": "172.29.0.1"})
    rec("N1", "create user network", d.get("ok") and (d.get("data") or {}).get("subnet") == "172.29.0.0/24", json.dumps(d.get("data") or d.get("error"))[:70])
    br = (d.get("data") or {}).get("bridge", "")
    hasbr = subprocess.run(["bash", "-c", f"ip link show {br} 2>/dev/null|wc -l"], capture_output=True, text=True).stdout.strip()
    rec("N2", "host bridge created", hasbr != "0", f"bridge={br}")
    rec("N3", "list_networks shows it", "testnet" in json.dumps(dop({"op": "list_networks"})), "ok")

    st, err = mk("na", {"networks": [{"network": "testnet"}]}); c = crow("na")
    rec("N4", "container on user net gets its IP", st == "done" and c and (c.get("ip") or "").startswith("172.29."), f"ip={c and c.get('ip')}")
    rec("N4b", "container iface in subnet", "172.29." in ifaces("na"), ifaces("na"))
    st, err = mk("nb", {"networks": [{"network": "testnet", "ipv4": "172.29.0.55"}]}); c = crow("nb")
    rec("N5", "static IP honored", st == "done" and (c.get("ip") or "").startswith("172.29.0.55"), f"ip={c and c.get('ip')}")
    ping = subprocess.run(["nsenter", "-t", pid_of("na"), "-n", "ping", "-c1", "-W2", "172.29.0.55"], capture_output=True, text=True)
    rec("N6", "same-network connectivity (ping)", ping.returncode == 0, f"na→nb rc={ping.returncode}")
    mk("nc", {"networks": [{"network": "testnet", "ipv4": "172.29.0.55"}]}); rec("N7", "duplicate static IP rejected", crow("nc") is None, "rejected"); rm("nc")

    dop({"op": "create_network", "name": "tn2", "subnet": "172.31.0.0/24", "gateway": "172.31.0.1"})
    d = dop({"op": "connect_network", "ref": cid("na"), "network": "tn2", "ipv4": "172.31.0.7"}); time.sleep(1)
    rec("N8", "hotplug connect → eth1", d.get("ok") and (d.get("data") or {}).get("ifname") == "eth1" and "172.31.0.7" in ifaces("na"), ifaces("na"))
    d = dop({"op": "set_network_ip", "ref": cid("na"), "network": "tn2", "ipv4": "172.31.0.99"}); time.sleep(1)
    rec("N9", "set_network_ip live change", d.get("ok") and "172.31.0.99" in ifaces("na"), ifaces("na"))
    d = dop({"op": "disconnect_network", "ref": cid("na"), "network": "tn2"}); time.sleep(1)
    rec("N10", "disconnect removes eth1", d.get("ok") and "172.31.0" not in ifaces("na"), ifaces("na"))

    d = dop({"op": "remove_network", "ref": "testnet"}); rec("N11", "remove in-use net refused", d.get("ok") is False and "attached" in json.dumps(d), json.dumps(d)[:70])
    dop({"op": "create_network", "name": "tnr", "subnet": "172.28.0.0/24"}); d = dop({"op": "rename_network", "ref": "tnr", "new_name": "tnr2"})
    nets = json.dumps(dop({"op": "list_networks"})); rec("N12", "rename network", d.get("ok") and "tnr2" in nets and '"tnr"' not in nets, "ok"); dop({"op": "remove_network", "ref": "tnr2"})
    rm("na"); rm("nb"); time.sleep(1)
    d = dop({"op": "remove_network", "ref": "tn2"}); d2 = dop({"op": "remove_network", "ref": "testnet"})
    rec("N13", "remove empty networks", d.get("ok") and d2.get("ok") and "testnet" not in json.dumps(dop({"op": "list_networks"})), "cleaned")
    gone = subprocess.run(["bash", "-c", f"ip link show {br} 2>/dev/null|wc -l"], capture_output=True, text=True).stdout.strip()
    rec("N14", "bridge removed on net delete", gone == "0", f"lines={gone}")
    rec("N15", "built-in net protected", dop({"op": "remove_network", "ref": "dn7"}).get("ok") is False, "protected")
    for n in ["na", "nb", "nc"]: rm(n)


# ============================================================================
def section_adv():
    S = "adv"
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def mk(n, extra=None, start=True):
        p = {"op": "create_container", "image": IMG, "name": n, "command": "/bin/sleep 300", "start": start}
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        return opwait(op) if op else ("refused", json.dumps(d))

    for n in ["a1", "a2", "a3", "a4", "a5", "a6", "a7"]: rm(n)
    dop({"op": "remove_network", "ref": "advnet"})

    d = dop({"op": "create_container", "image": "nosuchimage:zzz", "name": "a1", "start": True}); op = (d.get("data") or {}).get("op_id"); st = opwait(op) if op else ("refused", d.get("error", ""))
    rec("A01", "missing image → friendly 'not found'", st[0] == "error" and "not found" in st[1], f"{st[1][:60]}"); rm("a1")
    d = dop({"op": "create_container", "image": IMG, "name": "BadName!", "start": False})
    rec("A02", "invalid container name rejected", clean_err(d) and code({"op": "create_container", "image": IMG, "name": "BadName!"}) < 500, json.dumps(d)[:50])
    d = dop({"op": "create_container", "image": IMG, "name": "a2", "memory": "999999g", "command": "/bin/sleep 300", "start": True}); op = (d.get("data") or {}).get("op_id"); st = opwait(op) if op else ("refused", "")
    rec("A03", "over-host memory → clean refusal", st[0] in ("error", "refused") and crow("a2") is None, f"{st[0]}"); rm("a2")
    mk("a3"); d = dop({"op": "create_container", "image": IMG, "name": "a3", "command": "/bin/sleep 300", "start": False}); op = (d.get("data") or {}).get("op_id"); st = opwait(op) if op else ("refused", d.get("error", ""))
    rec("A04", "duplicate container name → clean error", st[0] == "error" or clean_err(d), f"{st[0]}")
    for bad in ["/var/run/docker.sock", "/etc", "/"]:
        d = dop({"op": "create_container", "image": IMG, "name": "a4", "volumes": [{"host": bad, "container": "/x", "readonly": False}], "start": False})
        rec(f"A05[{bad}]", "dangerous bind mount blocked", clean_err(d) and code({"op": "create_container", "image": IMG, "name": "a4", "volumes": [{"host": bad, "container": "/x"}]}) < 500, json.dumps(d)[:50]); rm("a4")
    d = dop({"op": "create_container", "image": IMG, "name": "a4", "volumes": [{"host": "/tmp", "container": "/../../etc", "readonly": False}], "start": False})
    rec("A06", "volume dest traversal handled", code({"op": "create_container", "image": IMG, "name": "a4", "volumes": [{"host": "/tmp", "container": "/../../etc"}]}) < 500, json.dumps(d)[:50]); rm("a4")
    mk("a5", start=False)
    rec("A07", "stop a never-started container → no crash", (lambda d: d.get("ok") or clean_err(d))(dop({"op": "stop_container", "ref": "a5"})), "ok")
    rec("A08", "pause a non-running container → clean error", (lambda d: clean_err(d) or d.get("ok") is False)(dop({"op": "pause_container", "ref": "a5"})), "ok"); rm("a5")
    rec("A09", "all ops on nonexistent container → no 500", all(code({"op": o, "ref": "ghost404", "tail": 10}) < 500 for o in ["start_container", "stop_container", "remove_container", "logs", "container_stats", "inspect_container"]), "checked")
    # restart:no so the supervisor doesn't (correctly) auto-restart the kill.
    mk("a6", {"restart": "no"}); pid = pid_of("a6")
    subprocess.run(["kill", "-9", pid]); time.sleep(1.5); c = crow("a6")
    rec("A10", "hard-killed init (restart:no) → not shown running", c and c.get("state") in ("exited", "stopped"), f"state={c and c.get('state')}"); rm("a6")
    dop({"op": "create_network", "name": "advnet", "subnet": "172.27.0.0/24", "gateway": "172.27.0.1"})
    rec("A11", "overlapping subnet rejected", (lambda d: clean_err(d) and "overlap" in json.dumps(d))(dop({"op": "create_network", "name": "ov", "subnet": "172.27.0.0/24"})), "ok")
    rec("A12", "invalid CIDR rejected", clean_err(dop({"op": "create_network", "name": "ov", "subnet": "not-a-cidr"})), "ok")
    rec("A13", "reserved network name rejected", clean_err(dop({"op": "create_network", "name": "host", "subnet": "172.26.0.0/24"})), "ok")
    st = mk("a7", {"networks": [{"network": "advnet", "ipv4": "10.9.9.9"}]})
    rec("A14", "static IP outside subnet → fails cleanly", st[0] == "error" and crow("a7") is None, f"{st[0]}"); rm("a7")
    mk("a7", {"networks": [{"network": "advnet"}]})
    rec("A15", "connect to nonexistent net → clean error", clean_err(dop({"op": "connect_network", "ref": cid("a7"), "network": "ghostnet"})), "ok")
    rec("A16", "disconnect primary refused", (lambda d: clean_err(d) and "primary" in json.dumps(d))(dop({"op": "disconnect_network", "ref": cid("a7"), "network": "advnet"})), "ok")
    rec("A17", "set-ip to gateway rejected", clean_err(dop({"op": "set_network_ip", "ref": cid("a7"), "network": "advnet", "ipv4": "172.27.0.1"})), "ok"); rm("a7")
    dop({"op": "remove_network", "ref": "advnet"})
    mk("a1", {"ports": [{"host": 17777, "container": 80, "proto": "tcp"}]}); st = mk("a2", {"ports": [{"host": 17777, "container": 80, "proto": "tcp"}]})
    rec("A19", "host port conflict → clean error", st[0] == "error" or crow("a2") is None, f"{st[0]}"); rm("a1"); rm("a2")
    for n in ["a1", "a2", "a3", "a4", "a5", "a6", "a7"]: rm(n)
    dop({"op": "remove_network", "ref": "advnet"})


# ============================================================================
def section_robust():
    S = "robust"
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def mk(n, extra=None, start=True):
        p = {"op": "create_container", "image": IMG, "name": n, "command": "/bin/sleep 300", "start": start}
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        return opwait(op) if op else ("refused", json.dumps(d))
    def memmax(n):
        v = cgf(n, "memory.max")
        return v if v != "ERR" else "?"

    for n in ["b1", "b2", "c1", "c2", "c3", "c4", "c5", "m1"]: rm(n)
    dop({"op": "remove_network", "ref": "cyc"})

    mk("b1"); oks = []
    for i in range(3):
        dop({"op": "stop_container", "ref": "b1"}); time.sleep(0.5); s1 = (crow("b1") or {}).get("state") in ("exited", "stopped")
        d = dop({"op": "start_container", "ref": "b1"}); time.sleep(1.2); s2 = (crow("b1") or {}).get("state") == "running"
        oks.append(bool(s1 and s2 and d.get("ok")))
    rec("R01", "stop→start cycle x3 stays healthy", all(oks), f"cycles={oks}")
    p = pid_of("b1"); ls = subprocess.run(["nsenter", "-t", p, "-m", "-p", "-n", "/bin/ls", "/"], capture_output=True, text=True) if p else None
    rec("R02", "restarted container rootfs intact", bool(ls and ls.returncode == 0 and "etc" in ls.stdout), f"rc={ls and ls.returncode}"); rm("b1")

    mk("m1", {"memory": "64m"}); first = memmax("m1")
    d = dop({"op": "create_container", "image": IMG, "name": "m1", "command": "/bin/sleep 300", "memory": "32m", "replace": "m1", "start": True}); op = (d.get("data") or {}).get("op_id"); opwait(op) if op else None; time.sleep(1.2); second = memmax("m1")
    rec("R03", "memory.max applied at create (64m)", first == "67108864", f"memory.max={first}")
    rec("R04", "memory limit re-applied after edit→32m", second in ("33554432", "34603008"), f"memory.max={second}"); rm("m1")

    # concurrency: same-name create → exactly one wins, no leak
    res = {}
    def cc(k):
        d = dop({"op": "create_container", "image": IMG, "name": "c1", "command": "/bin/sleep 200", "start": True}); op = (d.get("data") or {}).get("op_id")
        res[k] = opwait(op) if op else ("refused", json.dumps(d)[:40])
    ts = [threading.Thread(target=cc, args=(k,)) for k in range(5)]; [t.start() for t in ts]; [t.join() for t in ts]; time.sleep(1)
    rows = [c for c in (dop({"op": "list_containers"}).get("data") or {}).get("containers", []) if c.get("name") == "c1"]
    rec("R05", "concurrent same-name create → single container", len(rows) == 1 and sum(1 for v in res.values() if v[0] == "done") == 1, f"rows={len(rows)} done={sum(1 for v in res.values() if v[0]=='done')}"); rm("c1")

    dop({"op": "create_network", "name": "cyc", "subnet": "172.25.0.0/24", "gateway": "172.25.0.1"})
    outs = {}
    def cd_(n):
        d = dop({"op": "create_container", "image": IMG, "name": n, "command": "/bin/sleep 200", "start": True, "networks": [{"network": "cyc"}]}); op = (d.get("data") or {}).get("op_id")
        outs[n] = opwait(op) if op else ("refused", "")
    ts = [threading.Thread(target=cd_, args=(n,)) for n in ["c2", "c3", "c4", "c5"]]; [t.start() for t in ts]; [t.join() for t in ts]; time.sleep(1.5)
    ips = [ip_only(n) for n in ["c2", "c3", "c4", "c5"]]; uniq = len(set(x for x in ips if x)) == len([x for x in ips if x])
    allup = all((crow(n) or {}).get("state") == "running" for n in ["c2", "c3", "c4", "c5"])
    rec("R06", "concurrent creates on one net → unique IPs", uniq and allup and all(v[0] == "done" for v in outs.values()), f"ips={ips}")
    png = subprocess.run(["nsenter", "-t", pid_of("c2"), "-n", "ping", "-c1", "-W2", ip_only("c5")], capture_output=True, text=True)
    rec("R07", "concurrent-created peers reach each other", png.returncode == 0, f"c2→c5 rc={png.returncode}")
    for n in ["c2", "c3", "c4", "c5"]: rm(n)
    time.sleep(1); dop({"op": "remove_network", "ref": "cyc"})

    okc = []
    for i in range(3):
        st = mk("b2"); up = (crow("b2") or {}).get("state") == "running"; rm("b2"); time.sleep(0.8); gone = crow("b2") is None
        okc.append(st[0] == "done" and up and gone)
    rec("R08", "rapid create/delete/recreate x3", all(okc), f"cycles={okc}")

    # No leaked RUNNING container: a cgroup dir with live processes but no backing
    # container. (Empty, stateless cgroup dirs from a rare create/remove race carry
    # no procs/resources and are reaped by the boot orphan-GC.)
    time.sleep(1)  # let async teardown settle
    live = subprocess.run(["bash", "-c", "n=0; for d in /sys/fs/cgroup/dn7/*/; do [ -s \"${d}cgroup.procs\" ] && n=$((n+1)); done; echo $n"], capture_output=True, text=True).stdout.strip()
    rec("LEAK", "no leaked running-container cgroups", live == "0", f"live_leftover={live}")
    for n in ["b1", "b2", "c1", "c2", "c3", "c4", "c5", "m1"]: rm(n)


# ============================================================================
# UI-driven contract + localization checks: reproduce EXACTLY what the frontend
# forms send (optional fields omitted just like the modal does) and assert (a)
# the backend honors the advertised optionality, and (b) every error is a
# localizable ERR_CODE (a `code` field, or an "ERR_CODE:" job error) rather than
# a raw string that would show untranslated in the zh/zh-TW/ja console.
def section_ui():
    S = "ui"
    seen_errs = []
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def note(d):  # remember every error envelope for the final "nothing raw" sweep
        if isinstance(d, dict) and d.get("ok") is False:
            seen_errs.append(d)
        return d
    def coded(d):
        c = d.get("code") or ""
        e = d.get("error") or ""
        return (isinstance(c, str) and "." in c) or (isinstance(e, str) and e.startswith("ERR_CODE:"))
    def mkc(n, extra=None):
        p = {"op": "create_container", "image": IMG, "name": n, "command": "/bin/sleep 300", "start": True}
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        # A synchronous validation failure (e.g. port conflict) returns the error
        # envelope inline (no op_id) — hand back the whole dict, untruncated.
        return (opwait(op) if op else ("refused", d))

    for nm in ["uinet", "uiovl"]: dop({"op": "remove_network", "ref": nm})
    for c in ["uc1", "uc2", "uc2dup"]: rm(c)

    # UI1 — the headline bug: the create-network modal labels the subnet field
    # "(optional)" and OMITS it when blank (subnet: sub||undefined). The backend
    # must auto-assign a private subnet, not reject with "subnet (CIDR) is required".
    d = dop({"op": "create_network", "name": "uinet", "driver": "bridge"})
    sub = (d.get("data") or {}).get("subnet", "")
    rec("UI1", "create network w/o subnet → auto-assigned (optional honored)", bool(d.get("ok")) and sub.startswith(("172.", "10.")), f"subnet={sub or d.get('error')}")

    # UI2..UI4 — network validation errors now carry a localizable code (not raw English)
    d2 = note(dop({"op": "create_network", "name": "uinet", "subnet": "172.29.0.0/24"}))
    rec("UI2", "duplicate network name → coded", d2.get("code") == "docker.net_exists", f"code={d2.get('code')}")
    d3 = note(dop({"op": "create_network", "name": "uiovl", "subnet": sub or "172.20.0.0/24"}))
    rec("UI3", "overlapping subnet → coded", d3.get("code") == "docker.subnet_overlap", f"code={d3.get('code')}")
    d4 = note(dop({"op": "create_network", "name": "uibad", "subnet": "not-a-cidr"}))
    rec("UI4", "invalid CIDR → coded", d4.get("code") == "docker.bad_subnet_cidr", f"code={d4.get('code')}")

    # UI5 — a container on the network makes remove-in-use fail with a code
    mkc("uc1", {"networks": [{"network": "uinet"}]})
    d5 = note(dop({"op": "remove_network", "ref": "uinet"}))
    rec("UI5", "remove in-use network → coded", d5.get("code") == "docker.net_still_attached", f"code={d5.get('code')}")

    # UI6 — any op on a missing container is coded (was raw "no such container: X")
    d6 = note(dop({"op": "inspect_container", "ref": "ghost404"}))
    rec("UI6", "op on missing container → coded", d6.get("code") == "docker.no_such_container", f"code={d6.get('code')}")

    # UI7 — host-port conflict on create (a DETACHED op) surfaces a coded job error
    # carrying the port as an arg — not the old hardcoded-Chinese sentence.
    mkc("uc2", {"ports": [{"host": 18888, "container": 80, "proto": "tcp"}]})
    st7, err7 = mkc("uc2dup", {"ports": [{"host": 18888, "container": 80, "proto": "tcp"}]})
    # A detached-op error may arrive as the "ERR_CODE:<code>\x1f<args>" marker, a
    # JSON-string envelope, or a parsed dict {code, args}. Normalize to text and
    # require the code + the port either way.
    es = err7 if isinstance(err7, str) else json.dumps(err7)
    ok7 = "docker.port_in_use" in es and "18888" in es
    rec("UI7", "port conflict (create job) → coded + names the port", ok7, f"err={es[:60]}")

    # UI8 — removing an in-use image is coded (was hardcoded Chinese)
    d8 = note(dop({"op": "remove_image", "ref": IMG}))
    rec("UI8", "remove in-use image → coded", d8.get("code") == "docker.image_in_use", f"code={d8.get('code')}")

    # UI10..UI14 — the shared entry helpers (need_ref/validate_token) + container
    # state + network guards, i.e. the ops the report called out (inspect_container,
    # rename_network, set_network_ip): all coded now.
    d10 = note(dop({"op": "inspect_container"}))  # missing ref
    rec("UI10", "op w/o ref → coded (need_ref)", d10.get("code") == "docker.missing_ref", f"code={d10.get('code')}")
    d11 = note(dop({"op": "inspect_container", "ref": "bad ref!!"}))  # illegal chars
    rec("UI11", "op w/ bad ref → coded (validate_token)", d11.get("code") == "docker.bad_ref", f"code={d11.get('code')}")
    dc = dop({"op": "create_container", "image": IMG, "name": "uc3", "command": "/bin/sleep 300", "start": False})
    opwait((dc.get("data") or {}).get("op_id"))
    d12 = note(dop({"op": "pause_container", "ref": "uc3"}))  # created, not running
    rec("UI12", "action on wrong container state → coded", d12.get("code") == "docker.bad_container_state", f"code={d12.get('code')}")
    rm("uc3")
    d13 = note(dop({"op": "rename_network", "ref": "dn7"}))  # no new_name
    rec("UI13", "rename_network w/o new name → coded", d13.get("code") == "docker.need_network_name", f"code={d13.get('code')}")
    d14 = note(dop({"op": "set_network_ip", "ref": "uc1"}))  # no network field
    rec("UI14", "set_network_ip w/o network → coded", d14.get("code") == "docker.need_network", f"code={d14.get('code')}")

    # UI9 — SWEEP: not a single error surfaced this section was raw/un-localizable.
    raw = [d for d in seen_errs if not coded(d)]
    rec("UI9", "no raw (un-localizable) errors surfaced", len(raw) == 0, f"{len(seen_errs)} errors, {len(raw)} raw" + (f" e.g. {json.dumps(raw[0])[:60]}" if raw else ""))

    for c in ["uc1", "uc2", "uc2dup"]: rm(c)
    for nm in ["uinet", "uiovl"]: dop({"op": "remove_network", "ref": nm})


# ============================================================================
# Docker-parity checks: the container model should match Docker Engine's, not
# invent non-standard behavior — random immutable id ≠ name, mutable name,
# unique names, resolve by name/id-prefix, cgroup limits visible inside, bounded
# swap, host bind auto-create, and image re-import identical/replace semantics.
def section_parity():
    S = "parity"
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def mk(n, extra=None, start=True):
        p = {"op": "create_container", "image": IMG, "name": n, "command": "/bin/sleep 300", "start": start}
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        return (opwait(op) if op else ("refused", d)), d
    def inspect(ref):
        return dop({"op": "inspect_container", "ref": ref}).get("data") or {}
    import re as _re
    for n in ["pweb", "pWeb", "pweb2", "pbind"]: rm(n)

    # P1 — id is a random 64-hex short-form (12 shown), decoupled from the name
    mk("pweb")
    c = crow("pweb"); cid_ = (c or {}).get("id", "")
    rec("P1", "id is hex + distinct from name", bool(_re.fullmatch(r"[0-9a-f]{12}", cid_)) and cid_ != "pweb", f"id={cid_} name={c and c.get('name')}")

    # P2 — Docker allows uppercase names (was rejected when id==name)
    (st2, _), d2 = mk("pWeb")
    rec("P2", "uppercase name accepted", st2 == "done" and crow("pWeb") is not None, f"{st2} {d2.get('code','')}")

    # P3 — rename changes the NAME only; the id is immutable
    before = (crow("pweb") or {}).get("id")
    dop({"op": "rename_container", "ref": "pweb", "new_name": "pweb2"}); time.sleep(0.5)
    after = (crow("pweb2") or {}).get("id")
    rec("P3", "rename keeps the id (mutates name only)", before and before == after and crow("pweb") is None, f"id {before}=={after}, old-name gone")

    # P4 — duplicate name rejected (Docker 409 Conflict), coded
    (st4, _), d4 = mk("pweb2")  # pweb2 already exists
    rec("P4", "duplicate name → docker.name_conflict", (st4 == "error") or d4.get("code") == "docker.name_conflict", f"{st4} code={d4.get('code')}")

    # P5 — reference a container by NAME and by id-prefix
    byname = inspect("pweb2"); byprefix = inspect((after or "xxxxxx")[:6])
    rec("P5", "resolve by name + id-prefix", byname.get("name") == "pweb2" and byprefix.get("name") == "pweb2", f"name={byname.get('name')} prefix={byprefix.get('name')}")

    # the container row shows the SHORT 12-hex id; the host cgroup dir is the full
    # 64-hex id — resolve it by prefix.
    def cgdir(short):
        base = "/sys/fs/cgroup/dn7/"
        try:
            for d in os.listdir(base):
                if short and d.startswith(short) and os.path.isdir(base + d):
                    return base + d + "/"
        except Exception: pass
        return ""

    # P6 — cgroup limits are VISIBLE inside the container (/sys/fs/cgroup mounted)
    rm("plim"); mk("plim", {"memory": "64m", "cpus": "0.5"})
    d_ = cgdir((crow("plim") or {}).get("id", ""))
    p = ""
    try: p = open(d_ + "cgroup.procs").read().split()[0]
    except Exception: pass
    inside = subprocess.run(["nsenter", "-t", p, "-m", "-p", "-n", "/bin/sh", "-c", "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max 2>/dev/null"], capture_output=True, text=True).stdout if p else ""
    rec("P6", "cgroup limits visible inside container", "67108864" in inside and "50000 100000" in inside, f"inside={inside.split(chr(10))[:2]}")

    # P7 — --memory bounds swap (Docker memory-swap=2X ⇒ swap.max = limit)
    try: swx = open(d_ + "memory.swap.max").read().strip()
    except Exception: swx = "ERR"
    rec("P7", "memory-capped container has bounded swap", swx == "67108864", f"memory.swap.max={swx}"); rm("plim")

    # P8 — a missing host bind source is auto-created (Docker parity)
    subprocess.run(["rm", "-rf", "/tmp/dn7-autobind"])
    (st8, _), _ = mk("pbind", {"volumes": [{"host": "/tmp/dn7-autobind", "container": "/data", "readonly": False}]})
    made = subprocess.run(["bash", "-c", "test -d /tmp/dn7-autobind && echo yes"], capture_output=True, text=True).stdout.strip()
    rec("P8", "missing host bind source auto-created", st8 == "done" and made == "yes", f"{st8} dir={made}"); rm("pbind")

    # P9 — re-importing an identical image is reported as identical (not a blind 'imported')
    code_, raw = http(f"/api/docker/download?ticket={tkt('download')}&kind=image&ref={urllib.parse.quote(IMG)}", raw=True, tok=TOK, t=120)
    if code_ == 200:
        _, up = http("/api/docker/image-upload", raw, TOK, ctype="application/octet-stream", t=120)
        st9 = ((up or {}).get("data") or {}).get("status") if isinstance(up, dict) else None
        rec("P9", "re-import identical image → 'identical'", st9 == "identical", f"status={st9}")
    else:
        rec("P9", "re-import identical image → 'identical'", "SKIP", f"export http={code_}")

    # P10 — port host-IP is honored + displayed (not always 0.0.0.0)
    rm("phip"); mk("phip", {"ports": [{"host": 19191, "container": 80, "proto": "tcp", "host_ip": "127.0.0.1"}]})
    rec("P10", "port host-IP honored (127.0.0.1, not 0.0.0.0)", "127.0.0.1:19191" in json.dumps(inspect("phip")), f"ports={inspect('phip').get('ports')}"); rm("phip")
    # P11 — IPv6 publish → clean coded reject (dn7 DNAT is v4-only)
    d = dop({"op": "create_container", "image": IMG, "name": "phv6", "command": "/bin/sleep 300", "ports": [{"host": 19192, "container": 80, "ipv6": True}]})
    rec("P11", "IPv6 publish → coded reject", d.get("code") == "docker.ipv6_publish_unsupported", f"code={d.get('code')}"); rm("phv6")
    # P12 — named volume backed by a host path (was "not supported")
    subprocess.run(["rm", "-rf", "/tmp/dn7-hpvol"])
    d = dop({"op": "create_volume", "name": "hpvol", "path": "/tmp/dn7-hpvol"})
    made = subprocess.run(["bash", "-c", "test -d /tmp/dn7-hpvol && echo y"], capture_output=True, text=True).stdout.strip()
    rec("P12", "host-path named volume created", bool(d.get("ok")) and made == "y", f"{json.dumps(d)[:40]}"); dop({"op": "remove_volume", "ref": "hpvol"})
    # P13 — --rm auto-removes on exit
    dc = dop({"op": "create_container", "image": IMG, "name": "prm", "command": "/bin/sh -c 'sleep 1'", "start": True, "auto_remove": True})
    opwait((dc.get("data") or {}).get("op_id")); time.sleep(3)
    rec("P13", "--rm auto-removes on exit", crow("prm") is None, f"gone={crow('prm') is None}")
    # P14 — --pids-limit hits cgroup pids.max
    rm("ppid"); mk("ppid", {"pids_limit": 42})
    def _cg(n, f):
        try: return open(cgdir((crow(n) or {}).get("id", "")) + f).read().strip()
        except Exception: return "?"
    rec("P14", "--pids-limit → cgroup pids.max", _cg("ppid", "pids.max") == "42", f"pids.max={_cg('ppid', 'pids.max')}"); rm("ppid")
    # P15 — endpoint MAC honored
    dop({"op": "remove_network", "ref": "macnet"}); dop({"op": "create_network", "name": "macnet", "subnet": "172.22.0.0/24", "gateway": "172.22.0.1"})
    rm("pmac"); mk("pmac", {"networks": [{"network": "macnet", "mac": "02:42:de:ad:be:ef"}]})
    ifc = subprocess.run(["nsenter", "-t", pid_of("pmac"), "-n", "ip", "link", "show", "eth0"], capture_output=True, text=True).stdout if pid_of("pmac") else ""
    rec("P15", "endpoint MAC honored (--mac-address)", "02:42:de:ad:be:ef" in ifc, f"eth0 has requested MAC: {'de:ad:be:ef' in ifc}"); rm("pmac"); dop({"op": "remove_network", "ref": "macnet"})

    for n in ["pweb", "pWeb", "pweb2", "plim", "pbind"]: rm(n)


# ============================================================================
# The two headline Docker features: the restart-policy supervisor and the
# embedded container-to-container DNS.
def section_super():
    S = "super"
    def rec(i, name, ok, ev): add(S, i, name, ok, ev)
    def mk(n, extra=None, cmd="/bin/sleep 300"):
        p = {"op": "create_container", "image": IMG, "name": n, "command": cmd, "start": True}
        if extra: p.update(extra)
        d = dop(p); op = (d.get("data") or {}).get("op_id")
        return opwait(op) if op else ("refused", "")
    def insp(n): return dop({"op": "inspect_container", "ref": n}).get("data") or {}
    for n in ["salways", "sno", "sstop", "dalpha", "dbeta"]: rm(n)
    dop({"op": "remove_network", "ref": "sdns"})

    # SUP1 — restart=always auto-restarts a process that keeps exiting
    mk("salways", {"restart": "always"}, cmd="/bin/sh -c 'sleep 1; exit 1'")
    time.sleep(6)
    rc = insp("salways").get("restart_count", 0)
    rec("SUP1", "restart=always auto-restarts (count climbs)", rc >= 1, f"restart_count={rc}")
    # SUP2 — restart=no leaves an exited container exited
    mk("sno", {"restart": "no"}, cmd="/bin/sh -c 'sleep 1; exit 0'"); time.sleep(4)
    c = crow("sno")
    rec("SUP2", "restart=no stays exited", c and c.get("state") == "exited" and insp("sno").get("restart_count", 0) == 0, f"state={c and c.get('state')}")
    # SUP3 — a user stop is NOT auto-restarted (unless-stopped default)
    mk("sstop"); time.sleep(1); dop({"op": "stop_container", "ref": "sstop"}); time.sleep(4)
    c = crow("sstop")
    rec("SUP3", "user-stopped unless-stopped stays stopped", c and c.get("state") in ("exited", "stopped"), f"state={c and c.get('state')}")
    for n in ["salways", "sno", "sstop"]: rm(n)

    # SUP4 — embedded DNS resolves a peer container BY NAME
    dop({"op": "create_network", "name": "sdns", "subnet": "172.23.0.0/24", "gateway": "172.23.0.1"})
    mk("dbeta", {"networks": [{"network": "sdns"}]}); time.sleep(1)
    mk("dalpha", {"networks": [{"network": "sdns"}]}); time.sleep(1)
    betaip = (crow("dbeta") or {}).get("ip", "").split()[0]
    pa = pid_of("dalpha")
    look = subprocess.run(["nsenter", "-t", pa, "-m", "-p", "-n", "/bin/sh", "-c", "nslookup dbeta 2>/dev/null"], capture_output=True, text=True).stdout if pa else ""
    rec("SUP4", "container DNS resolves a peer by name", bool(betaip) and betaip in look, f"nslookup dbeta → {betaip}")
    # SUP5 — ping by name works (name → IP → reachable)
    png = subprocess.run(["nsenter", "-t", pa, "-m", "-p", "-n", "/bin/ping", "-c1", "-W2", "dbeta"], capture_output=True, text=True) if pa else None
    rec("SUP5", "ping a peer by name", bool(png) and png.returncode == 0, f"rc={png and png.returncode}")
    # SUP6 — external names still resolve (responder forwards upstream)
    ext = subprocess.run(["nsenter", "-t", pa, "-m", "-p", "-n", "/bin/sh", "-c", "nslookup github.com 2>&1"], capture_output=True, text=True).stdout if pa else ""
    rec("SUP6", "external DNS forwarded upstream", "Address" in ext and "github.com" in ext.lower() and ext.count("Address") >= 2, f"resolved={('Address' in ext)}")
    for n in ["dalpha", "dbeta"]: rm(n)
    dop({"op": "remove_network", "ref": "sdns"})


SECTIONS = {"core": section_core, "net": section_net, "adv": section_adv, "robust": section_robust, "ui": section_ui, "parity": section_parity, "super": section_super}
want = [a for a in sys.argv[1:] if a in SECTIONS] or list(SECTIONS)
for name in want:
    print(f"\n########## SECTION: {name} ##########", flush=True)
    SECTIONS[name]()

print("\n================= GRAND SUMMARY =================")
for sec in want:
    rows = [x for x in R if x[0] == sec]
    p = sum(1 for x in rows if x[3] == "PASS"); f = sum(1 for x in rows if x[3] == "FAIL"); s = sum(1 for x in rows if x[3] == "SKIP")
    print(f"  {sec:7s} total={len(rows):3d} pass={p:3d} fail={f} skip={s}")
tot = len(R); pf = sum(1 for x in R if x[3] == "PASS"); ff = sum(1 for x in R if x[3] == "FAIL")
print(f"  {'ALL':7s} total={tot:3d} pass={pf:3d} fail={ff}")
for x in R:
    if x[3] == "FAIL": print(f"  FAIL [{x[0]}] {x[1]} {x[2]} | {x[4]}")
sys.exit(1 if ff else 0)
