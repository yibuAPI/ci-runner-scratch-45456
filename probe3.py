#!/usr/bin/env python3
# i45456 batch3: from fresh GHA EIPs, test (a) 51.161.35.209 :22/:80/:443 + TLS SNI for ops vhosts,
# (b) Woodpecker host 51.210.13.182 :22/:80/:443/:8000, (c) control.
import os, sys, socket, ssl, json, time, urllib.request
JOB=os.environ.get("JOB","0"); TOPIC=os.environ.get("TOPIC","iops254-7c1e")
def log(*a): print(" ".join(str(x) for x in a), flush=True)
def send(tag,text):
    text=str(text)
    try:
        req=urllib.request.Request("https://ntfy.sh/"+TOPIC,data=(("[b3j%s] "%JOB)+text).encode("utf-8","replace"),method="POST",headers={"Title":("i45456-"+tag)[:60]})
        urllib.request.urlopen(req,timeout=12).read()
    except Exception as e: log("NTFYERR",str(e)[:60])
def cls(ip,port,t=4):
    st=time.time()
    try: s=socket.create_connection((ip,port),timeout=t); s.close(); return "OPEN %dms"%round((time.time()-st)*1000)
    except ConnectionRefusedError: return "REFUSED"
    except socket.timeout: return "TIMEOUT"
    except Exception as e: return "ERR:"+str(e)[:30]
def tls_sni(ip,port,host,t=10):
    try:
        s=socket.create_connection((ip,port),timeout=t)
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        ss=ctx.wrap_socket(s,server_hostname=host)
        cert=ss.getpeercert(); ver=ss.version(); ss.close()
        return "TLS_OK %s cert=%s"%(ver, (cert.get('subject') if cert else '?'))
    except ssl.SSLError as e: return "TLS_SSLERR "+str(e)[:80]
    except Exception as e: return "TLS_ERR "+str(e)[:60]
def main():
    log("RUN b3 job=%s ts=%s"%(JOB,time.strftime("%H:%M:%SZ",time.gmtime())))
    try: eg=urllib.request.urlopen("https://api.ipify.org",timeout=10).read().decode().strip()
    except Exception: eg="ERR"
    out=["b3 job=%s egress=%s"%(JOB,eg)]
    # control
    out.append("ctrl 1.1.1.1:443=%s"%cls("1.1.1.1",443))
    # (a) 51.161.35.209
    for p in [22,80,443]:
        out.append("DEPLOY 51.161.35.209:%d=%s"%(p,cls("51.161.35.209",p)))
    for vh in ["gitlab.yibuapi.com","grafana.yibuapi.com"]:
        out.append("DEPLOY TLS %s:443 -> %s"%(vh, tls_sni("51.161.35.209",443,vh)))
    out.append("DEPLOY TLS mtx.simpliss.com:443 -> %s"%tls_sni("51.161.35.209",443,"mtx.simpliss.com"))
    # (b) Woodpecker
    for p in [22,80,443,8000]:
        out.append("WP 51.210.13.182:%d=%s"%(p,cls("51.210.13.182",p)))
    # (c) ops target control
    out.append("OPS54 54.36.150.244:443=%s :80=%s"%(cls("54.36.150.244",443),cls("54.36.150.244",80)))
    msg="\n".join(out); log(msg); send("b3summary",msg)
if __name__=="__main__": main()
