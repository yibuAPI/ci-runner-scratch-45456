#!/usr/bin/env python3
# i45456 batch2: expanded port scan with refused-vs-timeout characterization +
# reachability controls, from a fresh GHA runner EIP.
import os, sys, socket, ssl, json, re, time, urllib.request

TARGET = os.environ.get("TARGET", "54.36.150.244")
JOB = os.environ.get("JOB", "0")
TOPIC = os.environ.get("TOPIC", "iops254-7c1e")
PORTS = [21,22,25,53,80,110,143,443,445,465,587,993,995,1080,1433,1521,2049,2082,2083,
         2086,2087,2095,2096,2181,2222,2375,2376,3000,3001,3100,3128,3306,3389,4443,5000,
         5432,5555,5601,5672,5900,5984,6000,6379,6443,7001,7002,8000,8008,8009,8080,8081,
         8082,8443,8880,8888,9000,9001,9042,9090,9091,9092,9093,9200,9300,9418,9443,10000,
         10250,11211,15672,16379,18080,27017,28017,50000,50070]

def log(*a): print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text=str(text)
    for i in range(0,len(text),3800):
        try:
            req=urllib.request.Request("https://ntfy.sh/"+TOPIC,
                data=((("[b2j%s %d] "%(JOB,i//3800+1))+text[i:i+3800]).encode("utf-8","replace")),
                method="POST", headers={"Title":("i45456-"+tag)[:60]})
            urllib.request.urlopen(req,timeout=12).read()
        except Exception as e: log("NTFYERR",str(e)[:80])

def egress():
    for u in ("https://api.ipify.org","https://icanhazip.com"):
        try: return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"

def cls_connect(ip,port,t=3.0):
    st=time.time()
    try:
        s=socket.create_connection((ip,port),timeout=t); s.close()
        return ("OPEN", round((time.time()-st)*1000))
    except ConnectionRefusedError:
        return ("REFUSED", round((time.time()-st)*1000))
    except socket.timeout:
        return ("TIMEOUT", round((time.time()-st)*1000))
    except OSError as e:
        # EHOSTUNREACH / ENETUNREACH etc
        return ("ERR:"+str(e)[:30], round((time.time()-st)*1000))
    except Exception as e:
        return ("ERR:"+str(e)[:30], round((time.time()-st)*1000))

def main():
    log("RUN b2 job=%s target=%s ts=%s"%(JOB,TARGET,time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())))
    eg=egress(); log("EGRESS",eg)
    # controls: prove egress can open TCP to known-good hosts
    ctrl=[("1.1.1.1",443),("8.8.8.8",53),("api.github.com",443)]
    ctrlout=[]
    for h,p in ctrl:
        st,_=cls_connect(h,p,5.0); ctrlout.append("%s:%d=%s"%(h,p,st))
    log("CONTROLS",ctrlout)
    bogus=cls_connect("10.255.255.1",80,2.5)  # should TIMEOUT (calibration)
    log("BOGUS_CONTROL",bogus)
    res={}
    opens=[]
    for p in PORTS:
        st,ms=cls_connect(TARGET,p,3.0)
        res[p]=st
        if st=="OPEN": opens.append(p)
    counts={}
    for st in res.values():
        k=st if st in ("OPEN","REFUSED","TIMEOUT") else "ERR"
        counts[k]=counts.get(k,0)+1
    log("SUMMARY counts",counts,"opens",opens)
    msg="b2 job=%s egress=%s controls=%s bogus=%s counts=%s opens=%s"%(JOB,eg,ctrlout,bogus,counts,opens)
    # only push ports that are not TIMEOUT (interesting)
    interesting={p:s for p,s in res.items() if s!="TIMEOUT"}
    send("b2summary", msg+"\ninteresting="+json.dumps(interesting))
    log("INTERESTING",json.dumps(interesting))
    log("DONE b2 job=%s"%JOB)

if __name__=="__main__": main()
