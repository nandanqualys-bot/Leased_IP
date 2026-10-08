#!/usr/bin/env python3
"""
04_ip_verification.py
Evidence-driven attribution of off-ASN candidates.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import requests
import dns.resolver
from dotenv import load_dotenv

load_dotenv()
UA="EASM-IP-Verification/1.0 (defensive asset verification)"

CENSYS_BASE="https://api.platform.censys.io/v3/global"

def censys_enabled(cfg):
    return bool(cfg.get("censys_api_token") or os.getenv("CENSYS_API_TOKEN")) and bool(cfg.get("censys_org_id") or os.getenv("CENSYS_ORG_ID"))

def censys_headers(cfg):
    token=os.getenv("CENSYS_API_TOKEN") or cfg.get("censys_api_token","")
    org=os.getenv("CENSYS_ORG_ID") or cfg.get("censys_org_id","")
    return {"Authorization":f"Bearer {token}","X-Organization-ID":org,"Accept":"application/json"}

def _walk_dicts(obj):
    if isinstance(obj,dict):
        yield obj
        for v in obj.values():
            yield from _walk_dicts(v)
    elif isinstance(obj,list):
        for v in obj:
            yield from _walk_dicts(v)

def censys_domain_history(client,cfg,domain,days=31):
    if not censys_enabled(cfg): return []
    try:
        from datetime import timedelta
        end=datetime.now(timezone.utc); start=end-timedelta(days=days)
        url=f"{CENSYS_BASE}/dns/resolutions/{domain}/bounds"
        params={"organization_id":os.getenv("CENSYS_ORG_ID") or cfg.get("censys_org_id"),
                "start_time":start.isoformat().replace("+00:00","Z"),
                "end_time":end.isoformat().replace("+00:00","Z"),
                "record_types":"A","page_size":100}
        r=client.get(url,params=params,headers=censys_headers(cfg),timeout=20)
        if not r.ok: return []
        ips=[]
        for d in _walk_dicts(r.json()):
            for k in ("value","values","answers","records","addresses","ips"):
                v=d.get(k)
                if isinstance(v,str): v=[v]
                if isinstance(v,list):
                    for item in v:
                        val=item.get("value") if isinstance(item,dict) else item
                        if isinstance(val,str):
                            try:
                                if ipaddress.ip_address(val).version==4: ips.append(val)
                            except Exception: pass
        return sorted(set(ips))
    except Exception: return []

def censys_ip_names(client,cfg,ip,domain_filter=None,days=31):
    if not censys_enabled(cfg): return []
    try:
        from datetime import timedelta
        end=datetime.now(timezone.utc); start=end-timedelta(days=days)
        url=f"{CENSYS_BASE}/dns/resolutions/ip/{ip}/ranges"
        params={"organization_id":os.getenv("CENSYS_ORG_ID") or cfg.get("censys_org_id"),
                "start_time":start.isoformat().replace("+00:00","Z"),
                "end_time":end.isoformat().replace("+00:00","Z"),
                "record_types":"A","page_size":100}
        if domain_filter: params["domain"]=domain_filter
        r=client.get(url,params=params,headers=censys_headers(cfg),timeout=20)
        if not r.ok: return []
        names=[]
        for d in _walk_dicts(r.json()):
            for k in ("name","domain","fqdn"):
                v=d.get(k)
                if isinstance(v,str) and "." in v: names.append(v.lower().rstrip("."))
        return sorted(set(names))
    except Exception: return []

DEFAULT_PORTS=[443,8443,9443,10443,4443,7443]

def setup():
    Path("logs").mkdir(exist_ok=True)
    logging.basicConfig(filename="logs/verification.log",level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

class Client:
    def __init__(self,cfg):
        self.timeout=cfg.get("timeouts",{}).get("http",15)
        self.retries=cfg.get("max_retries",2)
        self.delay=cfg.get("request_delay",0.2)
        self.s=requests.Session(); self.s.headers["User-Agent"]=UA
    def get(self,url,**kwargs):
        last=None
        for a in range(self.retries+1):
            try:
                r=self.s.get(url,timeout=kwargs.pop("timeout",self.timeout),**kwargs)
                if r.status_code==429 and a<self.retries:
                    time.sleep(self.delay*(2**a)); continue
                return r
            except requests.RequestException as e:
                last=e
                if a<self.retries: time.sleep(self.delay*(2**a))
        raise last

def rdap(client,ip):
    try:
        r=client.get(f"https://rdap.org/ip/{ip}",timeout=12)
        return r.json() if r.ok else {}
    except Exception: return {}

def rdap_org(obj):
    out=[]
    for ent in obj.get("entities",[]) if isinstance(obj,dict) else []:
        for v in ent.get("vcardArray",[None,[]])[1]:
            if isinstance(v,list) and len(v)>=4 and v[0]=="fn": out.append(str(v[3]))
    return "; ".join(dict.fromkeys(out))

def ripe_network(client,ip):
    try:
        r=client.get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",timeout=12)
        return r.json().get("data",{}) if r.ok else {}
    except Exception: return {}

def ripe_as(client,asn):
    try:
        r=client.get(f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}",timeout=12)
        return r.json().get("data",{}) if r.ok else {}
    except Exception: return {}

def ptr(ip):
    try:return socket.gethostbyaddr(ip)[0].rstrip(".")
    except Exception:return ""

def resolve(host):
    out=[]
    for typ in ("A",):
        try:
            for x in dns.resolver.resolve(host,typ,lifetime=8): out.append(str(x))
        except Exception: pass
    return out

def tls(ip,hostname,ports):
    import cryptography.x509 as x509
    from cryptography.hazmat.primitives import hashes
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    for port in ports:
        try:
            with socket.create_connection((ip,port),timeout=10) as raw:
                with ctx.wrap_socket(raw,server_hostname=hostname or None) as ss:
                    der=ss.getpeercert(binary_form=True)
                    if not der: continue
                    c=x509.load_der_x509_certificate(der)
                    sans=[]
                    try:
                        ext=c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                        sans=ext.get_values_for_type(x509.DNSName)
                    except Exception: pass
                    cn=""; org=""
                    for a in c.subject:
                        if a.oid.dotted_string=="2.5.4.3": cn=a.value
                        elif a.oid.dotted_string=="2.5.4.10": org=a.value
                    issuer="; ".join(a.value for a in c.issuer if a.oid.dotted_string=="2.5.4.3")
                    return {"port":port,"cn":cn,"sans":sans,"organization":org,"issuer":issuer,
                            "not_before":c.not_valid_before_utc.isoformat(),
                            "not_after":c.not_valid_after_utc.isoformat(),
                            "serial":str(c.serial_number),
                            "fingerprint":c.fingerprint(hashes.SHA256()).hex(),
                            "tls_version":ss.version()}
        except Exception: pass
    return {}

def shodan(client,api_key,ip):
    if not api_key:return {}
    try:
        r=client.get(f"https://api.shodan.io/shodan/host/{ip}",params={"key":api_key},timeout=15)
        return r.json() if r.ok else {}
    except Exception:return {}

def crt_assoc(client,domains,ip):
    # crt.sh search is certificate-name based; this function retrieves domain names and
    # relies on current DNS/TLS checks for the actual IP relationship.
    names=[]
    for d in domains:
        try:
            r=client.get("https://crt.sh/",params={"q":f"%.{d}","output":"json"},timeout=20)
            if r.ok:
                for row in r.json():
                    for n in str(row.get("name_value","")).splitlines():
                        n=n.strip().lower().lstrip("*.")
                        if host_matches(n,[d]): names.append(n)
        except Exception: pass
    return sorted(set(names))

def host_matches(host,domains):
    h=(host or "").lower().rstrip(".")
    return any(h==d or h.endswith("."+d) for d in domains)

def score_candidate(t,c,client,cfg):
    ip=c["ip"]; domains=t.get("target_domains",[])
    target_names=[t.get("parent_organization",""),t.get("target_entity","")]+t.get("known_registrant_names",[])
    target_names=[x.lower() for x in target_names if x]
    known_asns={x.upper() for x in t.get("known_asns",[])}
    ev=[]; evidence_records=[]; score=0
    rd=rdap(client,ip); rd_org=rdap_org(rd)
    ni=ripe_network(client,ip); asns=ni.get("asns") or []
    origin=("AS"+str(asns[0]).replace("AS","")) if asns else c.get("origin_asn","")
    origin_org=ripe_as(client,origin).get("holder","") if origin else c.get("origin_organization","")
    ptrname=ptr(ip)
    hostname=c.get("hostname") or ""
    current_dns_hosts=[]
    for h in [x.strip() for x in hostname.split(";") if x.strip()]:
        if ip in resolve(h): current_dns_hosts.append(h)
    if current_dns_hosts:
        score+=25; ev.append("Current target hostname resolves to IP")
        evidence_records.append(("DNS",f"Current DNS: {', '.join(current_dns_hosts)}",25))
    tlsinfo={}
    tls_host=current_dns_hosts[0] if current_dns_hosts else (hostname.split(";")[0] if hostname else "")
    if tls_host:
        tlsinfo=tls(ip,tls_host,cfg.get("tls_ports",DEFAULT_PORTS))
    tls_direct=bool(tlsinfo and (host_matches(tlsinfo.get("cn",""),domains) or any(host_matches(x,domains) for x in tlsinfo.get("sans",[]))))
    if tls_direct:
        score+=25; ev.append("TLS certificate contains target domain")
        evidence_records.append(("TLS",f"CN={tlsinfo.get('cn')}; SAN match",25))
    ct_names=crt_assoc(client,domains,ip)
    ct_match=any(host_matches(x,domains) for x in ct_names)
    # CT proves certificate/name existence, not that this IP served the certificate.
    if ct_match:
        ev.append("Certificate Transparency context only (not counted as IP proof)")
        evidence_records.append(("CT","CT names support target-domain context only; no score",0))

    censys_names=[]
    censys_hist=[]
    if censys_enabled(cfg):
        try: cfg["censys_history_days"]=int(os.getenv("CENSYS_HISTORY_DAYS",cfg.get("censys_history_days",31)))
        except Exception: pass
        for d in domains:
            censys_hist.extend(censys_ip_names(client,cfg,ip,d,cfg.get("censys_history_days",31)))
        censys_names=sorted(set(censys_hist))
        if any(host_matches(x,domains) for x in censys_names):
            score += 20
            ev.append("Censys historical/current DNS association")
            evidence_records.append(("Historical DNS",f"Censys observed target domain on IP: {', '.join(censys_names[:20])}",20))
    if ptrname and host_matches(ptrname,domains):
        score+=15; ev.append("Reverse DNS contains target-controlled domain")
        evidence_records.append(("Reverse DNS",ptrname,15))
    sh=shodan(client,os.getenv("SHODAN_API_KEY") or cfg.get("shodan_api_key",""),ip)
    shhosts=(sh.get("hostnames") or [])+(sh.get("domains") or [])
    if any(host_matches(x,domains) for x in shhosts):
        score+=10; ev.append("Shodan hostname/domain association")
        evidence_records.append(("Shodan",f"Hostnames/domains: {', '.join(shhosts[:20])}",10))
    if sh.get("org") and any(n in str(sh.get("org")).lower() for n in target_names):
        score+=10; ev.append("Shodan organization evidence")
        evidence_records.append(("Shodan",f"Organization: {sh.get('org')}",10))
    if rd_org and any(n in rd_org.lower() for n in target_names):
        score+=10; ev.append("RDAP organization matches target")
        evidence_records.append(("RDAP",rd_org,10))
    if c.get("discovery_evidence") and "Official/Public Domain" in str(c.get("discovery_sources","")):
        score+=20; ev.append("Official/public target-domain evidence")
        evidence_records.append(("Official Documentation","Target-domain public material explicitly referenced the candidate IP; treated as supporting evidence, not ownership proof",20))
    # Shared-infrastructure analysis. Multiple unrelated names on the same IP are a caution signal.
    all_names=sorted(set([x for x in shhosts if x] + censys_names + ([ptrname] if ptrname else [])))
    unrelated_names=[x for x in all_names if not host_matches(x,domains)]
    shared_infra = len(unrelated_names) >= 3
    if shared_infra:
        score -= 20
        ev.append("Shared infrastructure: multiple unrelated hostnames/domains")
        evidence_records.append(("Shared Infrastructure",f"Unrelated names observed: {', '.join(unrelated_names[:20])}",-20))

    # Negative signals
    unrelated=rd_org and not any(n in rd_org.lower() for n in target_names)
    # A cloud provider's registration is expected for hosted services when the
    # target currently resolves to the IP and serves a matching certificate.
    if unrelated and not (current_dns_hosts and tls_direct):
        score-=30; ev.append("RDAP shows an unrelated network organization")
        evidence_records.append(("RDAP",f"Negative: {rd_org}",-30))
    score=max(0,min(100,score))
    thresholds=cfg.get("confidence_thresholds",{"confirmed":90,"high":75,"medium":50,"low":30})
    if score>=thresholds["confirmed"]: conf="CONFIRMED"
    elif score>=thresholds["high"]: conf="HIGH"
    elif score>=thresholds["medium"]: conf="MEDIUM"
    elif score>=thresholds["low"]: conf="LOW"
    else: conf="UNVERIFIED"
    strong_direct=(bool(current_dns_hosts and tls_direct) or bool(c.get("discovery_evidence") and "Official/Public Domain" in str(c.get("discovery_sources","")) and rd_org and any(n in rd_org.lower() for n in target_names)))
    if conf=="CONFIRMED" and not strong_direct and len({x[0] for x in evidence_records})<3:
        conf="HIGH" if score>=75 else "MEDIUM"
    relationship="Unverified"
    if conf in ("CONFIRMED","HIGH"):
        if rd_org and any(n in rd_org.lower() for n in target_names):
            relationship="Owned"
        elif current_dns_hosts or tls_direct:
            relationship="Leased/Hosted"
        else:
            relationship="Operated"
    elif conf=="MEDIUM":
        relationship="Likely Hosted"
    elif conf=="LOW":
        relationship="Unverified"
    else:
        relationship="Likely Unrelated" if score==0 and unrelated else "Unverified"
    return {
        "score":score,"confidence":conf,"relationship":relationship,
        "registered_org":rd_org or c.get("registered_organization","Not Available"),
        "origin_asn":origin or c.get("origin_asn","Not Available"),
        "origin_org":origin_org or c.get("origin_organization","Not Available"),
        "hosting":c.get("hosting_provider","Not Available"),
        "ptr":ptrname or "Not Available","tls":tlsinfo,"ct_names":ct_names,
        "shodan":sh,"evidence":evidence_records,"evidence_count":len({x[0] for x in evidence_records}),
        "proof":build_proof(ip,origin,origin_org,known_asns,current_dns_hosts,tlsinfo,ct_names,ptrname,rd_org,relationship,conf)
    }

def build_proof(ip,asn,origin_org,known_asns,dns_hosts,tlsinfo,ct,ptrname,rd_org,relationship,conf):
    parts=[f"IP {ip} is originated by {asn or 'Not Available'} ({origin_org or 'Not Available'}) and is treated as off-ASN relative to known ASN(s): {', '.join(sorted(known_asns)) or 'Not Available'}."]
    if dns_hosts: parts.append(f"Current DNS resolves {', '.join(dns_hosts)} to this IP.")
    if tlsinfo: parts.append(f"TLS certificate: CN={tlsinfo.get('cn') or 'Not Available'}, SAN count={len(tlsinfo.get('sans',[]))}, issuer={tlsinfo.get('issuer') or 'Not Available'}.")
    if ct: parts.append(f"CT data contains target-domain names including {', '.join(ct[:10])}.")
    if ptrname: parts.append(f"Reverse DNS is {ptrname}.")
    if rd_org: parts.append(f"RDAP identifies {rd_org} as the registered network organization; this does not by itself prove application ownership.")
    parts.append(f"Conclusion: {relationship}. Confidence: {conf}.")
    return " ".join(parts)

def aggregate_range(ip):
    try:
        obj=ipaddress.ip_address(ip)
        # Conservative: return the address as /32 or /128 unless the registered CIDR
        # is explicitly supported by evidence. Never infer an entire cloud range.
        return f"{obj}/32" if obj.version==4 else f"{obj}/128"
    except Exception:return "Not Available"

def safe_path(path,overwrite):
    p=Path(path)
    if overwrite or not p.exists(): return p
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
    return p.with_name(f"{p.stem}_{stamp}{p.suffix}")

def main():
    setup()
    ap=argparse.ArgumentParser(description="Verify off-ASN EASM candidates.")
    ap.add_argument("--input",required=True)
    ap.add_argument("--output",default="verified_ip_ranges.xlsx")
    ap.add_argument("--json-output")
    ap.add_argument("--config",default="config.json")
    ap.add_argument("--workers",type=int)
    ap.add_argument("--timeout",type=float)
    ap.add_argument("--overwrite",action="store_true")
    ap.add_argument("--verbose",action="store_true")
    args=ap.parse_args()
    cfg=json.loads(Path(args.config).read_text(encoding="utf-8")) if Path(args.config).exists() else {}
    if args.workers: cfg["max_workers"]=args.workers
    if args.timeout: cfg.setdefault("timeouts",{})["http"]=args.timeout
    obj=json.loads(Path(args.input).read_text(encoding="utf-8"))
    if not isinstance(obj,dict) or not isinstance(obj.get("targets"),list): raise SystemExit("Malformed candidate JSON.")
    client=Client(cfg)
    jobs=[]
    for t in obj["targets"]:
        for c in t.get("candidates",[]):
            try:
                if ipaddress.ip_address(c.get("ip","")).version != 4:
                    continue
            except Exception:
                continue
            jobs.append((t,c))
    results=[]
    def one(job):
        t,c=job
        try:
            if ipaddress.ip_address(c.get("ip","")).version != 4:
                return t,c,{"score":0,"confidence":"UNVERIFIED","relationship":"Unverified","registered_org":"Not Available","origin_asn":c.get("origin_asn","Not Available"),"origin_org":c.get("origin_organization","Not Available"),"hosting":c.get("hosting_provider","Not Available"),"ptr":"Not Available","tls":{},"ct_names":[],"shodan":{},"evidence":[("IPv4 Gate","IPv6 excluded",0)],"evidence_count":1,"proof":"IPv6 excluded by policy."}
            return t,c,score_candidate(t,c,client,cfg)
        except Exception as e:
            logging.exception("Verification failed for %s",c.get("ip"))
            return t,c,{"score":0,"confidence":"UNVERIFIED","relationship":"Unverified",
                        "registered_org":"Not Available","origin_asn":c.get("origin_asn","Not Available"),
                        "origin_org":c.get("origin_organization","Not Available"),
                        "hosting":c.get("hosting_provider","Not Available"),"ptr":"Not Available",
                        "tls":{},"ct_names":[],"shodan":{},"evidence":[],"evidence_count":0,
                        "proof":f"Verification failed: {e}"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(cfg.get("max_workers",10))) as ex:
        for i,r in enumerate(ex.map(one,jobs),1):
            results.append(r)
            if i%10==0 or i==len(jobs): print(f"Verified {i}/{len(jobs)}")
    rows=[]; evidence_rows=[]
    for t,c,v in results:
        row={
            "IP Range":aggregate_range(c["ip"]),"IP":c["ip"],
            "Parent Organization":t.get("parent_organization",""),
            "Target Entity":t.get("target_entity",""),
            "Target Domain":";".join(t.get("target_domains",[])),
            "Relationship":v["relationship"],
            "Owned/Leased/Hosted":v["relationship"],
            "Registered Organization":v["registered_org"],
            "Origin ASN":v["origin_asn"],"Origin Organization":v["origin_org"],
            "Hosting Provider":v["hosting"],
            "Confidence Score":v["score"],"Confidence":v["confidence"],
            "Evidence Count":v["evidence_count"],
            "Discovery Sources":";".join(c.get("discovery_sources",[])),
            "Verification Sources":";".join(dict.fromkeys(x[0] for x in v["evidence"])),
            "DNS Evidence":next((x[1] for x in v["evidence"] if x[0]=="DNS"),"Not Available"),
            "TLS Evidence":next((x[1] for x in v["evidence"] if x[0]=="TLS"),"Not Available"),
            "Certificate Evidence":next((x[1] for x in v["evidence"] if x[0]=="CT"),"Not Available"),
            "RDAP Evidence":next((x[1] for x in v["evidence"] if x[0]=="RDAP"),"Not Available"),
            "BGP Evidence":f"Origin ASN={v['origin_asn']}; Origin Organization={v['origin_org']}",
            "Shodan Evidence":next((x[1] for x in v["evidence"] if x[0]=="Shodan"),"Not Available"),
            "Historical DNS Evidence":next((x[1] for x in v["evidence"] if x[0]=="Historical DNS"),"Not Available"),
            "Shared Infrastructure Evidence":next((x[1] for x in v["evidence"] if x[0]=="Shared Infrastructure"),"Not Detected"),
            "Official Source Evidence":next((x[1] for x in v["evidence"] if x[0]=="Official Documentation"),"Not Available"),
            "Proof Summary":v["proof"],
            "First Seen":c.get("first_seen","Not Available"),"Last Seen":c.get("last_seen","Not Available"),
            "Verification Timestamp":datetime.now(timezone.utc).isoformat()
        }
        rows.append(row)
        for src,detail,pts in v["evidence"]:
            evidence_rows.append({"IP":c["ip"],"Parent Organization":t.get("parent_organization",""),
                                  "Target Domain":";".join(t.get("target_domains",[])),
                                  "Source":src,"Evidence":detail,"Score Contribution":pts})
    cols=["IP Range","IP","Parent Organization","Target Entity","Target Domain","Relationship",
          "Owned/Leased/Hosted","Registered Organization","Origin ASN","Origin Organization",
          "Hosting Provider","Confidence Score","Confidence","Evidence Count","Discovery Sources",
          "Verification Sources","DNS Evidence","TLS Evidence","Certificate Evidence","RDAP Evidence",
          "BGP Evidence","Shodan Evidence","Historical DNS Evidence","Shared Infrastructure Evidence","Official Source Evidence",
          "Proof Summary","First Seen","Last Seen","Verification Timestamp"]
    df=pd.DataFrame(rows,columns=cols)
    if not df.empty:
        family_map={"DNS":"DNS","Historical DNS":"DNS","TLS":"TLS/Certificate","CT":"TLS/Certificate","Shodan":"Internet Scan","RDAP":"Registration","BGP":"Routing","Official Documentation":"Official Source","Shared Infrastructure":"Infrastructure Context","Reverse DNS":"DNS"}
        def families(v):
            vals=[x for x in str(v or "").split(";") if x]
            return ";".join(sorted({family_map.get(x,x) for x in vals}))
        df["Evidence Families"]=df["Verification Sources"].apply(families)
        df["Attribution Status"]=df.apply(lambda r: ("CONFIRMED_OWNED" if r["Confidence"]=="CONFIRMED" and r["Relationship"]=="Owned" else "CONFIRMED_LEASED" if r["Confidence"] in ("CONFIRMED","HIGH") and r["Relationship"]=="Leased/Hosted" else "CONFIRMED_OPERATED" if r["Confidence"] in ("CONFIRMED","HIGH") and r["Relationship"]=="Operated" else "SHARED_INFRASTRUCTURE" if "Shared Infrastructure" in str(r["Verification Sources"]) else "LIKELY_ASSOCIATED" if r["Confidence"]=="MEDIUM" else "UNVERIFIED"),axis=1)
        df["Included in EASM"]=df["Attribution Status"].isin(["CONFIRMED_OWNED","CONFIRMED_LEASED","CONFIRMED_OPERATED"])
        df["Exclusion Reason"]=df.apply(lambda r: "" if r["Included in EASM"] else ("Shared infrastructure" if r["Attribution Status"]=="SHARED_INFRASTRUCTURE" else "Insufficient independent attribution evidence"),axis=1)
    evdf=pd.DataFrame(evidence_rows)
    out=safe_path(args.output,args.overwrite)
    js=safe_path(args.json_output or str(Path(args.output).with_suffix(".json")),args.overwrite)
    summary=[]
    for t in obj["targets"]:
        td=";".join(t.get("target_domains",[]))
        sub=df[(df["Parent Organization"]==t.get("parent_organization",""))&(df["Target Domain"]==td)]
        summary.append({
            "Organization":t.get("parent_organization",""),"Known ASN(s)": ";".join(t.get("known_asns",[])),
            "Domains":td,"Total Candidates":len(t.get("candidates",[])),
            "Verified IPs":int(sub["Included in EASM"].sum()) if len(sub) and "Included in EASM" in sub else 0,
            "Verified Ranges":int(sub["IP Range"].nunique()) if len(sub) else 0,
            "Confirmed":int((sub["Confidence"]=="CONFIRMED").sum()) if len(sub) else 0,
            "High":int((sub["Confidence"]=="HIGH").sum()) if len(sub) else 0,
            "Medium":int((sub["Confidence"]=="MEDIUM").sum()) if len(sub) else 0,
            "Low":int((sub["Confidence"]=="LOW").sum()) if len(sub) else 0,
            "Owned":int((sub["Relationship"]=="Owned").sum()) if len(sub) else 0,
            "Leased":int(sub["Relationship"].astype(str).str.contains("Leased",na=False).sum()) if len(sub) else 0,
            "Hosted":int(sub["Relationship"].astype(str).str.contains("Hosted",na=False).sum()) if len(sub) else 0,
            "Unverified":int((sub["Confidence"]=="UNVERIFIED").sum()) if len(sub) else 0
        })
    sdf=pd.DataFrame(summary)
    cdf=pd.DataFrame([{
        "Parent Organization":t.get("parent_organization",""),"Target Entity":t.get("target_entity",""),
        "Target Domain":";".join(t.get("target_domains",[])),"IP":c.get("ip"),
        "Origin ASN":c.get("origin_asn"),"Origin Organization":c.get("origin_organization"),
        "Discovery Sources":";".join(c.get("discovery_sources",[])),"Off ASN":True
    } for t in obj["targets"] for c in t.get("candidates",[])])
    with pd.ExcelWriter(out,engine="openpyxl") as w:
        df.to_excel(w,index=False,sheet_name="Verified IPs")
        df[df.get("Included in EASM",pd.Series(dtype=bool))==True].to_excel(w,index=False,sheet_name="EASM Assets")
        evdf.to_excel(w,index=False,sheet_name="Evidence")
        sdf.to_excel(w,index=False,sheet_name="Summary")
        cdf.to_excel(w,index=False,sheet_name="Candidates")
        for ws in w.book.worksheets:
            ws.freeze_panes="A2"; ws.auto_filter.ref=ws.dimensions
            for col in ws.columns:
                vals=[len(str(c.value or "")) for c in col]
                ws.column_dimensions[col[0].column_letter].width=min(max(max(vals,default=10)+2,10),60)
                for c in col: c.alignment=__import__("openpyxl").styles.Alignment(vertical="top",wrap_text=True)
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),
             "results":df.to_dict(orient="records"),"evidence":evdf.to_dict(orient="records"),
             "summary":sdf.to_dict(orient="records")}
    js.write_text(json.dumps(payload,indent=2,default=str),encoding="utf-8")
    print(f"Verified Excel: {out.resolve()}")
    print(f"Verified JSON : {js.resolve()}")
    print(f"Rows          : {len(df)}")

if __name__=="__main__":
    main()
