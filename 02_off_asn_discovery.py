#!/usr/bin/env python3
"""
02_off_asn_discovery.py
Passive/lightweight off-ASN candidate discovery for defensive EASM.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from functools import lru_cache
from urllib.parse import urlparse

import pandas as pd
import requests
import dns.resolver
from dotenv import load_dotenv

load_dotenv()

UA = "EASM-OffASN-Discovery/1.0 (defensive asset discovery)"
DEFAULT_PORTS = [443, 8443, 9443, 10443, 4443, 7443]
OUT_COLS = [
    "Parent_Organization","Target_Entity","Target_Domain","IP","IP_Version","CIDR",
    "Origin_ASN","Origin_Organization","Registered_Organization","Hosting_Provider",
    "Reverse_DNS","Discovered_Hostname","Discovery_Source","TLS_CN","TLS_SANs",
    "CT_Domains","Shodan_Organization","Shodan_Hostnames","Shodan_Ports",
    "First_Seen","Last_Seen","In_Known_ASN","Off_ASN_Candidate","Discovery_Evidence"
]

class HttpClient:
    def __init__(self, timeout=15, retries=2, delay=0.2):
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA})

    def get(self, url, **kwargs):
        last = None
        for attempt in range(self.retries + 1):
            try:
                r = self.s.get(url, timeout=kwargs.pop("timeout", self.timeout), **kwargs)
                if r.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    time.sleep(self.delay * (2 ** attempt))
                    continue
                return r
            except requests.RequestException as e:
                last = e
                if attempt < self.retries:
                    time.sleep(self.delay * (2 ** attempt))
        raise last

def setup_logging():
    Path("logs").mkdir(exist_ok=True)
    logging.basicConfig(
        filename="logs/discovery.log", level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

def cfg_load(path):
    data = {}
    if Path(path).exists():
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data

def norm_domain(d):
    d = str(d).strip().lower().rstrip(".")
    d = re.sub(r"^[a-z]+://", "", d).split("/",1)[0]
    return d

def load_targets(path):
    p = Path(path)
    if p.suffix.lower() == ".json":
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj.get("targets", [])
    df = pd.read_excel(p, dtype=str).fillna("") if p.suffix.lower() in (".xlsx",".xls") else pd.read_csv(p, dtype=str).fillna("")
    out=[]
    for _,r in df.iterrows():
        out.append({
            "parent_organization": str(r.get("Parent_Organization","")).strip(),
            "target_entity": str(r.get("Target_Entity","")).strip(),
            "target_domains": [norm_domain(x) for x in str(r.get("Target_Domain","")).split(";") if x.strip()],
            "known_asns": [str(x).strip().upper() for x in str(r.get("Known_Target_ASNs","")).split(";") if x.strip()],
            "known_registrant_names": [str(x).strip() for x in str(r.get("Known_Registrant_Names","")).split(";") if x.strip()],
        })
    return out

def cache_db(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY, kind TEXT, value TEXT, fetched_at TEXT
    )""")
    con.commit()
    return con

def cache_get(con,key,max_age_hours=24):
    row=con.execute("SELECT value,fetched_at FROM cache WHERE key=?",(key,)).fetchone()
    if not row: return None
    try:
        age=(datetime.now(timezone.utc)-datetime.fromisoformat(row[1])).total_seconds()/3600
        if age > max_age_hours: return None
    except Exception: return None
    return json.loads(row[0])

def cache_put(con,key,kind,value):
    con.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                (key,kind,json.dumps(value,default=str),datetime.now(timezone.utc).isoformat()))
    con.commit()

@lru_cache(maxsize=10000)
def dns_resolve(host):
    results=[]
    for typ in ("A",):
        try:
            ans=dns.resolver.resolve(host,typ,lifetime=8)
            for r in ans:
                results.append((str(r),typ,"DNS"))
        except Exception:
            pass
    return results

@lru_cache(maxsize=10000)
def dns_cnames(host):
    out=[]
    try:
        ans=dns.resolver.resolve(host,"CNAME",lifetime=8)
        out=[str(x).rstrip(".") for x in ans]
    except Exception:
        pass
    return out

def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".")
    except Exception:
        return ""

def ripestat_network_info(client, ip):
    url=f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    try:
        r=client.get(url,timeout=12)
        if r.ok:
            return r.json().get("data",{})
    except Exception as e:
        logging.warning("RIPE network-info failed for %s: %s",ip,e)
    return {}

def ripestat_as_overview(client, asn):
    try:
        r=client.get(f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}",timeout=12)
        if r.ok: return r.json().get("data",{})
    except Exception as e:
        logging.warning("RIPE ASN overview failed %s: %s",asn,e)
    return {}

def rdap_ip(client, ip):
    try:
        r=client.get(f"https://rdap.org/ip/{ip}",timeout=12)
        if not r.ok: return {}
        return r.json()
    except Exception as e:
        logging.warning("RDAP failed %s: %s",ip,e)
        return {}

def rdap_name(obj):
    names=[]
    for ent in obj.get("entities",[]) if isinstance(obj,dict) else []:
        for c in ent.get("roles",[]):
            if c in ("registrant","administrative","technical"):
                for v in ent.get("vcardArray",[None,[]])[1]:
                    if isinstance(v,list) and len(v)>=4 and v[0]=="fn":
                        names.append(str(v[3]))
    return "; ".join(dict.fromkeys(names))

def cert_info(host,ip,port,timeout=12):
    ctx=ssl.create_default_context()
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE
    try:
        with socket.create_connection((ip,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as ss:
                cert=ss.getpeercert()
                der=ss.getpeercert(binary_form=True)
                if not der: return {}
                from cryptography import x509
                c=x509.load_der_x509_certificate(der)
                sans=[]
                try:
                    ext=c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    sans=ext.get_values_for_type(x509.DNSName)
                except Exception: pass
                cn=""
                for a in c.subject:
                    if a.oid.dotted_string=="2.5.4.3":
                        cn=a.value
                issuer="; ".join(a.value for a in c.issuer if a.oid.dotted_string=="2.5.4.3")
                return {
                    "cn":cn,"sans":sorted(set(sans)),"issuer":issuer,
                    "not_before":c.not_valid_before_utc.isoformat(),
                    "not_after":c.not_valid_after_utc.isoformat(),
                    "organization":"; ".join(a.value for a in c.subject if a.oid.dotted_string=="2.5.4.10"),
                    "serial":str(c.serial_number),
                    "fingerprint":c.fingerprint(__import__("cryptography").hazmat.primitives.hashes.SHA256()).hex(),
                    "tls_version":ss.version()
                }
    except Exception:
        return {}

def crtsh(client, domain):
    try:
        r=client.get("https://crt.sh/",params={"q":f"%.{domain}","output":"json"},timeout=20)
        if not r.ok: return []
        rows=r.json()
        names=set()
        for row in rows:
            for n in str(row.get("name_value","")).splitlines():
                n=n.strip().lower().lstrip("*.")
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception as e:
        logging.warning("crt.sh failed %s: %s",domain,e)
        return []

def shodan_host(client, api_key, ip):
    if not api_key: return {}
    try:
        r=client.get(f"https://api.shodan.io/shodan/host/{ip}",params={"key":api_key},timeout=15)
        if r.ok:
            return r.json()
    except Exception as e:
        logging.warning("Shodan failed %s: %s",ip,e)
    return {}

def official_site_discovery(client, domain):
    """Lightweight, same-domain public-page inspection; no search-engine scraping."""
    urls=[f"https://{domain}/",f"https://{domain}/sitemap.xml",f"https://{domain}/robots.txt",
          f"https://{domain}/security.txt",f"https://{domain}/.well-known/security.txt"]
    ips=set(); evidence=[]
    ip_re=re.compile(r"(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
    for u in urls:
        try:
            r=client.get(u,timeout=10)
            if not r.ok: continue
            found=ip_re.findall(r.text[:2_000_000])
            valid=[]
            for x in found:
                try:
                    obj=ipaddress.ip_network(x,strict=False) if "/" in x else ipaddress.ip_address(x)
                    valid.append(str(obj))
                    ips.add(str(obj))
                except ValueError: pass
            if valid: evidence.append({"url":u,"values":valid})
        except Exception: pass
    return sorted(ips), evidence

def host_in_scope(host, domain):
    host=host.lower().rstrip(".")
    d=domain.lower().rstrip(".")
    return host==d or host.endswith("."+d)

def process_target(target, client, cache, cfg, include_known=False):
    parent=target["parent_organization"]; entity=target["target_entity"]
    known_asns={x.upper() for x in target.get("known_asns",[])}
    candidates={}
    asn_org_cache={}
    domains=[norm_domain(x) for x in target.get("target_domains",[])]

    discovered_hosts=set(domains)
    for d in domains:
        discovered_hosts.update(crtsh(client,d))
        official_ips, _ = official_site_discovery(client,d)
        for item in official_ips:
            try:
                obj=ipaddress.ip_network(item,strict=False) if "/" in item else ipaddress.ip_address(item)
                if isinstance(obj,ipaddress.IPv4Address):
                    ip=str(obj)
                    candidates.setdefault(ip,{"official_evidence":True,"official_values":[item]})
            except ValueError: pass

    # DNS and CNAME expansion, limited to CT-discovered names.
    for host in list(discovered_hosts):
        if len(discovered_hosts)>5000: break
        for cname in dns_cnames(host):
            if any(host_in_scope(cname,d) for d in domains):
                discovered_hosts.add(cname)
        for ip,typ,src in dns_resolve(host):
            candidates.setdefault(ip,{})
            c=candidates[ip]
            c.setdefault("hostnames",set()).add(host)
            c.setdefault("dns_records",[]).append({"hostname":host,"type":typ,"source":src})

    rows=[]
    for ip,meta in candidates.items():
        try:
            ip_obj=ipaddress.ip_address(ip)
        except ValueError: continue
        if ip_obj.version != 4:
            continue
        ni=ripestat_network_info(client,ip)
        asns=ni.get("asns") or []
        origin_asn="AS"+str(asns[0]).replace("AS","") if asns else ""
        in_known=origin_asn.upper() in known_asns if origin_asn else False
        if in_known and not include_known: continue
        # Discovery is intentionally lightweight. Detailed RDAP, Shodan and TLS
        # attribution is deferred to 04_ip_verification.py to avoid duplicating
        # expensive network calls for candidates that will later be rejected.
        rd_org=""
        ptrname=""
        sh={}
        tls={}
        sans=[]
        ct_names=sorted({h for d in domains for h in discovered_hosts if host_in_scope(h,d)})
        first=last=datetime.now(timezone.utc).isoformat()
        sh_hostnames=[]
        sh_domains=[]
        ports=[]
        evidence=[]
        if meta.get("dns_records"): evidence.append("DNS")
        if ct_names: evidence.append("CT (context)")
        if meta.get("official_evidence"): evidence.append("Official/Public Domain")
        if origin_asn not in asn_org_cache:
            asn_org_cache[origin_asn]=ripestat_as_overview(client,origin_asn).get("holder","") if origin_asn else ""
        origin_org=asn_org_cache.get(origin_asn,"")
        cidr=f"{ip}/32"
        rows.append({
            "Parent_Organization":parent,"Target_Entity":entity,"Target_Domain":";".join(domains),
            "IP":ip,"IP_Version":str(ip_obj.version),"CIDR":cidr,
            "Origin_ASN":origin_asn or "Not Available","Origin_Organization":origin_org or "Not Available",
            "Registered_Organization":rd_org or "Not Available",
            "Hosting_Provider":sh.get("isp") or sh.get("org") or "Not Available",
            "Reverse_DNS":ptrname or "Not Available",
            "Discovered_Hostname":";".join(sorted(meta.get("hostnames",set()))),
            "Discovery_Source":";".join(evidence) or "DNS",
            "TLS_CN":tls.get("cn","Not Available"),"TLS_SANs":";".join(sans) if sans else "Not Available",
            "CT_Domains":";".join(ct_names) if ct_names else "Not Available",
            "Shodan_Organization":sh.get("org") or "Not Available",
            "Shodan_Hostnames":";".join(sh_hostnames) if sh_hostnames else "Not Available",
            "Shodan_Ports":",".join(map(str,ports)) if ports else "Not Available",
            "First_Seen":first,"Last_Seen":last,
            "In_Known_ASN":in_known,"Off_ASN_Candidate":not in_known,
            "Discovery_Evidence":json.dumps({
                "dns":meta.get("dns_records",[]),"tls":tls,
                "rdap_org":rd_org,"origin_asn":origin_asn,
                "shodan_org":sh.get("org"),"official":meta.get("official_values",[])
            },default=str)
        })
    return rows

def safe_path(path, overwrite):
    p=Path(path)
    if overwrite or not p.exists(): return p
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
    return p.with_name(f"{p.stem}_{stamp}{p.suffix}")

def main():
    setup_logging()
    ap=argparse.ArgumentParser(description="Discover off-ASN EASM IP candidates.")
    ap.add_argument("--input",required=True)
    ap.add_argument("--output",default="off_asn_candidates.xlsx")
    ap.add_argument("--json-output",default="off_asn_candidates.json")
    ap.add_argument("--config",default="config.json")
    ap.add_argument("--workers",type=int)
    ap.add_argument("--timeout",type=float)
    ap.add_argument("--overwrite",action="store_true")
    ap.add_argument("--verbose",action="store_true")
    args=ap.parse_args()
    if args.verbose: logging.getLogger().setLevel(logging.DEBUG)
    cfg=cfg_load(args.config)
    if args.workers: cfg["max_workers"]=args.workers
    if args.timeout: cfg.setdefault("timeouts",{})["http"]=args.timeout
    client=HttpClient(cfg.get("timeouts",{}).get("http",15),cfg.get("max_retries",2),cfg.get("request_delay",0.2))
    targets=load_targets(args.input)
    if not targets: raise SystemExit("No targets supplied.")
    cache=cache_db(cfg.get("cache_db","easm_cache.db"))
    allrows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,int(cfg.get("max_workers",10)))) as ex:
        futs=[ex.submit(process_target,t,client,cache,cfg) for t in targets]
        for i,f in enumerate(futs,1):
            try:
                allrows.extend(f.result())
                print(f"[{i}/{len(futs)}] target complete; cumulative candidates={len(allrows)}")
            except Exception as e:
                logging.exception("Target failed")
                print(f"[{i}/{len(futs)}] target failed: {e}")
    df=pd.DataFrame(allrows,columns=OUT_COLS).drop_duplicates(subset=["Parent_Organization","IP"])
    xlsx=safe_path(args.output,args.overwrite); js=safe_path(args.json_output,args.overwrite)
    with pd.ExcelWriter(xlsx,engine="openpyxl") as w:
        df.to_excel(w,index=False,sheet_name="Candidates")
        ws=w.book["Candidates"]; ws.freeze_panes="A2"; ws.auto_filter.ref=ws.dimensions
        for col in ws.columns:
            width=min(max(len(str(c.value or "")) for c in col)+2,55)
            ws.column_dimensions[col[0].column_letter].width=width
    targets_json={}
    for row in allrows:
        key=(row["Parent_Organization"],row["Target_Entity"],row["Target_Domain"])
        targets_json.setdefault(key,[]).append(row)
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),
             "targets":[]}
    for (parent,entity,tdomain),rows in targets_json.items():
        first=rows[0]
        payload["targets"].append({
            "parent_organization":parent,"target_entity":entity,
            "target_domains":tdomain.split(";"),"known_asns":load_targets(args.input)[0].get("known_asns",[]) if False else [],
            "candidates":[{
                "ip":r["IP"],"ip_version":r["IP_Version"],"cidr":r["CIDR"],
                "origin_asn":r["Origin_ASN"],"origin_organization":r["Origin_Organization"],
                "registered_organization":r["Registered_Organization"],
                "hosting_provider":r["Hosting_Provider"],"reverse_dns":r["Reverse_DNS"],
                "hostname":r["Discovered_Hostname"],"discovery_sources":r["Discovery_Source"].split(";"),
                "tls_cn":r["TLS_CN"],"tls_sans":r["TLS_SANs"].split(";") if r["TLS_SANs"]!="Not Available" else [],
                "ct_domains":r["CT_Domains"].split(";") if r["CT_Domains"]!="Not Available" else [],
                "shodan_organization":r["Shodan_Organization"],"shodan_hostnames":r["Shodan_Hostnames"],
                "shodan_ports":r["Shodan_Ports"],"first_seen":r["First_Seen"],"last_seen":r["Last_Seen"],
                "discovery_evidence":r["Discovery_Evidence"]
            } for r in rows]
        })
    # Restore exact known ASN lists from input by key.
    source_targets=load_targets(args.input)
    lookup={(t["parent_organization"],t["target_entity"],";".join(t["target_domains"])):t for t in source_targets}
    for t in payload["targets"]:
        k=(t["parent_organization"],t["target_entity"],";".join(t["target_domains"]))
        t["known_asns"]=lookup.get(k,{}).get("known_asns",[])
        t["known_registrant_names"]=lookup.get(k,{}).get("known_registrant_names",[])
    js.write_text(json.dumps(payload,indent=2,default=str),encoding="utf-8")
    print(f"Candidate Excel: {xlsx.resolve()}")
    print(f"Candidate JSON : {js.resolve()}")
    print(f"Candidates     : {len(df)}")

if __name__=="__main__":
    main()
