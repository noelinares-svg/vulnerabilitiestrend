#!/usr/bin/env python3
"""Recolecta NVD, CISA KEV, EPSS, SSVC y señales de exploit público y genera data.json."""
import json, time, urllib.request, urllib.parse, urllib.error, gzip, csv, io, datetime, sys, os, re
from concurrent.futures import ThreadPoolExecutor

OUT = sys.argv[1] if len(sys.argv) > 1 else "data.json"
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(CACHE, exist_ok=True)
UA = {"User-Agent": "vicarius-vuln-panorama/0.1"}
NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()
USE_CACHE = os.environ.get("USE_CACHE") == "1"
NOW = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
YEAR = NOW.year
PERIOD_DAYS = 30
log = lambda *a: print(time.strftime("%H:%M:%S"), *a, flush=True)
stats = {"nvd": 0, "errors": []}


def get(url, tries=5, pause=0, binary=False, timeout=120, headers=None):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=dict(UA, **(headers or {})))
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            if pause:
                time.sleep(pause)
            return data if binary else data.decode("utf-8", "replace")
        except Exception as e:  # noqa
            wait = 8 + i * 12
            log("  retry", i + 1, str(e)[:80], "->", wait, "s")
            time.sleep(wait)
    raise RuntimeError("fallo " + url)


def nvd(params):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + params
    stats["nvd"] += 1
    return json.loads(get(url, pause=0.8 if NVD_KEY else 6.5, timeout=180, headers={"apiKey": NVD_KEY} if NVD_KEY else None))


def cached(name, fn):
    p = os.path.join(CACHE, name)
    if USE_CACHE and os.path.exists(p):
        return json.load(open(p))
    v = fn()
    json.dump(v, open(p, "w"))
    return v


def cvss_of(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        arr = m.get(key) or []
        if not arr:
            continue
        arr = sorted(arr, key=lambda x: 0 if x.get("type") == "Primary" else 1)
        d = arr[0].get("cvssData", {})
        sev = d.get("baseSeverity") or arr[0].get("baseSeverity") or ""
        return d.get("baseScore"), sev.upper()
    return None, ""


def desc_of(cve, lang, n=150):
    for d in cve.get("descriptions", []):
        if d.get("lang") == lang:
            t = " ".join(d.get("value", "").split())
            return t if len(t) <= n else t[: n - 1].rstrip() + "…"
    return ""


def cpe_of(cve):
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    p = m.get("criteria", "").split(":")
                    if len(p) > 4:
                        return p[3], p[4]
    return "", ""


# ---------- A. KEV
log("KEV")
kev_raw = json.loads(get("https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"))
kev = {v["cveID"]: v for v in kev_raw["vulnerabilities"]}
log("  KEV entradas", len(kev), "catalogo", kev_raw.get("catalogVersion"))

# ---------- B. NVD conteo por mes
log("NVD por mes")
def month_counts():
    out = {}
    for m in range(1, NOW.month + 1):
        last = (datetime.date(YEAR + (m == 12), (m % 12) + 1, 1) - datetime.timedelta(days=1)).day
        q = f"pubStartDate={YEAR}-{m:02d}-01T00:00:00.000Z&pubEndDate={YEAR}-{m:02d}-{last}T23:59:59.999Z&resultsPerPage=1&noRejected"
        out[f"{YEAR}-{m:02d}"] = nvd(q)["totalResults"]
        log("  ", m, out[f"{YEAR}-{m:02d}"])
    return out
cve_por_mes = cached("meses.json", month_counts)

# ---------- C. NVD hasKev (fecha de publicación de cada CVE del KEV)
log("NVD hasKev")
def has_kev():
    out, start = {}, 0
    while True:
        r = nvd(f"hasKev&resultsPerPage=2000&startIndex={start}")
        for it in r["vulnerabilities"]:
            c = it["cve"]
            sc, sev = cvss_of(c)
            out[c["id"]] = {"pub": c["published"][:10], "cvss": sc, "sev": sev,
                            "en": desc_of(c, "en"), "es": desc_of(c, "es")}
        start += r["resultsPerPage"]
        log("  ", start, "/", r["totalResults"])
        if start >= r["totalResults"] or not r["vulnerabilities"]:
            break
    return out
kev_nvd = cached("haskev.json", has_kev)

# ---------- D. NVD período (últimos 30 días)
log("NVD período")
p_start = (NOW - datetime.timedelta(days=PERIOD_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
p_end = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
def period():
    out, start = [], 0
    while True:
        r = nvd(f"pubStartDate={p_start}&pubEndDate={p_end}&noRejected&resultsPerPage=2000&startIndex={start}")
        for it in r["vulnerabilities"]:
            c = it["cve"]
            sc, sev = cvss_of(c)
            v, p = cpe_of(c)
            out.append({"id": c["id"], "pub": c["published"], "cvss": sc, "sev": sev, "v": v, "p": p,
                        "en": desc_of(c, "en"), "es": desc_of(c, "es"), "st": c.get("vulnStatus", "")})
        start += r["resultsPerPage"]
        log("  ", start, "/", r["totalResults"])
        if start >= r["totalResults"] or not r["vulnerabilities"]:
            break
    return {"start": p_start, "end": p_end, "items": out}
per = cached("periodo.json", period)
items = per["items"]

# ---------- E. EPSS (volcado de hoy y de hace 7 días)
log("EPSS")
def epss_csv(date=None):
    name = "epss_scores-current.csv.gz" if date is None else f"epss_scores-{date}.csv.gz"
    raw = get("https://epss.empiricalsecurity.com/" + name, binary=True, timeout=180)
    txt = gzip.decompress(raw).decode()
    head = txt.split("\n", 1)[0]
    sd = re.search(r"score_date:([0-9T:\-+Z]+)", head)
    mv = re.search(r"model_version:([^,]+)", head)
    rows = {}
    rd = csv.reader(io.StringIO(txt))
    for row in rd:
        if len(row) == 3 and row[0].startswith("CVE-"):
            rows[row[0]] = (float(row[1]), float(row[2]))
    return rows, (sd.group(1) if sd else ""), (mv.group(1) if mv else "")
epss, epss_date, epss_model = epss_csv()
log("  hoy", len(epss), epss_date, epss_model)
ep_d = epss_date[:10] or NOW.strftime("%Y-%m-%d")
d7 = (datetime.date.fromisoformat(ep_d) - datetime.timedelta(days=7)).isoformat()
try:
    epss7, _, _ = epss_csv(d7)
    log("  hace 7 días", len(epss7))
except Exception as e:
    epss7 = {}
    stats["errors"].append("EPSS 7d: " + str(e))

bands = [0, 0, 0, 0]
for s, _ in epss.values():
    bands[0 if s < 0.01 else 1 if s < 0.1 else 2 if s < 0.5 else 3] += 1
top = sorted(epss.items(), key=lambda kv: -kv[1][0])[:25]
chg = []
if epss7:
    for c, (s, p) in epss.items():
        if s >= 0.1 or epss7.get(c, (0, 0))[0] >= 0.1:
            old = epss7.get(c)
            if old is not None:
                chg.append((c, round(s, 4), round(old[0], 4)))
    chg.sort(key=lambda x: -abs(x[1] - x[2]))
    chg = chg[:20]

# ---------- F. Exploit público
log("Exploits")
ex_n, ex_m, ex_e = set(), set(), set()
try:
    for line in get("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json").splitlines():
        m = re.search(r'"ID"\s*:\s*"(CVE-\d{4}-\d+)"', line)
        if m:
            ex_n.add(m.group(1).upper())
except Exception as e:
    stats["errors"].append("Nuclei: " + str(e))
try:
    msf = json.loads(get("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"))
    for mod in msf.values():
        if mod.get("type") in ("exploit", "auxiliary"):
            for ref in mod.get("references", []) or []:
                m = re.match(r"CVE-(\d{4}-\d+)", ref)
                if m:
                    ex_m.add("CVE-" + m.group(1))
except Exception as e:
    stats["errors"].append("Metasploit: " + str(e))
try:
    edb = get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")
    for row in csv.DictReader(io.StringIO(edb)):
        for m in re.findall(r"CVE-\d{4}-\d+", row.get("codes", "") or ""):
            ex_e.add(m)
except Exception as e:
    stats["errors"].append("Exploit-DB: " + str(e))
log("  nuclei", len(ex_n), "msf", len(ex_m), "edb", len(ex_e))
xflag = lambda c: (1 if c in ex_n else 0) | (2 if c in ex_m else 0) | (4 if c in ex_e else 0)

# ---------- G. SSVC (CISA Vulnrichment) para los candidatos del período
log("SSVC")
def cand_score(it):
    e = epss.get(it["id"], (0, 0))[0]
    return (it["id"] in kev) * 10 + e + ((it["cvss"] or 0) >= 9) * 0.5
cands = [it for it in items if it["id"] in kev or epss.get(it["id"], (0, 0))[0] >= 0.01 or (it["cvss"] or 0) >= 9]
cands = sorted(cands, key=lambda it: -cand_score(it))[:450]
def ssvc(cid):
    y, n = cid.split("-")[1], cid.split("-")[2]
    folder = (n[:-3] or "0") + "xxx"
    try:
        req = urllib.request.Request(f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{y}/{folder}/{cid}.json", headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            j = json.loads(r.read())
    except Exception:
        return cid, ""
    for adp in j.get("containers", {}).get("adp", []):
        for met in adp.get("metrics", []):
            o = met.get("other", {})
            if o.get("type") == "ssvc":
                d = {}
                for opt in o.get("content", {}).get("options", []):
                    d.update(opt)
                e = {"active": "A", "poc": "P", "none": "N"}.get(str(d.get("Exploitation", "")).lower(), "")
                a = {"yes": "Y", "no": "N"}.get(str(d.get("Automatable", "")).lower(), "")
                t = {"total": "T", "partial": "P"}.get(str(d.get("Technical Impact", "")).lower(), "")
                return cid, e + "/" + a + "/" + t if e else ""
    return cid, ""
with ThreadPoolExecutor(8) as ex:
    ssvc_map = dict(ex.map(ssvc, [c["id"] for c in cands]))
log("  SSVC consultados", len(cands), "con datos", sum(1 for v in ssvc_map.values() if v))

# ---------- H. Ransomware por país en las Américas (solo conteos agregados)
log("Ransomware Américas")
AMERICAS = ("US CA MX GT BZ SV HN NI CR PA CU DO HT JM TT BS BB AG DM GD KN LC VC PR "
            "CO VE EC PE BO CL AR UY PY BR GY SR").split()
rans = {}
for cc in AMERICAS:
    arr = None
    for i in range(4):
        try:
            req = urllib.request.Request(f"https://api.ransomware.live/v2/countryvictims/{cc}", headers=UA)
            with urllib.request.urlopen(req, timeout=90) as r:
                arr = json.loads(r.read())
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:  # la fuente responde 404 cuando no tiene registros del país
                arr = []
                break
            time.sleep(6 + i * 8)
        except Exception:
            time.sleep(6 + i * 8)
    if arr is None:
        stats["errors"].append("ransomware.live " + cc)
        continue
    by_m, groups, n = {}, {}, 0
    for v in arr if isinstance(arr, list) else []:
        d = str(v.get("attackdate") or v.get("discovered") or v.get("published") or "")[:10]
        if not d.startswith(str(YEAR)):
            continue
        n += 1
        by_m[d[:7]] = by_m.get(d[:7], 0) + 1
        g = str(v.get("group") or v.get("group_name") or "?").lower()
        groups[g] = groups.get(g, 0) + 1
    rans[cc] = {"n": n, "m": by_m, "g": sorted(groups.items(), key=lambda kv: -kv[1])}
    time.sleep(0.8)
log("  países", len(rans), "víctimas", sum(v["n"] for v in rans.values()))

# ---------- I. Ensamblar
log("Ensamblar")
rows, rest_day, rest_sev = [], {}, {}
for it in items:
    c = it["id"]
    e, pc = epss.get(c, (None, None))
    isk = c in kev
    keep = isk or (it["cvss"] or 0) >= 7 or (e or 0) >= 0.01 or (pc or 0) >= 0.9 or ssvc_map.get(c)
    day = it["pub"][:10]
    if not keep:
        rest_day[day] = rest_day.get(day, 0) + 1
        s = it["sev"] or "NONE"
        rest_sev[s] = rest_sev.get(s, 0) + 1
        continue
    old = epss7.get(c)
    rows.append([c, it["pub"][:16], it["cvss"], it["sev"],
                 None if e is None else round(e, 5), None if pc is None else round(pc, 4),
                 1 if isk else 0, 1 if isk and kev[c].get("knownRansomwareCampaignUse") == "Known" else 0,
                 it["v"], it["p"], it["en"], it["es"] if it["es"] != it["en"] else "",
                 ssvc_map.get(c, ""), xflag(c),
                 None if (e is None or old is None) else round(e - old[0], 4)])

kev_rows = []
for c, v in kev.items():
    n = kev_nvd.get(c, {})
    e = epss.get(c, (None, None))[0]
    kev_rows.append([c, v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", "")[:90],
                     v.get("dateAdded", ""), n.get("pub", ""), 1 if v.get("knownRansomwareCampaignUse") == "Known" else 0,
                     n.get("cvss"), None if e is None else round(e, 4), xflag(c)])
kev_rows.sort(key=lambda r: r[4])

top_rows = []
for c, (s, p) in top:
    top_rows.append([c, round(s, 4), round(p, 4), 1 if c in kev else 0, xflag(c)])

data = {
    "version": 1,
    "generado": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "anio": YEAR,
    "periodo": {"desde": per["start"], "hasta": per["end"], "dias": PERIOD_DAYS, "total": len(items)},
    "cvePorMes": cve_por_mes,
    "kevCatalogo": {"version": kev_raw.get("catalogVersion"), "fecha": kev_raw.get("dateReleased"), "total": len(kev)},
    "epss": {"fecha": ep_d, "modelo": epss_model, "total": len(epss), "bandas": bands, "top": top_rows,
             "cambios": [[c, a, b, 1 if c in kev else 0] for c, a, b in chg], "ge10": bands[2] + bands[3]},
    "kev": kev_rows,
    "filas": rows,
    "resto": {"porDia": rest_day, "porSev": rest_sev},
    "ssvc": {"consultados": len(cands), "conDatos": sum(1 for v in ssvc_map.values() if v)},
    "exploits": {"nuclei": len(ex_n), "metasploit": len(ex_m), "exploitdb": len(ex_e)},
    "ransomware": rans,
    "peticionesNvd": stats["nvd"],
    "errores": stats["errors"],
}
json.dump(data, open(OUT, "w"), ensure_ascii=False, separators=(",", ":"))
log("LISTO", OUT, os.path.getsize(OUT), "bytes; filas", len(rows), "kev", len(kev_rows), "errores", stats["errors"])
