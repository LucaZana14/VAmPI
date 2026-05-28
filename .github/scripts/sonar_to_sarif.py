import json, urllib.request, urllib.parse, os, base64, time, sys
from collections import Counter

# 1. VARIABILI D'AMBIENTE
token   = os.environ.get("SONAR_TOKEN")
org     = os.environ.get("SONAR_ORG")
project = os.environ.get("SONAR_PROJECT_KEY")
base    = os.environ.get("SONAR_HOST_URL", "https://sonarcloud.io").rstrip("/")

if not all([token, org, project]):
    print("ERRORE: Mancano le variabili d'ambiente SONAR_TOKEN, SONAR_ORG o SONAR_PROJECT_KEY")
    sys.exit(1)

print(f"[DEBUG] Connessione a: {base}")
print(f"[DEBUG] Org: {org} | Project: {project}")

# 2. SCORING DIFFERENZIATO PER TIPO + SEVERITA'
#
# Il problema del vecchio script: usava solo "severity", quindi un CODE_SMELL
# marcato CRITICAL (es. "duplichi questa stringa 27 volte") riceveva
# security-severity 9.0 e GitHub lo mostrava come Critical, generando
# falsi allarmi di sicurezza.
#
# Soluzione: il security-severity (il numero che GitHub usa per Critical/High)
# dipende dal TIPO di problema, non solo dalla severita':
#   - VULNERABILITY / SECURITY_HOTSPOT -> veri rischi di sicurezza -> score alto
#   - BUG -> problema di affidabilita', rischio medio -> score medio
#   - CODE_SMELL -> manutenibilita', NON sicurezza -> score basso (mai Critical)
#
# GitHub: >=9.0 Critical | 7.0-8.9 High | 4.0-6.9 Medium | 0.1-3.9 Low

def compute_score(issue_type, severity):
    """Security-severity in base al tipo. I CODE_SMELL non superano mai Medium."""
    if issue_type in ("VULNERABILITY", "SECURITY_HOTSPOT"):
        return {
            "BLOCKER": "9.5", "CRITICAL": "9.0", "MAJOR": "7.5",
            "MINOR": "5.0", "INFO": "3.0",
        }.get(severity, "5.0")

    if issue_type == "BUG":
        return {
            "BLOCKER": "7.0", "CRITICAL": "6.0", "MAJOR": "5.0",
            "MINOR": "3.0", "INFO": "1.0",
        }.get(severity, "4.0")

    # CODE_SMELL e resto: manutenibilita', mai sicurezza alta
    return {
        "BLOCKER": "3.5", "CRITICAL": "3.0", "MAJOR": "2.0",
        "MINOR": "1.0", "INFO": "0.5",
    }.get(severity, "1.0")


def compute_level(issue_type, severity):
    """Level SARIF (error/warning/note). I CODE_SMELL non diventano mai 'error'."""
    if issue_type in ("VULNERABILITY", "SECURITY_HOTSPOT"):
        return {
            "BLOCKER": "error", "CRITICAL": "error", "MAJOR": "error",
            "MINOR": "warning", "INFO": "note",
        }.get(severity, "warning")

    if issue_type == "BUG":
        return {
            "BLOCKER": "error", "CRITICAL": "error", "MAJOR": "warning",
            "MINOR": "warning", "INFO": "note",
        }.get(severity, "warning")

    # CODE_SMELL: mai error
    return {
        "BLOCKER": "warning", "CRITICAL": "warning", "MAJOR": "warning",
        "MINOR": "note", "INFO": "note",
    }.get(severity, "note")


# 3. FUNZIONE PER CHIAMARE LE API DI SONARCLOUD
def api_get(path, params=None):
    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    print(f"[DEBUG] GET {url}")
    req = urllib.request.Request(url)
    creds = base64.b64encode(f"{token}:".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read()
            print(f"[DEBUG] HTTP {r.status} -- {len(body)} bytes")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[ERRORE] HTTP {e.code}: {body}")
        raise


# 4. ATTESA DEL COMPLETAMENTO DELL'ANALISI (Max 5 minuti)
print("Attendo completamento analisi SonarCloud...")
for attempt in range(30):
    data = api_get("/api/ce/component", {"component": project})
    tasks = data.get("queue", []) + ([data["current"]] if data.get("current") else [])
    in_progress = [t for t in tasks if t.get("status") in ("IN_PROGRESS", "PENDING")]

    if not in_progress:
        current = data.get("current", {})
        status  = current.get("status", "UNKNOWN")
        print(f"Analisi completata con status: {status}")
        if status == "FAILED":
            print("ATTENZIONE: l'analisi SonarCloud e' fallita.")
            sys.exit(1)
        break

    print(f"  Tentativo {attempt+1}/30: analisi ancora in corso, attendo 10s...")
    time.sleep(10)
else:
    print("Timeout attesa analisi. Procedo comunque.")


# 5. RECUPERO ISSUE (BUG, VULNERABILITY, CODE_SMELL)
def fetch_issues():
    issues, page = [], 1

    while True:
        params = {
            "componentKeys": project,
            "organization":  org,
            "ps":   500,
            "p":    page,
            "resolved": "false",
        }

        data = api_get("/api/issues/search", params)

        total     = data.get("total", 0)
        page_size = data.get("ps", 500)
        returned  = len(data.get("issues", []))

        print(f"[DEBUG] Issues pagina {page}: total={total}, ritornate={returned}")

        if page == 1:
            print(f"Totale issue trovate: {total}")
            if total == 0:
                print(f"[DEBUG] Risposta API completa: {json.dumps(data, indent=2)[:2000]}")

        issues.extend(data.get("issues", []))

        if len(issues) >= total or returned < page_size:
            break

        page += 1

    return issues


# 6. RECUPERO HOTSPOT DI SICUREZZA (endpoint separato)
def fetch_hotspots():
    hotspots_as_issues = []
    page = 1
    total = None

    while total is None or len(hotspots_as_issues) < total:
        params = {
            "projectKey":   project,
            "organization": org,
            "ps":   500,
            "p":    page,
            "status": "TO_REVIEW",
        }

        try:
            data = api_get("/api/hotspots/search", params)
        except Exception as e:
            print(f"[WARN] Hotspot API non disponibile o errore: {e}")
            break

        if total is None:
            total = data.get("paging", {}).get("total", 0)
            print(f"[DEBUG] Totale hotspot trovati: {total}")

        hotspots = data.get("hotspots", [])
        returned = len(hotspots)
        print(f"[DEBUG] Hotspot pagina {page}: ritornati={returned}")

        # vulnerabilityProbability (HIGH/MEDIUM/LOW) indica la gravita' reale
        prob_to_sev = {"HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR"}

        for h in hotspots:
            prob = h.get("vulnerabilityProbability", "MEDIUM")
            hotspots_as_issues.append({
                "rule":      h.get("ruleKey", "unknown"),
                "message":   h.get("message", "Security Hotspot"),
                "severity":  prob_to_sev.get(prob, "MAJOR"),
                "type":      "SECURITY_HOTSPOT",
                "component": h.get("component", ""),
                "line":      h.get("line", 1),
            })

        if returned < 500:
            break

        page += 1

    return hotspots_as_issues


# 7. RECUPERO E UNIONE
issues   = fetch_issues()
hotspots = fetch_hotspots()
all_issues = issues + hotspots

print(f"[DEBUG] Issue totali: {len(issues)} | Hotspot totali: {len(hotspots)}")
print(f"[DEBUG] Problemi combinati: {len(all_issues)}")

type_count = Counter(i.get("type", "UNKNOWN") for i in all_issues)
print(f"[DEBUG] Distribuzione per tipo: {dict(type_count)}")


# 8. CONVERSIONE IN FORMATO SARIF
rules, results = {}, []
for i in all_issues:
    rid   = i.get("rule", "unknown")
    msg   = i.get("message", "")
    sev   = i.get("severity", "MAJOR")
    itype = i.get("type", "CODE_SMELL")  # default prudente
    comp  = i.get("component", "")
    path  = comp.split(":", 2)[-1] if ":" in comp else comp
    line  = i.get("line", 1) or 1

    score = compute_score(itype, sev)
    level = compute_level(itype, sev)

    if rid not in rules:
        rules[rid] = {
            "id": rid,
            "shortDescription": {"text": f"[{itype}] {rid}"},
            "defaultConfiguration": {"level": level},
            "properties": {
                "security-severity": score,
                "sonar-type": itype,
                "sonar-severity": sev,
                "tags": ["security"] if itype in ("VULNERABILITY", "SECURITY_HOTSPOT") else [itype.lower()],
            }
        }

    results.append({
        "ruleId": rid,
        "message": {"text": f"[{itype}/{sev}] {msg}"},
        "level":   level,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": line},
            }
        }],
    })

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {
            "driver": {
                "name": "SonarCloud",
                "version": "1.0",
                "informationUri": "https://sonarcloud.io",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }],
}

# 9. SALVATAGGIO
with open("sonarcloud.sarif", "w") as f:
    json.dump(sarif, f, indent=2)

real_critical = sum(
    1 for i in all_issues
    if i.get("type") in ("VULNERABILITY", "SECURITY_HOTSPOT")
    and i.get("severity") in ("BLOCKER", "CRITICAL")
)
print(f"SARIF generato: {len(results)} risultati, {len(rules)} regole")
print(f"[RIEPILOGO] Veri Critical di SICUREZZA (vuln/hotspot): {real_critical}")
print("[RIEPILOGO] I code smell NON inquinano piu' la severita' di sicurezza")