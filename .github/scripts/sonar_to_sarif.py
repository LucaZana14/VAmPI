import json, urllib.request, urllib.parse, os, base64, time, sys

token   = os.environ.get("SONAR_TOKEN")
org     = os.environ.get("SONAR_ORG")
project = os.environ.get("SONAR_PROJECT_KEY")
base    = os.environ.get("SONAR_HOST_URL", "https://sonarcloud.io").rstrip("/")

if not all([token, org, project]):
    print("ERRORE: Mancano le variabili d'ambiente SONAR_TOKEN, SONAR_ORG o SONAR_PROJECT_KEY")
    sys.exit(1)

print(f"[DEBUG] Connessione a: {base}")
print(f"[DEBUG] Org: {org} | Project: {project}")

LEVEL = {
    "BLOCKER":  "error",
    "CRITICAL": "error",
    "MAJOR":    "error",
    "MINOR":    "warning",
    "INFO":     "note",
}

SCORE = {
    "BLOCKER":  "9.5",
    "CRITICAL": "9.0",
    "MAJOR":    "7.5",
    "MINOR":    "5.5",
    "INFO":     "2.0",
}

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
            print(f"[DEBUG] HTTP {r.status} — {len(body)} bytes")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[ERRORE] HTTP {e.code}: {body}")
        raise

# Attesa completamento analisi
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
            print("ATTENZIONE: l'analisi SonarCloud è fallita.")
            sys.exit(1)
        break

    print(f"  Tentativo {attempt+1}/30: analisi ancora in corso, attendo 10s...")
    time.sleep(10)
else:
    print("Timeout attesa analisi. Procedo comunque.")

# Recupero issue con debug esteso
def fetch_issues():
    issues, page = [], 1

    while True:
        params = {
            "componentKeys": project,
            "organization":  org,
            "types":         "BUG,VULNERABILITY,CODE_SMELL,SECURITY_HOTSPOT",  # <-- AGGIUNTO
            "ps":  500,
            "p":   page,
            "resolved": "false",
        }

        data = api_get("/api/issues/search", params)

        total     = data.get("total", 0)
        page_size = data.get("ps", 500)
        returned  = len(data.get("issues", []))

        print(f"[DEBUG] Pagina {page}: total={total}, ritornate={returned}")

        if page == 1:
            print(f"Totale issue trovate: {total}")
            if total == 0:
                # Stampa la risposta completa per capire cosa sta succedendo
                print(f"[DEBUG] Risposta API completa: {json.dumps(data, indent=2)[:2000]}")

        issues.extend(data.get("issues", []))

        # Condizione di uscita corretta
        if len(issues) >= total or returned < page_size:
            break

        page += 1

    return issues

issues = fetch_issues()
print(f"[DEBUG] Issue totali recuperate: {len(issues)}")

# Breakdown per severità
from collections import Counter
sev_count = Counter(i.get("severity", "UNKNOWN") for i in issues)
print(f"[DEBUG] Distribuzione severità: {dict(sev_count)}")

# Conversione SARIF
rules, results = {}, []
for i in issues:
    rid  = i.get("rule", "unknown")
    msg  = i.get("message", "")
    sev  = i.get("severity", "MAJOR")
    comp = i.get("component", "")
    path = comp.split(":", 2)[-1] if ":" in comp else comp
    line = i.get("line", 1) or 1

    if rid not in rules:
        rules[rid] = {
            "id": rid,
            "shortDescription": {"text": rid},
            "defaultConfiguration": {"level": LEVEL.get(sev, "warning")},
            "properties": {
                "security-severity": SCORE.get(sev, "5.0")
            }
        }

    results.append({
        "ruleId": rid,
        "message": {"text": msg},
        "level":   LEVEL.get(sev, "warning"),
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

with open("sonarcloud.sarif", "w") as f:
    json.dump(sarif, f, indent=2)

print(f"SARIF generato: {len(results)} risultati, {len(rules)} regole")