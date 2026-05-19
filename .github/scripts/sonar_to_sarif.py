import json, urllib.request, urllib.parse, os, base64, time, sys

# 1. LEGGERE DALLE VARIABILI D'AMBIENTE (Niente più nomi fissi nel codice!)
token   = os.environ.get("SONAR_TOKEN")
org     = os.environ.get("SONAR_ORG")
project = os.environ.get("SONAR_PROJECT_KEY")
base    = "https://sonarcloud.io"

if not all([token, org, project]):
    print("ERRORE: Mancano le variabili d'ambiente SONAR_TOKEN, SONAR_ORG o SONAR_PROJECT")
    sys.exit(1)

# 2. DIZIONARI PER LA TRADUZIONE DELLE SEVERITA'
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

# 3. FUNZIONE PER CHIAMARE LE API DI SONARCLOUD
def api_get(path, params=None):
    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    creds = base64.b64encode(f"{token}:".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    with urllib.request.urlopen(req) as r:
        return json.load(r)

# 4. ATTESA DEL COMPLETAMENTO DELL'ANALISI (Max 5 minuti)
print("Attendo completamento analisi SonarCloud...")
for attempt in range(30):
    data = api_get("/api/ce/component", {"component": project})
    tasks = data.get("queue", []) + (
        [data["current"]] if data.get("current") else []
    )
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

# 5. RECUPERO DELLE VULNERABILITA' (Paginazione)
def fetch_issues():
    issues, page, total = [], 1, None
    while total is None or len(issues) < total:
        data = api_get("/api/issues/search", {
            "componentKeys": project,
            "organization":  org,
            "ps": 500,
            "p":  page,
            "statuses": "OPEN,CONFIRMED,REOPENED",
        })
        if total is None:
            total = data["total"]
            print(f"Totale issue trovate: {total}")
        issues.extend(data["issues"])
        if len(data["issues"]) < 500:
            break
        page += 1
    return issues

issues = fetch_issues()

# 6. CONVERSIONE IN FORMATO SARIF PER GITHUB
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
                "security-severity": SCORE.get(sev, "5.0") # TRUCCO PER VEDERE CRITICAL E HIGH
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

# 7. SALVATAGGIO DEL FILE SARIF DA PASSARE A GITHUB ACTIONS
with open("sonarcloud.sarif", "w") as f:
    json.dump(sarif, f, indent=2)

print(f"SARIF generato: {len(results)} risultati, {len(rules)} regole")