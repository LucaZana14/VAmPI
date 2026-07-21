import json
import sys
from urllib.parse import urlparse

def enhance_sarif(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            # 1. Gestione granulare degli URI (evita l'accorpamento su openapi.json)
            if k == 'uri' and isinstance(v, str):
                if v.startswith('http'):
                    parsed = urlparse(v)
                    path = parsed.path.lstrip('/')
                    obj[k] = path if path else 'root'
                else:
                    enhance_sarif(v)
            # 2. Promozione dei livelli: converte i 'note' in 'warning' 
            # (o 'error') per dare peso visivo e bloccante su GitHub
            elif k == 'level' and v == 'note':
                obj[k] = 'warning'  
            else:
                enhance_sarif(v)
    elif isinstance(obj, list):
        for item in obj:
            enhance_sarif(item)

if __name__ == '__main__':
    try:
        with open('results.json', 'r') as f:
            data = json.load(f)
        
        enhance_sarif(data)
        
        with open('results.json', 'w') as f:
            json.dump(data, f)
        print('SARIF bonificato, reso granulare e promosso a Warning con successo!')
    except Exception as e:
        print(f'Errore FATALE durante la bonifica: {e}')
        sys.exit(1)