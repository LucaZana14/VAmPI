import json
import sys
from urllib.parse import urlparse

def clean_uris(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == 'uri' and isinstance(v, str):
                if v.startswith('http'):
                    # Estrae il path specifico dell'endpoint (es. /users/v1/login) 
                    # evitando di collassare tutto su openapi.json
                    parsed = urlparse(v)
                    path = parsed.path.lstrip('/')
                    obj[k] = path if path else 'root'
                else:
                    clean_uris(v)
            else:
                clean_uris(v)
    elif isinstance(obj, list):
        for item in obj:
            clean_uris(item)

if __name__ == '__main__':
    try:
        with open('results.json', 'r') as f:
            data = json.load(f)
        
        clean_uris(data)
        
        with open('results.json', 'w') as f:
            json.dump(data, f)
        print('SARIF granulare bonificato con successo!')
    except Exception as e:
        print(f'Errore FATALE durante la bonifica: {e}')
        sys.exit(1)