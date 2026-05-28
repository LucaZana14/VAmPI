# Esca generica (GitHub di solito ignora questa, ma gitLeaks la intercetta come "Generic API Key")
my_secret_api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"

# Esca per Chiave Asimmetrica (Modificata per sembrare finta a GitHub, ma gitLeaks legge l'intestazione)
fake_key = """
-----BEGIN PRIVATE KEYs-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDK...
-----END PRIVATE KEY-----
"""
