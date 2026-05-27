# ==========================================
# ATTENZIONE: FILE FAKE PER TEST GITLEAKS
# ==========================================

def get_cloud_credentials():
    # 1. Esca per AWS (Riconosce il prefisso AKIA)
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    # 2. Esca per GitHub (Riconosce il prefisso ghp_ e la lunghezza)
    github_pat_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzA"

    # 3. Esca per Slack (Riconosce il prefisso xoxb-)
    slack_bot_token = "xoxb-1234567890-123456789012-ABCDEFGHIJKLMNOPQRSTUVWX"

    # 4. Esca per Stripe (Chiave API Standard)
    stripe_live_key = "sk_live_51J9abcdEFGHijklMNOPqrstUVWXYZ1234567890"

    # 5. Esca per una Chiave Privata RSA hardcodata (Riconosce l'intestazione standard)
    private_key = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAw7x3z1... (Chiave troncata per test)
    -----END RSA PRIVATE KEY-----
    """

    return {
        "aws_key": aws_access_key,
        "github": github_pat_token,
        "slack": slack_bot_token,
        "stripe": stripe_live_key
    }