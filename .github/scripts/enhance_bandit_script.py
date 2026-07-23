import json
import sys

# Bandit scrive 'level' (error/warning/note) sul singolo result, non sulla rule,
# e non scrive mai 'security-severity' — il campo che GitHub Security usa per
# il badge Critical/High/Medium/Low. Qui lo ricostruiamo:
# 1. per ogni rule, troviamo il level piu' alto tra i suoi result
# 2. lo mappiamo a un punteggio security-severity (0.0-10.0)
LEVEL_RANK = {'note': 0, 'warning': 1, 'error': 2}
LEVEL_TO_SEVERITY = {
    'error': '9.0',    # Critical/High
    'warning': '6.0',  # Medium
    'note': '3.0',     # Low
}


def apply_security_severity(sarif: dict) -> int:
    updated = 0
    for run in sarif.get('runs', []):
        rules = run.get('tool', {}).get('driver', {}).get('rules', [])
        results = run.get('results', [])

        # livello piu' alto per ogni ruleId, guardando i result
        best_level_by_rule = {}
        for result in results:
            rule_id = result.get('ruleId')
            level = result.get('level', 'warning')
            if rule_id is None:
                continue
            current_rank = LEVEL_RANK.get(best_level_by_rule.get(rule_id), -1)
            new_rank = LEVEL_RANK.get(level, -1)
            if new_rank > current_rank:
                best_level_by_rule[rule_id] = level

        for rule in rules:
            rule_id = rule.get('id')
            level = best_level_by_rule.get(rule_id)
            severity = LEVEL_TO_SEVERITY.get(level)
            if severity is None:
                continue
            rule.setdefault('properties', {})['security-severity'] = severity
            updated += 1
    return updated


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'results.sarif'
    try:
        with open(path, 'r') as f:
            data = json.load(f)

        n = apply_security_severity(data)

        with open(path, 'w') as f:
            json.dump(data, f)

        print(f'SARIF Bandit bonificato: security-severity assegnata a {n} rule.')
    except Exception as e:
        print(f'Errore durante la bonifica: {e}')
        sys.exit(1)