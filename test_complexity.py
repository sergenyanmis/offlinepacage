from services.complexity_scorer import score_all_rules_from_export

path = "/opt/test/qradar-rule-analyzer/offline-package/data/latest_export.xml"
results = score_all_rules_from_export(path)

if not results:
    print("Sonuc yok — dosya okunamadi veya kural bulunamadi")

for r in results:
    print("KURAL:", r.rule_name)
    print("SKOR:", r.score)
    print("SINIF:", r.classification)
    print("ISSUES:", r.breakdown.issues)
    print()
