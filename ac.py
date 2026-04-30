import base64
import re
from lxml import etree

path = "/opt/test/qradar-rule-analyzer/offline-package/data/latest_export.xml"
data = open(path, "rb").read()
data = re.sub(rb'[\x00-\x08\x0b\x0c\x0e-\x1f]', b'', data)
root = etree.fromstring(data)

for r in root.findall("custom_rule"):
    raw_b64 = r.findtext("rule_data")
    if not raw_b64:
        continue
    raw = base64.b64decode(raw_b64)
    raw = re.sub(rb'[\x00-\x08\x0b\x0c\x0e-\x1f]', b'', raw)
    inner = etree.fromstring(raw)
    name = inner.findtext("name")
    tests = inner.findall(".//test")
    print("KURAL:", name)
    print("TEST SAYISI:", len(tests))
    for t in tests:
        tname = t.get("name")
        print("  TEST:", tname)
        for us in t.findall(".//userSelection"):
            val = us.text or ""
            print("    VAL:", val[:120])
    print()
