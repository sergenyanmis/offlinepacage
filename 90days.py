#!/usr/bin/env python3
import requests
import time
import csv
import os

# === Config ===
QRADAR_HOST = "172.24.16.3"
API_TOKEN = "fd636daf-4a3c-42ea-9ace-7f40dbe64984"

QRADAR_URL = f"https://{QRADAR_HOST}/"

headers = {
    'SEC': API_TOKEN,
    'Version': '12.0',
    'Accept': 'application/json'
}

requests.packages.urllib3.disable_warnings()

# Mevcut dosya varsa sil
inactive_rules_path = "/opt/test/sgm_inactive_rules.csv"
if os.path.exists(inactive_rules_path):
    os.remove(inactive_rules_path)

# 90 gün önceki epoch timestamp (saniye cinsinden)
ninety_days_ago = int(time.time() - 90 * 24 * 60 * 60)

# === 1. Adım: Tüm USER ve ENABLED kuralları çek ===
rules_url = f'{QRADAR_URL}/api/analytics/rules?filter=enabled=true AND origin="USER"'
rules_resp = requests.get(rules_url, headers=headers, verify=False)
all_rules = rules_resp.json()

# "SGM -" ile başlayan kuralları filtrele ve temizle
sgm_rules = sorted({
    rule['name'].strip()
    for rule in all_rules
    if rule.get('name', '').startswith("SGM -")
})

# === 2. Adım: Son 90 günde tetiklenen SGM kuralları (description içinde "SGM -" geçenler) ===
offenses_url = f'{QRADAR_URL}/api/siem/offenses?filter=categories CONTAINS "Device Information" AND start_time>{ninety_days_ago}'
offenses_resp = requests.get(offenses_url, headers=headers, verify=False)
offenses = offenses_resp.json()

# Description'ı "SGM -" ile başlayan offense'leri ayıkla ve temizle
triggered_sgm_rules = sorted({
    off['description'].strip()
    for off in offenses
    if off.get('description', '').startswith("SGM -")
})

# === 3. Adım: Tetiklenmemiş (inactive) SGM kuralları ===
inactive_sgm_rules = sorted(set(sgm_rules) - set(triggered_sgm_rules))

# === 4. Adım: CSV Dosyalarına Yaz ===
def write_csv(filename, title, data):
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([title])
        for item in data:
            writer.writerow([item])

write_csv("sgm_all_rules.csv", "All SGM Rules", sgm_rules)
write_csv("sgm_triggered_rules.csv", "Triggered SGM Rules", triggered_sgm_rules)
write_csv(inactive_rules_path, "Inactive SGM Rules", inactive_sgm_rules)

print("Tamamlandı. Oluşan CSV dosyaları:")
print("- sgm_all_rules.csv")
print("- sgm_triggered_rules.csv")
print(f"- {inactive_rules_path}")

