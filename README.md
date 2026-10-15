# 🛡️ Sigma Rules Detection

Набор Sigma-правил для обнаружения трёх распространённых атак:
- **Brute Force** (брутфорс)
- **Port Scan** (сканирование портов)
- **Password Spraying**

А также Python-скрипт для проверки логики этих правил на тестовых логах.

---

## 📂 Файлы

| Файл | Описание |
|------|----------|
| `bruteforce_sigma_rules.yml` | Sigma-правило для обнаружения брутфорса |
| `port_scan_sigma.yml` | Sigma-правило для обнаружения сканирования портов |
| `password_spraying_sigma.yml` | Sigma-правило для обнаружения Password Spraying |
| `check_sigma_rules.py` | Скрипт проверки логики правил на тестовых данных |
| `README.md` | Описание проекта |

---

## 🚀 Как использовать

1. Скопируйте `.yml` правила в вашу SIEM (Elastic, Splunk, Wazuh).
2. Запустите `check_sigma_rules.py`, чтобы проверить логику на тестовых логах:

```bash
python check_sigma_rules.py
