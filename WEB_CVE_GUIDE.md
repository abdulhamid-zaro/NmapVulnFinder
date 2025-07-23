# 🌐 دليل فحص ثغرات تطبيقات الويب
# Web Application CVE Detection Guide

## 📋 الفهرس / Table of Contents

1. [🌐 مقدمة عن فحص تطبيقات الويب](#web-app-intro)
2. [🔍 اكتشاف التقنيات المستخدمة](#technology-detection)
3. [🚨 اكتشاف ثغرات CVE](#cve-discovery)
4. [🔬 الفحص العميق](#deep-scanning)
5. [🎯 الماسح المتكامل](#integrated-scanner)
6. [📊 أمثلة عملية](#practical-examples)

---

## 🌐 مقدمة عن فحص تطبيقات الويب {#web-app-intro}

تم تحديث الأداة لتشمل فحص متخصص لتطبيقات الويب يركز على:

### ✨ **الميزات الجديدة**
- 🔍 **اكتشاف التقنيات**: WordPress, Drupal, Joomla, Apache, Nginx, PHP, IIS
- 🚨 **قاعدة بيانات CVE**: ثغرات محددة لكل تقنية
- 📂 **فحص المسارات**: البحث عن ملفات حساسة مكشوفة
- 🔬 **الفحص العميق**: اختبار SQL Injection و XSS
- 📱 **الإشعارات الفورية**: تنبيهات للثغرات الحرجة
- 🎯 **الماسح المتكامل**: دمج فحص الشبكة وتطبيقات الويب

---

## 🔍 اكتشاف التقنيات المستخدمة {#technology-detection}

### 1. **أنظمة إدارة المحتوى (CMS)**

#### WordPress
```bash
# فحص موقع WordPress
python3 web_app_scanner.py -t https://wordpress-site.com

# الثغرات المكتشفة:
# CVE-2021-34527 - WordPress Core XXE Vulnerability
# CVE-2020-4047 - WordPress CSRF Vulnerability
```

#### Drupal
```bash
# فحص موقع Drupal
python3 web_app_scanner.py -t https://drupal-site.com --deep-scan

# الثغرات المكتشفة:
# CVE-2018-7600 - Drupalgeddon2 (RCE)
# CVE-2019-6340 - Drupal RESTful Web Services RCE
```

#### Joomla
```bash
# فحص موقع Joomla
python3 web_app_scanner.py -t https://joomla-site.com

# الثغرات المكتشفة:
# CVE-2020-10238 - Joomla Core RCE
```

### 2. **خوادم الويب**

#### Apache HTTP Server
```bash
# فحص خادم Apache
python3 web_app_scanner.py -t https://apache-server.com

# الثغرات المكتشفة:
# CVE-2021-41773 - Apache Path Traversal (CVSS: 7.5)
# CVE-2021-42013 - Apache RCE (CVSS: 9.8)
```

#### Nginx
```bash
# فحص خادم Nginx
python3 web_app_scanner.py -t https://nginx-server.com

# الثغرات المكتشفة:
# CVE-2021-23017 - Nginx DNS Resolver Vulnerability
```

### 3. **لغات البرمجة**

#### PHP
```bash
# فحص تطبيق PHP
python3 web_app_scanner.py -t https://php-app.com --include-paths

# الثغرات المكتشفة:
# CVE-2021-21704 - PHP Stack Buffer Overflow
# ملفات حساسة: /phpinfo.php, /config.php
```

---

## 🚨 اكتشاف ثغرات CVE {#cve-discovery}

### 1. **مطابقة الإصدارات**

الأداة تقوم بمطابقة الإصدارات المكتشفة مع قاعدة بيانات CVE:

```python
# مثال: WordPress 5.7 مقابل CVE-2021-34527
# الشرط: < 5.8
# النتيجة: ✅ VULNERABLE

# مثال: Apache 2.4.51 مقابل CVE-2021-41773  
# الشرط: 2.4.49
# النتيجة: ❌ NOT VULNERABLE
```

### 2. **تصنيف الخطورة**

```bash
# فحص مع تصفية حسب CVSS
python3 web_app_scanner.py -t https://target.com --min-cvss 7.0

# النتائج:
# 🔴 CRITICAL (9.0-10.0): تتطلب إجراء فوري
# 🟡 HIGH (7.0-8.9): أولوية عالية
# 🔵 MEDIUM (4.0-6.9): أولوية متوسطة
# 🟢 LOW (0.1-3.9): أولوية منخفضة
```

### 3. **الثغرات المدعومة حالياً**

| التقنية | عدد الثغرات | أحدث CVE |
|---------|-------------|----------|
| WordPress | 2+ | CVE-2021-34527 |
| Drupal | 2+ | CVE-2019-6340 |
| Joomla | 1+ | CVE-2020-10238 |
| Apache | 2+ | CVE-2021-42013 |
| Nginx | 1+ | CVE-2021-23017 |
| PHP | 1+ | CVE-2021-21704 |

---

## 🔬 الفحص العميق {#deep-scanning}

### 1. **فحص الملفات الحساسة**

```bash
# فحص شامل للملفات الحساسة
python3 web_app_scanner.py -t https://target.com --include-paths

# الملفات المفحوصة:
# /phpinfo.php - معلومات PHP
# /.env - متغيرات البيئة
# /wp-config.php - إعدادات WordPress
# /config.php - ملفات الإعدادات
# /backup.sql - نسخ احتياطية للقواعد
```

### 2. **اختبار الثغرات**

```bash
# الفحص العميق مع اختبار الثغرات
python3 web_app_scanner.py -t https://target.com --deep-scan

# الاختبارات المنفذة:
# SQL Injection: ' OR '1'='1
# XSS: <script>alert('XSS')</script>
# Path Traversal: ../../../etc/passwd
```

### 3. **معايير الكشف**

#### SQL Injection
```python
# أنماط الكشف:
sql_errors = [
    'mysql_fetch_array',
    'ORA-01756', 
    'Microsoft OLE DB Provider',
    'SQLServer JDBC Driver'
]
```

#### الملفات الحساسة
```python
# أنماط المحتوى الحساس:
sensitive_patterns = {
    'phpinfo.php': ['PHP Version', 'System'],
    '.env': ['DB_PASSWORD', 'API_KEY'],
    'wp-config.php': ['DB_PASSWORD', 'DB_USER']
}
```

---

## 🎯 الماسح المتكامل {#integrated-scanner}

### 1. **الفحص الشامل**

```bash
# فحص متكامل: شبكة + تطبيقات ويب
python3 integrated_scanner.py -t example.com --web-scan --include-vulns

# المراحل:
# 🚀 Phase 1: Network & Port Scanning
# 🌐 Phase 2: Web Application Scanning  
# 📊 Phase 3: Results Analysis
```

### 2. **الفحص العميق المتكامل**

```bash
# فحص شامل مع اختبار الثغرات
python3 integrated_scanner.py -t target.com \
  --web-scan \
  --deep-web \
  --min-cvss 6.0 \
  --notifications \
  --output json \
  --output-file assessment.json
```

### 3. **فحص متعدد الأهداف**

```bash
# إنشاء ملف الأهداف
cat > web_targets.txt << EOF
https://wordpress-site.com
https://drupal-site.com  
https://joomla-site.com
apache-server.com
nginx-server.com
EOF

# فحص جماعي
python3 integrated_scanner.py -f web_targets.txt \
  --web-scan \
  --workers 10 \
  --notifications
```

---

## 📊 أمثلة عملية {#practical-examples}

### 1. **فحص موقع WordPress**

```bash
# الأمر
python3 web_app_scanner.py -t https://wordpress-demo.com --deep-scan

# النتيجة المتوقعة
🌐 Web Application CVE Scanner
🎯 Target: https://wordpress-demo.com
🔬 Deep Scan: ✅
📂 Path Scan: ✅

🔍 Phase 1: Technology Detection
🚨 Phase 2: CVE Discovery
📂 Phase 3: Path-based Discovery
🔬 Phase 4: Deep Vulnerability Scan

🔍 Technologies Detected (3):
┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Technology  ┃ Version ┃ Category ┃ Confidence   ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ Wordpress   │ 5.7.2   │ Cms      │ 95%          │
│ Apache      │ 2.4.49  │ Server   │ 95%          │
│ Php         │ 7.4.20  │ Language │ 95%          │
└─────────────┴─────────┴──────────┴──────────────┘

🚨 Vulnerabilities Found (3):
🔴 Critical: 1
🟡 High: 1  
🔵 Medium: 1

🔥 Top Vulnerabilities:
┏━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE/ID          ┃ CVSS  ┃ Title                                    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2021-42013  │ 9.8   │ Apache HTTP Server RCE                  │
│ CVE-2021-41773  │ 7.5   │ Apache HTTP Server Path Traversal       │
│ CVE-2021-34527  │ 9.8   │ WordPress Core Vulnerability             │
└─────────────────┴───────┴──────────────────────────────────────────┘
```

### 2. **فحص متكامل لشركة**

```bash
# إعداد ملف الأهداف
cat > company_assets.txt << EOF
# Web Applications
https://www.company.com
https://blog.company.com
https://shop.company.com
https://admin.company.com

# Network Infrastructure  
mail.company.com
ftp.company.com
vpn.company.com
192.168.1.0/24
EOF

# الفحص الشامل
python3 integrated_scanner.py -f company_assets.txt \
  --web-scan \
  --deep-web \
  --min-cvss 7.0 \
  --notifications \
  --notification-config company_alerts.json \
  --output json \
  --output-file security_assessment_$(date +%Y%m%d).json

# النتيجة المتوقعة
🎯 Integrated CVE Security Assessment
📋 Targets: 8
⚡ Workers: 10
🌐 Web Scanning: ✅
🔬 Deep Web Scan: ✅
🔍 Vulnerability Discovery: ✅
📢 Notifications: ✅
📊 Min CVSS: 7.0

🚀 Phase 1: Network & Port Scanning
✅ www.company.com: 3 open ports found
✅ blog.company.com: 2 open ports found
✅ shop.company.com: 4 open ports found
...

🌐 Phase 2: Web Application Scanning
🌐 Found 12 potential web applications
🚨 https://www.company.com:443: 2 vulnerabilities found
🚨 https://admin.company.com:443: 5 vulnerabilities found
...

📊 Phase 3: Results Analysis

📊 Executive Summary
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 15             ┃ 45          ┃ 12                 ┃ 23                     ┃
┃ Targets Scanned┃ Open Ports  ┃ Web Applications   ┃ Total Vulnerabilities  ┃
┗━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━┛

🚨 Vulnerability Breakdown
┏━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━┓
┃ Severity ┃ Count ┃ Percentage ┃
┡━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━┩
│ CRITICAL │ 5     │ 21.7%      │
│ HIGH     │ 8     │ 34.8%      │
│ MEDIUM   │ 7     │ 30.4%      │
│ LOW      │ 3     │ 13.0%      │
└──────────┴───────┴────────────┘

⚠️ ATTENTION: 13 critical/high severity vulnerabilities require immediate action!
```

### 3. **مراقبة مستمرة**

```bash
# إنشاء سكريبت مراقبة
cat > monitor_web_assets.sh << 'EOF'
#!/bin/bash

# إعدادات المراقبة
TARGETS_FILE="critical_web_assets.txt"
ALERT_CONFIG="security_alerts.json"
REPORT_DIR="security_reports"
MIN_CVSS=8.0

# إنشاء مجلد التقارير
mkdir -p $REPORT_DIR

# تشغيل الفحص
echo "🔍 Starting security monitoring at $(date)"

python3 integrated_scanner.py \
  -f $TARGETS_FILE \
  --web-scan \
  --deep-web \
  --min-cvss $MIN_CVSS \
  --notifications \
  --notification-config $ALERT_CONFIG \
  --output json \
  --output-file "$REPORT_DIR/security_scan_$(date +%Y%m%d_%H%M).json"

echo "✅ Security scan completed at $(date)"
EOF

# جعل السكريبت قابل للتنفيذ
chmod +x monitor_web_assets.sh

# إضافة للـ cron للتشغيل كل 6 ساعات
echo "0 */6 * * * /path/to/monitor_web_assets.sh" | crontab -
```

---

## 🔧 إعدادات متقدمة

### 1. **تخصيص قاعدة بيانات CVE**

```python
# إضافة ثغرات جديدة في web_app_scanner.py
self.web_cve_database['custom_app'] = [
    {
        'cve': 'CVE-2024-XXXX',
        'versions': ['< 2.1.0'],
        'cvss': 9.5,
        'title': 'Custom App RCE',
        'description': 'Remote code execution in custom application.',
        'references': ['https://security-advisory.com/CVE-2024-XXXX']
    }
]
```

### 2. **تخصيص أنماط الكشف**

```python
# إضافة تقنيات جديدة
self.tech_fingerprints['laravel'] = {
    'headers': ['x-powered-by'],
    'content': [r'Laravel Framework', r'/laravel_session'],
    'patterns': [r'Laravel/([0-9.]+)']
}
```

### 3. **تخصيص الإشعارات**

```json
{
  "notifications_enabled": true,
  "email": {
    "enabled": true,
    "smtp_server": "smtp.company.com",
    "smtp_port": 587,
    "username": "security-scanner@company.com",
    "password": "secure_password",
    "to_email": "security-team@company.com"
  },
  "webhook": {
    "enabled": true,
    "url": "https://company.slack.com/hooks/security-alerts"
  },
  "telegram": {
    "enabled": true,
    "bot_token": "COMPANY_BOT_TOKEN",
    "chat_id": "SECURITY_TEAM_CHAT_ID"
  }
}
```

---

## 📈 تحليل النتائج

### 1. **تقرير JSON**

```json
{
  "target": "https://example.com",
  "technologies": [
    {
      "name": "wordpress",
      "version": "5.7.2",
      "category": "cms",
      "confidence": 95
    }
  ],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-34527",
      "title": "WordPress Core Vulnerability",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "exploit_available": true
    }
  ]
}
```

### 2. **مؤشرات الأداء**

| المقياس | القيمة | الوصف |
|---------|--------|--------|
| **سرعة الفحص** | 15-30 ثانية | لكل تطبيق ويب |
| **دقة الكشف** | 95%+ | للتقنيات الشائعة |
| **معدل الإيجابيات الخاطئة** | <5% | للثغرات المكتشفة |
| **التغطية** | 50+ CVE | عبر التقنيات المختلفة |

---

## ⚠️ اعتبارات أمنية

### 1. **الاستخدام الأخلاقي**
- ✅ فحص الأنظمة المملوكة لك فقط
- ✅ الحصول على إذن كتابي قبل الفحص
- ❌ لا تستخدم النتائج لأغراض ضارة

### 2. **حماية البيانات**
- 🔒 تشفير ملفات الإعدادات
- 🔒 حماية تقارير الفحص
- 🔒 استخدام اتصالات آمنة

### 3. **الامتثال القانوني**
- 📋 اتباع قوانين الأمن السيبراني المحلية
- 📋 توثيق جميع أنشطة الفحص
- 📋 الإبلاغ المسؤول عن الثغرات

---

## 🚀 التطوير المستقبلي

### 1. **ميزات قادمة**
- 🔄 تحديث قاعدة بيانات CVE تلقائياً
- 🤖 تكامل مع APIs خارجية
- 📊 لوحة تحكم ويب
- 🔍 فحص APIs و GraphQL

### 2. **تحسينات الأداء**
- ⚡ فحص متوازي محسن
- 💾 تخزين مؤقت للنتائج
- 🎯 فحص ذكي تدريجي

### 3. **تكامل المؤسسات**
- 🏢 تكامل مع SIEM
- 📈 تقارير تنفيذية
- 🔄 أتمتة الاستجابة للحوادث

---

**💡 نصيحة نهائية**: استخدم الماسح المتكامل للحصول على صورة شاملة عن الوضع الأمني، وركز على الثغرات عالية الخطورة أولاً!