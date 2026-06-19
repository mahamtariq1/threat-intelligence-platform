
# 🛡️ Threat Intelligence Platform

Web-based collaborative threat intelligence and incident response platform that enables organizations to report, investigate, and resolve security incidents with automated IOC extraction, MITRE ATT&CK-mapped threat classification, realtime alerts, and severity-based prioritization.

![PHP](https://img.shields.io/badge/Backend-PHP-777BB4)
![MySQL](https://img.shields.io/badge/Database-MySQL-4479A1)
![Bootstrap](https://img.shields.io/badge/Frontend-Bootstrap%205-7952B3)

## ✨ Key Features

- 🔍 **Rule-Based IOC Extraction Engine** — automatically scans incident submissions to extract indicators of compromise (IPs, domains, hashes, etc.)
- 🎯 **MITRE ATT&CK Mapping** — classifies detected threats against standardized adversary tactics and techniques
- 📊 **Automated Severity Scoring** — calculates and assigns risk levels to incoming incidents to support faster triage
- 🚨 **Real-Time Alerts** — notifies organization admins of new or high-priority threats and incidents
- 🤝 **Cross-Organization Threat Sharing** — enables multiple organizations to collaboratively share and act on threat intelligence
- 🔐 **Role-Based Access Control** — dedicated dashboards and permissions for employees, security experts, and organization administrators
- 📁 **End-to-End Case Management** — from incident submission to expert review to resolution, fully tracked within the platform

## 🏗️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | PHP |
| Database | MySQL |
| Frontend | Bootstrap 5 |
| Server | Apache (XAMPP) |

## 📂 Project Structure
- **admin/** — Platform-wide admin panel and controls
- **auth/** — Login, registration, and session handling
- **employee/** — Employee case filing and dashboard
- **expert/** — Security expert investigation and reporting tools
- **org-admin/** — Organization-level admin controls, alerts, and case oversight
- **engine/** — Core IOC extraction and threat detection logic
- **includes/** — Shared layout and reusable components
- **database.sql** — Database schema
- **setup.php** — Initial setup script

## ⚙️ Setup & Installation

1. Clone this repository into your XAMPP `htdocs` folder:
```bash
   git clone https://github.com/mahamtariq1/threat-intelligence-platform.git
```
2. Start Apache and MySQL via XAMPP Control Panel
3. Import `database.sql` into MySQL using phpMyAdmin
4. Run `setup.php` to initialize the application
5. Access the platform at `http://localhost/threat-intelligence-platform`
6. credentials for platform admin: email:admin@platform.com password:password


- Built by **[Maham Tariq](https://github.com/mahamtariq1)**
- Cybersecurity student 

