
# 🛡️ T-Pot Honeypot Lab & Attack Analytics 🎯

Laboratorio completo para el despliegue, integración, análisis y visualización de ciberataques en tiempo real usando **T-Pot Honeypot Platform** y **Elastic Stack**.

---

## 📖 Tabla de Contenidos

- [1. Descripción del Proyecto](#1-descripción-del-proyecto)
- [2. Topología del Laboratorio](#2-topología-del-laboratorio)
- [3. Instalación paso a paso](#3-instalación-paso-a-paso)
- [4. Uso y Gestión de T-Pot](#4-uso-y-gestión-de-t-pot)
- [5. Análisis de ataques reales](#5-análisis-de-ataques-reales)
- [6. Metodología de investigación de ataques](#6-metodología-de-investigación-de-ataques)
- [7. Buenas prácticas y Lecciones Aprendidas](#7-buenas-prácticas-y-lecciones-aprendidas)
- [8. Referencias](#8-referencias)
- [9. Créditos y Contacto](#9-créditos-y-contacto)

---

## 1️⃣ Descripción del Proyecto

🔬 Laboratorio práctico de ciberseguridad que simula un entorno real para **detectar, analizar y visualizar ataques** usando:

- 🦾 **T-Pot** (suite de honeypots)
- 📊 **Elastic Stack** (Kibana, Elasticvue, etc)
- 🔎 Herramientas OSINT (Shodan, VirusTotal, AbuseIPDB...)

Incluye:  
✔️ Instalación paso a paso  
✔️ Integración de dashboards  
✔️ Análisis avanzado de IPs atacantes  
✔️ Buenas prácticas para SOC y Blue Team  

---

## 2️⃣ Topología del Laboratorio

- 🖥️ **Servidor Cloud** (Contabo, Hetzner, OVH…)
    - Ubuntu 24.04, 6 vCPU, 12GB RAM (ajustable)
- 🔒 **T-Pot**: Honeypots Dionaea, Cowrie, Honeytrap…
- 📦 **Elastic Stack**: Dashboards, analítica y visualización
- 🔐 SSH seguro, firewall, acceso web protegido

```
[Internet] 🌐 → [VPS/Cloud] → [T-Pot] ↔ [Elastic Stack] → [Dashboards/Web]
```

> _Puedes incluir un diagrama visual aquí con la topología de red_

---

## 3️⃣ Instalación paso a paso

### 🧰 3.1 Prerrequisitos

- VPS o servidor dedicado  
- Ubuntu 22.04/24.04  
- Acceso root (temporalmente)

### ⚙️ 3.2 Instalación de T-Pot

```bash
# Descargar el repositorio oficial
git clone https://github.com/telekom-security/tpotce.git
cd tpotce

# Crear usuario recomendado y asignar permisos (no root)
adduser pruebas
usermod -aG sudo pruebas

# Ejecutar instalación como usuario NO root (pero con sudo)
sudo ./install.sh
```
➡️ Sigue las instrucciones interactivas del instalador.

### 🚦 3.3 Post-instalación

- Cambiar el puerto SSH 🔒  
- Configurar acceso web (puertos, firewall)  
- Reiniciar el servidor  
- Validar acceso web a T-Pot y Kibana

---

## 4️⃣ Uso y Gestión de T-Pot

- Acceso web: `https://<ip-servidor>:64295`  
- Dashboards principales:
    - 📊 Kibana: `/kibana`
    - 🕸️ Elasticvue, 🕵️ Spiderfoot, 🗺️ Attack Map...

---

## 5️⃣ Análisis de ataques reales

### 📊 Visualización en Dashboards

Incluye:

- Número y tipo de ataques  
- Honeypot impactado  
- País/ciudad de origen  
- Estadísticas por puerto/protocolo  
- Usuarios/contraseñas más atacados

![Dashboard Principal](screenshots/Captura de pantalla 2025-05-21 181844.png)

---

### 🏷️ Ejemplo de Caso Analizado

|    🕓 timestamp    |     🌐 src_ip      |  🎯 dest_ip | 🏷️ alert.category                    | 🔔 alert.signature                             |
|-------------------|-------------------|------------|--------------------------------------|------------------------------------------------|
| 2025-05-21 14:09  | 34.95.113.255     | tu_ip      | Generic Protocol Command Decode      | SURICATA STREAM reassembly sequence GAP...     |
| 2025-05-21 14:07  | 34.95.113.255     | tu_ip      | Attempted Admin Privilege Gain       | SSH Brute-Force attempt detected               |
| 2025-05-21 14:02  | 34.95.113.255     | tu_ip      | Network Trojan                       | ET MALWARE Win32/Banker Trojan Downloader      |

![Detalle de Evento en Kibana](screenshots/Captura de pantalla 2025-05-21 182100.png)

---

### 🔍 Investigación OSINT sobre la IP Atacante

#### 🟢 VirusTotal

- Resultado: Clean  
- ASN: Google Cloud  
- País: EE.UU.  
![VirusTotal](screenshots/Captura de pantalla 2025-05-21 182135.png)

#### 🟠 AbuseIPDB

- 36 reportes, principalmente brute-force y port scan  
- Confianza de abuso: 2%  
![AbuseIPDB](screenshots/Captura de pantalla 2025-05-21 182220.png)

#### 🔴 Shodan

- Abierto en puertos 80/443  
- Hostnames: telemetry.elastic.co, googleusercontent.com  
- Cloud Provider: Google  
![Shodan](screenshots/Captura de pantalla 2025-05-21 182253.png)

#### 🔵 IPVoid

- No listado en blacklists  
- Ubicación: Kansas City, Missouri  
![IPVoid](screenshots/Captura de pantalla 2025-05-21 182333.png)

---

## 6️⃣ Metodología de investigación de ataques

1. **Filtrar por IP en Kibana/Elastic:**
   - Búsqueda por campo `src_ip` o `dest_ip`
   - Analizar patrones, frecuencia, honeypots impactados

2. **Extraer detalles relevantes:**
   - Puertos, protocolos, timestamps, alertas Suricata

3. **Consultar la IP en OSINT:**
   - [VirusTotal](https://www.virustotal.com/)
   - [AbuseIPDB](https://www.abuseipdb.com/)
   - [Shodan](https://www.shodan.io/)
   - [IPVoid](https://www.ipvoid.com/)

4. **Clasificar el ataque:**
   - Brute-force, PortScan, Exploit, Malware, etc

5. **Sacar conclusiones:**
   - ¿Automatizado? ¿Ataque activo o histórico?
   - ¿Repetición en el tiempo? ¿Indicadores de compromiso?

---

## 7️⃣ Buenas prácticas y Lecciones Aprendidas

- 🚫 **NO** instalar T-Pot como root
- 🔍 Usa filtrados avanzados en Kibana (`src_ip`, tipo de alerta, honeypot…)
- 🤖 Automatiza consultas OSINT si es posible
- 📝 Documenta cada hallazgo y captura pantallas
- 🔄 Refuerza la seguridad: firewall, segmentación de red, acceso limitado

---

## 8️⃣ Referencias

- [T-Pot GitHub](https://github.com/telekom-security/tpotce)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Shodan](https://www.shodan.io/)
- [Elastic Stack Docs](https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-elastic-stack.html)
- [Ejemplo laboratorio Wazuh (by U7Dani)](https://github.com/U7Dani/wazuh-kali-lab)

---

## 9️⃣ Créditos y Contacto

👤 Proyecto realizado por [Daniel Sánchez García](https://www.linkedin.com/in/danielsánchezgarcía/)  
📧 Contacto: [GitHub/U7Dani](https://github.com/U7Dani) | [LinkedIn](https://www.linkedin.com/in/danielsánchezgarcía/)

---

## 🖼️ Capturas recomendadas

Guarda todas las capturas en `/screenshots/` y referencia aquí:

- Dashboard general
- Eventos Suricata
- Búsqueda por IP
- Consultas en VirusTotal, Shodan, AbuseIPDB, IPVoid
- Estadísticas por honeypot, país, usuario, contraseña, etc.

---
