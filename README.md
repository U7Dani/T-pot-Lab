
# 🛡️ T-Pot Honeypot Lab & Attack Analytics 🎯

![image](https://github.com/user-attachments/assets/ae6226c1-4347-4f10-bb4a-e910cfa4a6a2)

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
![image](https://github.com/user-attachments/assets/b28a1484-8085-466d-a6ca-0d411cf42009)


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
![image](https://github.com/user-attachments/assets/bea97994-74f3-44c2-90ce-dbf6269bf5df)

---

## 5️⃣ Análisis de ataques reales

### 📊 Visualización en Dashboards

Incluye:

- Número y tipo de ataques  
- Honeypot impactado  
- País/ciudad de origen  
- Estadísticas por puerto/protocolo  
- Usuarios/contraseñas más atacados

![image](https://github.com/user-attachments/assets/7a90d6f1-9252-4e54-9ac6-b7e410c99057)
![image](https://github.com/user-attachments/assets/cedadc56-f3c7-4870-bb29-e01e447b4b83)
![image](https://github.com/user-attachments/assets/b9aae1ac-bb35-4ceb-a99d-641153031ca1)
![image](https://github.com/user-attachments/assets/a31870c0-5829-4238-b133-8f5bfb48c55f)
![Captura de pantalla 2025-05-21 182529](https://github.com/user-attachments/assets/d483097a-9935-4494-af68-487f4546e4ea)
![Captura de pantalla 2025-05-21 182618](https://github.com/user-attachments/assets/ecd6f102-1430-4257-a7a0-746362c2d224)

---

### 🏷️ Ejemplo de Caso Analizado

|    🕓 timestamp    |     🌐 src_ip      |  🎯 dest_ip | 🏷️ alert.category                    | 🔔 alert.signature                             |
|-------------------|-------------------|------------|--------------------------------------|------------------------------------------------|
| 2025-05-21 14:09  | 34.95.113.255     | tu_ip      | Generic Protocol Command Decode      | SURICATA STREAM reassembly sequence GAP...     |
| 2025-05-21 14:07  | 34.95.113.255     | tu_ip      | Attempted Admin Privilege Gain       | SSH Brute-Force attempt detected               |
| 2025-05-21 14:02  | 34.95.113.255     | tu_ip      | Network Trojan                       | ET MALWARE Win32/Banker Trojan Downloader      |

![Captura de pantalla 2025-05-21 181844](https://github.com/user-attachments/assets/bfdfbfee-414b-4292-9d2f-46cbd2dce052)
![Captura de pantalla 2025-05-21 182100](https://github.com/user-attachments/assets/896b6bfb-0f63-43ad-9e29-2d01c60513f3)

---

### 🔍 Investigación OSINT sobre la IP Atacante

#### 🟢 VirusTotal

- Resultado: Clean  
- ASN: Google Cloud  
- País: EE.UU.  
![Captura de pantalla 2025-05-21 182135](https://github.com/user-attachments/assets/56fbfd66-ef9d-4df5-9075-cf0fa511c349)


#### 🟠 AbuseIPDB

- 36 reportes, principalmente brute-force y port scan  
- Confianza de abuso: 2%  
![Captura de pantalla 2025-05-21 182253](https://github.com/user-attachments/assets/9322bfb1-4d33-4723-9d7b-c7f07c4a78b2)
![Captura de pantalla 2025-05-21 182333](https://github.com/user-attachments/assets/1c4c6342-c961-4931-a840-73fe5d517d1d)

#### 🔴 Shodan

- Abierto en puertos 80/443  
- Hostnames: telemetry.elastic.co, googleusercontent.com  
- Cloud Provider: Google  

![Captura de pantalla 2025-05-21 182357](https://github.com/user-attachments/assets/a093664e-5ffd-435e-8c7c-5581fe871f1b)

#### 🔵 IPVoid

- No listado en blacklists  
- Ubicación: Kansas City, Missouri  

![Captura de pantalla 2025-05-21 182446](https://github.com/user-attachments/assets/5297e93d-5c4b-479e-a38e-66e64b3c1967)

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

