# Projet Honeypot - Infrastructure de detection d'intrusions

## Objectif

Concevoir et deployer une infrastructure honeypot capable de :
- Attirer et detecter des tentatives d'intrusion en temps reel
- Capturer les techniques, outils et comportements des attaquants
- Centraliser les logs et visualiser les attaques sur un dashboard
- Demontrer la valeur d'un honeypot dans une strategie de defense

## Architecture

### Schema reseau

```
[INTERNET / Attaquant]
        |
   [ Firewall ]  ----  VM4 (pfSense) - optionnel
        |
  [ Switch virtuel ]
    /         \
VM1 (Honeypot)    VM2 (Monitoring)
                       |
                  [Dashboard]

VM3 (Attaquant) --- reseau isole pour demos
```

### VMs

| VM | Role | OS | IP (exemple) | RAM | Stockage |
|----|------|----|-------------|-----|----------|
| VM1 | Honeypot | Debian 12 | 10.0.0.10 | 2 Go | 20 Go |
| VM2 | Monitoring / SIEM | Ubuntu 22.04 | 10.0.0.20 | 8 Go | 50 Go |
| VM3 | Attaquant (demo) | Kali Linux | 10.0.0.50 | 2 Go | 30 Go |
| VM4 | Firewall (optionnel) | pfSense | 10.0.0.1 | 1 Go | 10 Go |

**Total minimum : 3 VMs (12 Go RAM, 100 Go disque)**

## Stack technique

### VM1 - Honeypot (services pieges)

**Cowrie** - Honeypot SSH/Telnet
- Simule un serveur SSH vulnérable
- Enregistre chaque commande tapée par l'attaquant
- Capture les mots de passe testes en brute force
- Enregistre les fichiers telecharges (malwares)

**Dionaea** - Honeypot multi-protocoles
- Expose : SMB, HTTP, FTP, MSSQL, MySQL, SIP
- Capture les payloads et binaires malveillants
- Emule des vulnerabilites connues pour attirer les exploits

**Ports exposes :**

| Port | Service | Honeypot | Ce qu'on capture |
|------|---------|----------|-----------------|
| 22 | SSH | Cowrie | Credentials, commandes, sessions |
| 23 | Telnet | Cowrie | Credentials, commandes |
| 80 | HTTP | Dionaea | Requetes, scans, exploits web |
| 21 | FTP | Dionaea | Credentials, fichiers deposes |
| 445 | SMB | Dionaea | Exploits (EternalBlue etc), malwares |
| 3306 | MySQL | Dionaea | Injections SQL, credentials |
| 1433 | MSSQL | Dionaea | Exploits, credentials |

### VM2 - Monitoring / SIEM

**ELK Stack** (Elasticsearch + Logstash + Kibana)
- **Elasticsearch** : stockage et indexation des logs
- **Logstash** : ingestion et parsing des logs Cowrie/Dionaea
- **Kibana** : dashboards temps reel, cartes geo des attaques

**Dashboards prevus :**
- Carte mondiale des IPs attaquantes (GeoIP)
- Top 10 des mots de passe testes
- Timeline des attaques par service
- Commandes les plus executees dans le faux shell
- Malwares captures (hashes, noms)

### VM3 - Attaquant (pour la demo)

**Kali Linux** avec :
- `nmap` - scan des ports du honeypot
- `hydra` - brute force SSH/FTP
- `metasploit` - exploits SMB (EternalBlue)
- `nikto` - scan vulnerabilites web
- Scripts custom pour simuler des attaques automatisees

## Deroulement de la demo

### Phase 1 - Presentation de l'infra (5 min)
- Expliquer le concept de honeypot (leurre vs production)
- Montrer l'architecture reseau
- Montrer les services exposes sur VM1

### Phase 2 - Attaque en direct (10 min)
1. **Scan** : `nmap -sV 10.0.0.10` depuis Kali - montre les ports ouverts
2. **Brute force SSH** : `hydra -l root -P wordlist.txt ssh://10.0.0.10` - teste des passwords
3. **Connexion SSH** : se connecter avec un password capture - montrer le faux shell
4. **Exploit SMB** : tenter EternalBlue via Metasploit
5. **Scan web** : `nikto -h http://10.0.0.10`

### Phase 3 - Analyse des resultats (10 min)
- Ouvrir Kibana sur VM2
- Montrer les dashboards en temps reel
- Analyser les logs de la session SSH (commandes tapees)
- Montrer la carte GeoIP (si on a des attaques externes)
- Presenter les credentials captures

### Phase 4 - Conclusion (5 min)
- Valeur ajoutee du honeypot dans un SOC
- Limites (faux positifs, maintenance, risque de pivot)
- Evolutions possibles (honeynets, deception platforms)

## Installation

### VM1 - Cowrie

```bash
# Installation
sudo apt update && sudo apt install -y git python3-venv
git clone https://github.com/cowrie/cowrie.git /opt/cowrie
cd /opt/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt

# Configuration
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Editer : hostname, listen_endpoints, output plugins (json)

# Rediriger le port 22 reel vers 2222, Cowrie ecoute sur 22
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Demarrer
bin/cowrie start
```

### VM1 - Dionaea

```bash
sudo apt install -y dionaea
# Config dans /etc/dionaea/dionaea.cfg
# Activer les services voulus (smb, http, ftp, mysql, mssql)
sudo systemctl enable dionaea
sudo systemctl start dionaea
```

### VM2 - ELK Stack

```bash
# Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic.list
sudo apt update && sudo apt install -y elasticsearch kibana logstash

# Configurer Logstash pour ingerer les logs Cowrie (JSON over TCP/file)
# Configurer Kibana : server.host: "0.0.0.0"

sudo systemctl enable elasticsearch kibana logstash
sudo systemctl start elasticsearch kibana logstash
```

### VM3 - Kali

```bash
# Deja pre-installe avec les outils necessaires
# Verifier :
which nmap hydra msfconsole nikto
```

## Risques et mitigations

| Risque | Mitigation |
|--------|-----------|
| L'attaquant pivote du honeypot vers le reseau reel | Isolation reseau stricte (VLAN dedie, firewall) |
| Le honeypot est identifie comme faux | Personnaliser les bannieres, ajouter de faux fichiers |
| Surcharge de logs (bruit) | Filtres Logstash, alertes uniquement sur events critiques |
| Problemes legaux (capture de donnees) | Environnement de lab isole, pas de donnees reelles |

## Livrables

- [ ] Infrastructure fonctionnelle (3 VMs)
- [ ] Demo d'attaque en direct
- [ ] Dashboard Kibana avec visualisations
- [ ] Documentation technique (ce document)
- [ ] Rapport d'analyse des attaques capturees
