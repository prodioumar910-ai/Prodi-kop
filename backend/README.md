# FIRE AGENT — Backend & Moteur d'Analyse de Cybersécurité (FastAPI & Python)

Ce répertoire contient l'architecture backend indépendante pour l'ingestion, la validation, le stockage et l'analyse d'événements de cybersécurité réels pour **FIRE AGENT**.

## 1. Caractéristiques Principales

- **Framework** : Python avec FastAPI (ou serveur autonome standard `http.server`).
- **Validation Stricte** :
  - Vérification de structure JSON.
  - Rejet immédiat des événements incomplets ou malformés (`HTTP 422 / 400`).
  - **Principe de minimisation et de déontologie** : Rejet absolu de tout payload contenant des mots de passe, clés d'API ou tokens secrets.
- **Stockage Persistant** : Base SQLite (`fire_agent.db`) avec horodatage, indexation et traçabilité complète.
- **Moteur de Règles Déterministe & Transparent** :
  - **R-AUTH-01 & R-AUTH-02** : Échecs répétés et attaques par force brute (Brute Force / Password Spraying).
  - **R-CONN-01 & R-CONN-02** : Connexions inhabituelles (Déplacement géographique impossible > 900 km/h, accès distant non autorisé sur port sensible).
  - **R-FILE-01 & R-FILE-02** : Fichiers suspects (Macro bureautique avec déclenchement de shell PowerShell/cmd, extensions dissimulées).
  - **R-PHISH-01 & R-PHISH-02** : Phishing simulé (Échecs SPF/DKIM, domaine de moins de 15 jours avec formulaire de capture).
- **Transparence Absolue** : Chaque analyse produit le niveau de risque (`Faible`, `Élevé`, `Critique`), les règles déclenchées, les motifs explicites, les limites d'analyse et les recommandations de remédiation.

## 2. Format Standard des Événements (`SecurityEventInput`)

```json
{
  "event_id": "EVT-2026-1010-001",
  "timestamp": "2026-10-10T08:30:00Z",
  "source_host": "SRV-DC-01",
  "event_type": "failed_logins",
  "description": "Multiples échecs de connexion sur le compte d'administration",
  "technical_data": {
    "source_ip": "194.26.29.112",
    "failed_attempts": 22,
    "targeted_account": "admin"
  }
}
```

### Types d'événements autorisés :
- `failed_logins` : Échecs d'authentification
- `unusual_connection` : Connexions distantes anormales
- `suspicious_file` : Détection de fichiers et processus suspects
- `phishing_simulation` : Courriels suspects et leurres
- `telemetry_scan` : Sondes et diagnostics
- `generic_event` : Événements génériques surveillés

## 3. Installation et Démarrage

### Option A — Avec FastAPI & Uvicorn (recommandé en production) :
```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Option B — Mode autonome (sans dépendances pip externes) :
```bash
python3 backend/standalone_server.py 8000
```

## 4. Endpoints API

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/api/events` | Valide, analyse et enregistre un événement |
| `GET` | `/api/events` | Liste l'historique des événements (avec pagination et filtres) |
| `GET` | `/api/events/{id}` | Détail d'un événement spécifique et de son analyse |
| `POST` | `/api/analyze` | Analyse à la volée sans persistance (dry-run) |
| `GET` | `/api/rules` | Catalogue complet des règles et seuils du moteur |
| `GET` | `/api/stats` | Métriques globales et répartition des risques |
| `GET` | `/api/health` | Contrôle d'état du service |

## 5. Exécution de la Suite de Tests Automatisés

```bash
python3 backend/test_engine.py
```
Les 9 tests couvrent la validation, le rejet des événements malformés, le filtrage des secrets, chacune des 4 familles de règles, la persistance SQLite et la transparence des décisions.
