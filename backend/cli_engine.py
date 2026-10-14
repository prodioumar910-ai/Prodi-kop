#!/usr/bin/env python3
"""
FIRE AGENT — Interface CLI pour le moteur d'analyse et SQLite.
Permet au serveur Express (ou tout autre orchestrateur) d'exécuter
directement le moteur Python multi-agents et la persistance SQLite
sans dépendre d'un port réseau externe, avec sérialisation JSON stricte.

Commandes disponibles :
  python3 backend/cli_engine.py ingest '<json_event>'
  python3 backend/cli_engine.py history [limit] [offset] [risk_level] [event_type]
  python3 backend/cli_engine.py get <event_id>
  python3 backend/cli_engine.py stats
  python3 backend/cli_engine.py rules
  python3 backend/cli_engine.py health
"""

import sys
import os
import json

# Configuration du path
sys.path.insert(0, os.path.dirname(__file__))

from models import SecurityEventInput, ValidationError, SensitiveDataRejectedError
from agents import FireAgentPipeline
from rule_engine import SecurityRuleEngine, RULES_CATALOG
from storage import EventStorage

storage = EventStorage()

def cmd_ingest(raw_json_str: str):
    try:
        data = json.loads(raw_json_str)
    except Exception as e:
        print(json.dumps({"error": f"JSON syntaxe invalide : {str(e)}", "code": 400}))
        sys.exit(1)

    try:
        event = SecurityEventInput.from_dict(data)
    except SensitiveDataRejectedError as se:
        print(json.dumps({"error": f"Rejet de sécurité : {str(se)}", "code": 422}))
        sys.exit(2)
    except ValidationError as ve:
        print(json.dumps({"error": f"Validation échouée : {str(ve)}", "code": 422}))
        sys.exit(2)

    # 1. Exécution par le moteur de règles déterministe
    direct_analysis = SecurityRuleEngine.evaluate(event)

    # 2. Exécution ordonnée par les 6 agents logiciels
    chief_output = FireAgentPipeline.execute(event)

    # Enregistrement persistant dans SQLite
    saved_record = storage.save_event_with_analysis(event, direct_analysis)

    # Réponse enrichie avec l'arbre d'exécution des 6 agents
    response_payload = {
        "status": "success",
        "stored": True,
        "event": event.to_dict(),
        "analysis": direct_analysis.to_dict(),
        "agents_pipeline": chief_output.final_analysis.get("agents_pipeline", {}),
        "alert_priority": chief_output.alert_priority,
        "consensus_score": chief_output.consensus_score,
        "hardening_recommendations": chief_output.hardening_recommendations,
        "stored_at": saved_record.get("stored_at")
    }

    print(json.dumps(response_payload, ensure_ascii=False))

def cmd_history(limit=50, offset=0, risk_level=None, event_type=None):
    events = storage.get_events(limit=int(limit), offset=int(offset), risk_level=risk_level, event_type=event_type)
    stats = storage.get_statistics()
    print(json.dumps({
        "status": "success",
        "total_count": stats["total_events"],
        "returned_count": len(events),
        "events": events
    }, ensure_ascii=False))

def cmd_get(event_id: str):
    event = storage.get_event_by_id(event_id)
    if not event:
        print(json.dumps({"error": f"Événement '{event_id}' introuvable", "code": 404}))
        sys.exit(1)
    print(json.dumps({"status": "success", "event": event}, ensure_ascii=False))

def cmd_stats():
    stats = storage.get_statistics()
    print(json.dumps({"status": "success", "stats": stats}, ensure_ascii=False))

def cmd_rules():
    print(json.dumps({"status": "success", "total": len(RULES_CATALOG), "rules": RULES_CATALOG}, ensure_ascii=False))

def cmd_health():
    print(json.dumps({
        "status": "operational",
        "service": "FIRE AGENT Multi-Agent Engine",
        "version": "1.0.0",
        "database": "sqlite3",
        "agents_count": 6,
        "rules_count": len(RULES_CATALOG)
    }, ensure_ascii=False))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Commande requise (ingest, history, get, stats, rules, health)"}))
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "ingest":
        if len(sys.argv) < 3:
            # Essayer de lire depuis stdin
            input_data = sys.stdin.read().strip()
            if not input_data:
                print(json.dumps({"error": "Payload JSON requis"}))
                sys.exit(1)
            cmd_ingest(input_data)
        else:
            cmd_ingest(sys.argv[2])
    elif cmd == "history":
        lim = sys.argv[2] if len(sys.argv) > 2 else 50
        off = sys.argv[3] if len(sys.argv) > 3 else 0
        risk = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "None" else None
        etype = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] != "None" else None
        cmd_history(lim, off, risk, etype)
    elif cmd == "get":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "event_id requis"}))
            sys.exit(1)
        cmd_get(sys.argv[2])
    elif cmd == "stats":
        cmd_stats()
    elif cmd == "rules":
        cmd_rules()
    elif cmd == "health":
        cmd_health()
    else:
        print(json.dumps({"error": f"Commande inconnue '{cmd}'"}))
        sys.exit(1)
