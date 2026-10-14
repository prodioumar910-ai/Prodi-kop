"""
Serveur HTTP autonome FIRE AGENT utilisant la bibliothèque standard Python (http.server).
Fournit l'API REST complète sans nécessiter de paquets pip tiers (FastAPI / uvicorn).
Idéal pour exécuter le backend instantanément avec :
    python3 backend/standalone_server.py --port 8000
"""

import sys
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import des modules locaux
sys.path.insert(0, os.path.dirname(__file__))
from models import SecurityEventInput, ValidationError, SensitiveDataRejectedError
from rule_engine import SecurityRuleEngine, RULES_CATALOG
from storage import EventStorage

storage = EventStorage()

class FireAgentRequestHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_json_response(self, status_code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == '/api/health':
            self._send_json_response(200, {
                "status": "operational",
                "service": "FIRE AGENT Security Analysis Engine (Standalone Python)",
                "storage": "sqlite3",
                "rules_count": len(RULES_CATALOG)
            })
            return

        if path == '/api/rules':
            self._send_json_response(200, {
                "total_rules": len(RULES_CATALOG),
                "rules": RULES_CATALOG
            })
            return

        if path == '/api/stats':
            self._send_json_response(200, storage.get_statistics())
            return

        if path == '/api/events':
            limit = int(query.get('limit', [50])[0])
            offset = int(query.get('offset', [0])[0])
            risk = query.get('risk_level', [None])[0]
            etype = query.get('event_type', [None])[0]
            events = storage.get_events(limit=limit, offset=offset, risk_level=risk, event_type=etype)
            stats = storage.get_statistics()
            self._send_json_response(200, {
                "total_count": stats["total_events"],
                "returned_count": len(events),
                "events": events
            })
            return

        if path.startswith('/api/events/'):
            event_id = path.replace('/api/events/', '').strip()
            event = storage.get_event_by_id(event_id)
            if event:
                self._send_json_response(200, event)
            else:
                self._send_json_response(404, {"detail": f"Événement '{event_id}' introuvable."})
            return

        self._send_json_response(404, {"detail": "Endpoint non trouvé."})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Lecture du corps
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self._send_json_response(400, {"detail": "Corps de la requête vide."})
            return

        body_raw = self.rfile.read(content_length)
        try:
            payload = json.loads(body_raw.decode('utf-8'))
        except Exception:
            self._send_json_response(400, {"detail": "JSON malformé ou syntaxe invalide."})
            return

        if path == '/api/events' or path == '/api/analyze':
            try:
                event = SecurityEventInput.from_dict(payload)
            except SensitiveDataRejectedError as se:
                self._send_json_response(422, {"detail": f"Rejet de sécurité : {str(se)}"})
                return
            except ValidationError as ve:
                self._send_json_response(422, {"detail": f"Validation échouée : {str(ve)}"})
                return

            analysis = SecurityRuleEngine.evaluate(event)

            if path == '/api/events':
                record = storage.save_event_with_analysis(event, analysis)
                self._send_json_response(201, record)
            else:
                self._send_json_response(200, {
                    "event": event.to_dict(),
                    "analysis": analysis.to_dict()
                })
            return

        self._send_json_response(404, {"detail": "Endpoint POST non trouvé."})

def run(port: int = 8000):
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, FireAgentRequestHandler)
    print(f"🔥 FIRE AGENT Standalone Backend démarré sur http://0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
        httpd.server_close()

if __name__ == '__main__':
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run(port)
