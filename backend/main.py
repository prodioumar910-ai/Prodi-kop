"""
Serveur API Backend FIRE AGENT utilisant FastAPI.
Architecture indépendante du frontend pour la réception, la validation,
le stockage et l'analyse de véritables événements de cybersécurité.

Endpoints :
- POST /api/events          : Réception, validation, analyse et enregistrement persistant
- GET  /api/events          : Consultation de l'historique avec filtres et pagination
- GET  /api/events/{id}     : Détail d'un événement et de son rapport d'analyse
- POST /api/analyze         : Analyse instantanée sans persistance (mode simulation / test)
- GET  /api/rules           : Consultation du catalogue des règles du moteur
- GET  /api/stats           : Statistiques d'ingestion et répartition des risques
- GET  /api/health          : Statut de disponibilité du service backend
"""

try:
    from fastapi import FastAPI, HTTPException, Request, Response, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from models import SecurityEventInput, ValidationError, SensitiveDataRejectedError
from rule_engine import SecurityRuleEngine, RULES_CATALOG
from storage import EventStorage

storage = EventStorage()

if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="FIRE AGENT — API d'Analyse de Cybersécurité",
        description="Moteur d'analyse multi-règles et passerelle d'ingestion d'événements informatiques.",
        version="1.0.0"
    )

    # Middleware CORS pour autoriser les requêtes du frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health_check():
        return {
            "status": "operational",
            "service": "FIRE AGENT Security Analysis Engine",
            "version": "1.0.0",
            "storage": "sqlite3",
            "rules_count": len(RULES_CATALOG)
        }

    @app.get("/api/rules")
    def list_rules():
        """Renvoie le catalogue complet des règles d'analyse."""
        return {
            "total_rules": len(RULES_CATALOG),
            "rules": RULES_CATALOG
        }

    @app.post("/api/events", status_code=status.HTTP_201_CREATED)
    async def ingest_event(request: Request):
        """
        Reçoit un événement informatique au format JSON.
        Vérifie la conformité, rejette les formats invalides ou contenant des données sensibles,
        exécute l'analyse de risque et persiste le résultat.
        """
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payload JSON malformé ou illisible."
            )

        try:
            event = SecurityEventInput.from_dict(payload)
        except SensitiveDataRejectedError as se:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Rejet de sécurité : {str(se)}"
            )
        except ValidationError as ve:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Validation échouée : {str(ve)}"
            )

        # Transmission au moteur d'analyse
        analysis = SecurityRuleEngine.evaluate(event)

        # Enregistrement dans le stockage persistant
        stored_record = storage.save_event_with_analysis(event, analysis)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=stored_record
        )

    @app.post("/api/analyze")
    async def dry_run_analyze(request: Request):
        """Analyse un événement sans l'enregistrer dans la base (mode simulation)."""
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payload JSON malformé ou illisible."
            )

        try:
            event = SecurityEventInput.from_dict(payload)
        except (ValidationError, SensitiveDataRejectedError) as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(e)
            )

        analysis = SecurityRuleEngine.evaluate(event)
        return {
            "event": event.to_dict(),
            "analysis": analysis.to_dict()
        }

    @app.get("/api/events")
    def get_events_history(
        limit: int = 50,
        offset: int = 0,
        risk_level: str = None,
        event_type: str = None
    ):
        """Consulte l'historique des événements analysés."""
        events = storage.get_events(limit=limit, offset=offset, risk_level=risk_level, event_type=event_type)
        stats = storage.get_statistics()
        return {
            "total_count": stats["total_events"],
            "returned_count": len(events),
            "events": events
        }

    @app.get("/api/events/{event_id}")
    def get_event_detail(event_id: str):
        """Détail complet d'un événement analysé."""
        event = storage.get_event_by_id(event_id)
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Événement '{event_id}' introuvable."
            )
        return event

    @app.get("/api/stats")
    def get_stats():
        """Statistiques globales d'ingestion et niveaux de risque."""
        return storage.get_statistics()

else:
    app = None
