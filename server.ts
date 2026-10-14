import express, { Request, Response } from 'express';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const isProd = process.env.NODE_ENV === 'production';

// Parsing middleware
app.use(express.json({ limit: '5mb' }));

// Helper pour exécuter le moteur Python de manière asynchrone et sécurisée
function runPythonEngine(command: string, args: string[] = [], inputData?: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const pythonScript = path.resolve(__dirname, 'backend', 'cli_engine.py');
    const childArgs = [pythonScript, command, ...args];
    
    const child = spawn('python3', childArgs, {
      cwd: __dirname,
      env: { ...process.env, PYTHONUNBUFFERED: '1' }
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (err) => {
      reject(err);
    });

    child.on('close', (code) => {
      resolve({ stdout: stdout.trim(), stderr: stderr.trim(), code: code ?? 0 });
    });

    if (inputData) {
      child.stdin.write(inputData);
      child.stdin.end();
    }
  });
}

// ==============================================================================
// ROUTES API BACKEND (/api/*)
// ==============================================================================

// 1. Contrôle d'état et disponibilité du moteur
app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    const result = await runPythonEngine('health');
    if (result.code === 0) {
      const data = JSON.parse(result.stdout);
      res.json({
        ...data,
        node_server: 'operational',
        port: PORT,
        proxy_mode: 'integrated_fastapi_engine'
      });
    } else {
      res.status(500).json({ error: 'Erreur d\'exécution du moteur Python', details: result.stderr });
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Service backend indisponible', details: err.message });
  }
});

// 2. Catalogue des règles de détection
app.get('/api/rules', async (_req: Request, res: Response) => {
  try {
    const result = await runPythonEngine('rules');
    if (result.code === 0) {
      res.json(JSON.parse(result.stdout));
    } else {
      res.status(500).json({ error: 'Impossible de charger les règles', details: result.stderr });
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur', details: err.message });
  }
});

// 3. Statistiques globales d'ingestion depuis SQLite
app.get('/api/stats', async (_req: Request, res: Response) => {
  try {
    const result = await runPythonEngine('stats');
    if (result.code === 0) {
      res.json(JSON.parse(result.stdout));
    } else {
      res.status(500).json({ error: 'Erreur lors de la récupération des statistiques', details: result.stderr });
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur', details: err.message });
  }
});

// 4. Ingestion, analyse multi-agents et persistance SQLite
app.post('/api/events', async (req: Request, res: Response) => {
  try {
    const payload = req.body;
    if (!payload || typeof payload !== 'object') {
      return res.status(400).json({ error: 'Corps JSON invalide ou vide.' });
    }

    // Sérialisation du payload JSON et transmission au moteur Python
    const jsonStr = JSON.stringify(payload);
    const result = await runPythonEngine('ingest', [], jsonStr);

    if (result.code === 0) {
      const parsed = JSON.parse(result.stdout);
      return res.status(201).json(parsed);
    } else if (result.code === 2) {
      // Erreur de validation ou rejet de données sensibles
      try {
        const errObj = JSON.parse(result.stdout);
        return res.status(errObj.code || 422).json(errObj);
      } catch {
        return res.status(422).json({ error: result.stdout || 'Rejet de validation.' });
      }
    } else {
      // Erreur d'exécution
      try {
        const errObj = JSON.parse(result.stdout);
        return res.status(errObj.code || 400).json(errObj);
      } catch {
        return res.status(500).json({ error: 'Échec d\'analyse de l\'événement', details: result.stderr || result.stdout });
      }
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur interne lors de l\'ingestion', details: err.message });
  }
});

// 5. Historique des événements enregistrés dans SQLite
app.get('/api/events', async (req: Request, res: Response) => {
  try {
    const limit = (req.query.limit as string) || '50';
    const offset = (req.query.offset as string) || '0';
    const riskLevel = (req.query.risk_level as string) || 'None';
    const eventType = (req.query.event_type as string) || 'None';

    const result = await runPythonEngine('history', [limit, offset, riskLevel, eventType]);
    if (result.code === 0) {
      res.json(JSON.parse(result.stdout));
    } else {
      res.status(500).json({ error: 'Impossible de lire l\'historique', details: result.stderr });
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur', details: err.message });
  }
});

// 6. Consultation d'un événement spécifique par identifiant
app.get('/api/events/:id', async (req: Request, res: Response) => {
  try {
    const eventId = req.params.id;
    const result = await runPythonEngine('get', [eventId]);
    if (result.code === 0) {
      res.json(JSON.parse(result.stdout));
    } else {
      res.status(404).json({ error: `Événement '${eventId}' introuvable dans SQLite.` });
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Erreur serveur', details: err.message });
  }
});

// ==============================================================================
// INTÉGRATION VITE FRONTEND (DEV & PROD)
// ==============================================================================
async function startServer() {
  if (!isProd) {
    // Mode Développement : montage des middlewares Vite
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR === 'true' ? false : false // iFrame preview does not route raw WebSockets to container
      },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    // Mode Production : fichiers statiques compilés dans dist
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔥 FIRE AGENT Full-Stack Server démarré sur http://0.0.0.0:${PORT}`);
    console.log(`   - Frontend Vite actif sur port ${PORT}`);
    console.log(`   - API Backend Python & SQLite connectés sur http://0.0.0.0:${PORT}/api`);
  });
}

startServer().catch((err) => {
  console.error('Erreur critique lors du démarrage du serveur:', err);
  process.exit(1);
});
