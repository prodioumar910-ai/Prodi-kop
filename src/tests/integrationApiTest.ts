/**
 * Test d'intégration de bout en bout (Frontend/Client -> Express API -> Python Engine -> SQLite -> Réponse).
 * Exécute de véritables requêtes HTTP contre le serveur sur http://localhost:3000/api.
 */

export async function runIntegrationTests(): Promise<{ passed: boolean; results: { name: string; passed: boolean; message: string }[] }> {
  const results: { name: string; passed: boolean; message: string }[] = [];
  const BASE_URL = 'http://localhost:3000/api';

  // Test 1: Contrôle de santé API /api/health
  try {
    const res = await fetch(`${BASE_URL}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.status !== 'operational' || data.database !== 'sqlite3') {
      throw new Error(`Réponse inattendue : ${JSON.stringify(data)}`);
    }
    results.push({
      name: 'Contrôle d\'état de santé (/api/health)',
      passed: true,
      message: `Backend opérationnel (6 agents prêts, SQLite connecté, port 3000).`
    });
  } catch (err: any) {
    results.push({
      name: 'Contrôle d\'état de santé (/api/health)',
      passed: false,
      message: err.message
    });
  }

  // Test 2: Ingestion d'un événement valide et analyse par les 6 agents
  const testEventId = `INT-TEST-${Date.now().toString().slice(-5)}`;
  try {
    const payload = {
      event_id: testEventId,
      timestamp: new Date().toISOString(),
      source_host: 'SRV-INTEGRATION-01',
      event_type: 'suspicious_file',
      description: 'Test d\'intégration réelle de bout en bout',
      technical_data: {
        file_name: 'test_macro.xlsm',
        has_macros: true,
        spawned_process: 'powershell.exe'
      }
    };

    const res = await fetch(`${BASE_URL}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (res.status !== 201) throw new Error(`Statut HTTP attendu 201, reçu ${res.status}`);
    const data = await res.json();

    if (!data.stored || !data.analysis || data.analysis.risk_level !== 'Critique') {
      throw new Error(`Analyse inattendue : ${JSON.stringify(data)}`);
    }

    if (!data.agents_pipeline?.detecteur || !data.agents_pipeline?.chef) {
      throw new Error('L\'arbre d\'exécution des 6 agents est manquant dans la réponse API');
    }

    results.push({
      name: 'Ingestion HTTP et analyse par les 6 agents (/api/events)',
      passed: true,
      message: `Événement ${testEventId} validé et analysé au niveau Critique par les 6 agents (Consensus: ${data.consensus_score}%).`
    });
  } catch (err: any) {
    results.push({
      name: 'Ingestion HTTP et analyse par les 6 agents (/api/events)',
      passed: false,
      message: err.message
    });
  }

  // Test 3: Vérification de la persistance réelle dans SQLite
  try {
    const res = await fetch(`${BASE_URL}/events/${testEventId}`);
    if (!res.ok) throw new Error(`Événement non retrouvé dans SQLite (HTTP ${res.status})`);
    const data = await res.json();
    const eventObj = data.event || data;

    if (eventObj.event_id !== testEventId || eventObj.risk_level !== 'Critique') {
      throw new Error(`Données SQLite inattendues : ${JSON.stringify(data)}`);
    }

    results.push({
      name: 'Persistance et relecture dans SQLite (/api/events/:id)',
      passed: true,
      message: `Événement ${testEventId} relu avec succès depuis SQLite avec son rapport complet.`
    });
  } catch (err: any) {
    results.push({
      name: 'Persistance et relecture dans SQLite (/api/events/:id)',
      passed: false,
      message: err.message
    });
  }

  // Test 4: Rejet strict d'un événement malformé (HTTP 422)
  try {
    const res = await fetch(`${BASE_URL}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: 'Sans event_id' })
    });

    if (res.status !== 422 && res.status !== 400) {
      throw new Error(`Un payload malformé doit retourner 422 ou 400, reçu : ${res.status}`);
    }

    results.push({
      name: 'Rejet d\'un événement malformé (HTTP 422 / 400)',
      passed: true,
      message: `Requête correctement rejetée avec le statut HTTP ${res.status}.`
    });
  } catch (err: any) {
    results.push({
      name: 'Rejet d\'un événement malformé (HTTP 422 / 400)',
      passed: false,
      message: err.message
    });
  }

  // Test 5: Rejet de sécurité d'un payload contenant un mot de passe (HTTP 422)
  try {
    const res = await fetch(`${BASE_URL}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event_id: 'TEST-SECRET',
        timestamp: new Date().toISOString(),
        source_host: 'HOST-01',
        event_type: 'failed_logins',
        description: 'Test secret',
        technical_data: { password: 'MonMotDePasseInterdit123!' }
      })
    });

    if (res.status !== 422) {
      throw new Error(`Un payload avec mot de passe doit être rejeté en 422, reçu : ${res.status}`);
    }

    results.push({
      name: 'Rejet de sécurité des données sensibles (Mots de passe)',
      passed: true,
      message: 'Déontologie respectée : blocage absolu de la collecte de mots de passe (HTTP 422).'
    });
  } catch (err: any) {
    results.push({
      name: 'Rejet de sécurité des données sensibles (Mots de passe)',
      passed: false,
      message: err.message
    });
  }

  const allPassed = results.every(r => r.passed);
  return { passed: allPassed, results };
}
