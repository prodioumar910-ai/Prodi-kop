import { FireAgentTestEngine } from './fireAgentSuite';
import { runIntegrationTests } from './integrationApiTest';

async function main() {
  console.log('======================================================================');
  console.log('       FIRE AGENT - SUITE DE VALIDATION & TESTS AUTOMATISÉS');
  console.log('======================================================================');
  console.log('Environnement : Banc d\'essai didactique (Données synthétiques pures)');
  console.log('Début des tests unitaires & multi-agents...\n');

  const summary = FireAgentTestEngine.runAllTests();

  summary.results.forEach((test, idx) => {
    const statusIcon = test.passed ? '✅ [RÉUSSI]' : '❌ [ÉCHEC]';
    console.log(`${idx + 1}. ${statusIcon} - ${test.name} (${test.category})`);
    console.log(`   Message : ${test.message}`);
    console.log(`   Durée   : ${test.durationMs.toFixed(2)} ms\n`);
  });

  console.log('----------------------------------------------------------------------');
  console.log('Début des tests d\'intégration API HTTP & SQLite (Port 3000)...\n');

  const integrationSummary = await runIntegrationTests();

  integrationSummary.results.forEach((test, idx) => {
    const statusIcon = test.passed ? '✅ [RÉUSSI]' : '❌ [ÉCHEC]';
    console.log(`${summary.results.length + idx + 1}. ${statusIcon} - ${test.name}`);
    console.log(`   Message : ${test.message}\n`);
  });

  const totalTests = summary.total + integrationSummary.results.length;
  const totalPassed = summary.passed + integrationSummary.results.filter(r => r.passed).length;
  const totalFailed = summary.failed + integrationSummary.results.filter(r => !r.passed).length;

  console.log('======================================================================');
  console.log(`RÉSULTAT GLOBAL : ${totalPassed} / ${totalTests} tests réussis (${totalFailed} échecs)`);
  console.log('======================================================================\n');

  if (totalFailed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Erreur non interceptée dans les tests:', err);
  process.exit(1);
});
