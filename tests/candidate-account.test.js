const test = require('node:test');
const assert = require('node:assert/strict');
const {createApp} = require('../app');
const {Candidate} = require('../models/mongo');
const {normalizePhone} = require('../routes/candidate-auth');
test('les accès au compte et au profil NIPCAN exigent une session', async () => {
  const server = createApp().listen(0);
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/v1`;
    for (const [route, method] of [['/candidate-auth/me','GET'], ['/candidats/nipcan/NIP2026000001/dashboard','GET'], ['/applications','POST']]) {
      const response = await fetch(base + route, {method});
      assert.equal(response.status, 401, route);
      assert.equal((await response.json()).success, false);
    }
    // La recherche par NIP reste publique (auto-remplissage du formulaire
    // d'inscription) : elle ne doit jamais répondre 401.
    const nipResponse = await fetch(base + '/candidats/nip/NIP2026000001', {method: 'GET'});
    assert.notEqual(nipResponse.status, 401, '/candidats/nip/:nip');
  } finally {await new Promise(resolve => server.close(resolve));}
});
test('les identifiants du compte sont uniques sans contraindre les anciens profils', () => {
  for (const field of ['username', 'accountPhone']) {
    const index = Candidate.schema.indexes().find(([fields]) => fields[field] === 1);
    assert.equal(index[1].unique, true);
    assert.equal(index[1].sparse, true);
  }
  assert.equal(Candidate.schema.path('passwordHash').options.select, false);
});
test('le téléphone de connexion ignore les séparateurs et harmonise 00', () => {
  assert.equal(normalizePhone('00241 77-12-34-56'), '+24177123456');
  assert.equal(normalizePhone('+241 (77) 12 34 56'), '+24177123456');
});
