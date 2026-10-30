// Exercise the actual edge -> API/gateway -> PostgreSQL/volume paths.
// Self-signed TLS is accepted only by this local test client.
import https from 'node:https';
import assert from 'node:assert/strict';

const base = process.env.SMOKE_BASE_URL ?? 'https://edge';
const owner = new Map();
const guest = new Map();
const denied = new Map();
const payload = 'Storage Boxes Windows Compose: encrypted storage and verified delivery.\n';

async function call(method, path, body, jar = owner, extraHeaders = {}) {
  const raw = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  const headers = { Accept: 'application/json', ...extraHeaders };
  if (raw !== undefined && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  if (method !== 'GET' && jar.has('sb_csrf')) headers['X-CSRF-Token'] = jar.get('sb_csrf');
  return new Promise((resolve, reject) => {
    const req = https.request(new URL(path, base), { method, headers, rejectUnauthorized: false, timeout: 30000 }, res => {
      for (const cookie of res.headers['set-cookie'] ?? []) {
        const pair = cookie.split(';')[0];
        const i = pair.indexOf('=');
        jar.set(pair.slice(0, i), pair.slice(i + 1));
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        let json;
        try { json = JSON.parse(text); } catch { /* Downloads and HTML are not JSON. */ }
        resolve({ status: res.statusCode, text, json });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Smoke request timed out')));
    req.on('error', reject);
    req.end(raw);
  });
}

function expectStatus(response, status, label) {
  assert.equal(response.status, status, `${label}: expected ${status}, got ${response.status} (${response.json?.error?.code ?? 'no error code'})`);
  return response.json;
}

expectStatus(await call('GET', '/api/v1/auth/me', undefined, guest), 401, 'anonymous owner API');
expectStatus(await call('POST', '/api/v1/auth/login', {
  email: process.env.SEED_ADMIN_EMAIL, password: process.env.SEED_ADMIN_PASSWORD,
}), 200, 'admin login');
assert(owner.has('sb_csrf'), 'Login must issue CSRF cookie');
expectStatus(await call('GET', '/api/v1/auth/me'), 200, 'authenticated owner API');
assert((await call('GET', '/login')).text.includes('<div id="root"'), 'Frontend must serve the SPA');

// On repeat runs, verify data created by a previous container lifecycle.
const boxes = expectStatus(await call('GET', '/api/v1/boxes'), 200, 'persisted box listing');
const previous = boxes.items.filter(item => item.name.startsWith('Windows smoke ') && item.status === 'active')
  .sort((a, b) => b.name.localeCompare(a.name))[0];
if (previous) {
  const session = expectStatus(await call('POST', `/api/v1/boxes/${previous.id}/sessions`, {
    password: 'local-smoke-box-password',
  }), 200, 'persisted box unlock');
  const headers = { 'X-Unlock-Session': session.session_id };
  const files = expectStatus(await call('GET', `/api/v1/boxes/${previous.id}/files`, undefined, owner, headers), 200, 'persisted file listing');
  const file = files.items.find(item => item.logical_path === '/smoke.txt');
  assert(file, 'Previous smoke sample must retain its file');
  const download = await call('GET', `/api/v1/boxes/${previous.id}/files/${file.id}/content`, undefined, owner, headers);
  expectStatus(download, 200, 'persisted encrypted download');
  assert.equal(download.text, payload, 'Previous sample must still decrypt with the retained master key');
  console.log('PASS: previous sample retained and decrypted successfully.');
}

const name = `Windows smoke ${new Date().toISOString()}`;
const box = expectStatus(await call('POST', '/api/v1/boxes', {
  name, size_bytes: 1048576, password: 'local-smoke-box-password',
}), 201, 'box create');
const unlock = expectStatus(await call('POST', `/api/v1/boxes/${box.id}/sessions`, {
  password: 'local-smoke-box-password',
}), 200, 'box unlock');
const unlockHeaders = { 'X-Unlock-Session': unlock.session_id };
const uploaded = expectStatus(await call('PUT', `/api/v1/boxes/${box.id}/files?path=/smoke.txt`, payload, owner, {
  ...unlockHeaders, 'Content-Type': 'text/plain',
}), 201, 'encrypted upload');
const fileId = uploaded.entry.id;
const roundTrip = await call('GET', `/api/v1/boxes/${box.id}/files/${fileId}/content`, undefined, owner, unlockHeaders);
expectStatus(roundTrip, 200, 'vault download');
assert.equal(roundTrip.text, payload, 'Vault download must match the original bytes');

async function createShare(restricted) {
  return expectStatus(await call('POST', '/api/v1/shares', {
    box_id: box.id, file_entry_id: fileId, expiry_seconds: 3600, max_downloads: 20,
    ...(restricted ? { access_mode: 'restricted', recipient_emails: ['member@example.com'] } : {}),
  }, owner, unlockHeaders), 201, restricted ? 'restricted share create' : 'temporary share create');
}
const temporary = await createShare(false);
const publicDownload = await call('GET', `/s/${temporary.token}`, undefined, new Map());
expectStatus(publicDownload, 200, 'temporary download');
assert.equal(publicDownload.text, payload);

const share = await createShare(true);
const publicPath = `/s/${share.token}`;
expectStatus(await call('GET', publicPath, undefined, guest), 401, 'restricted delivery before approval');
const submit = expectStatus(await call('POST', `${publicPath}/request-access`, {
  email: 'guest@example.com', message: 'Windows Compose smoke check',
}, guest), 202, 'access request submission');
assert.deepEqual(submit, { status: 'pending' }, 'Public response must contain only coarse status');
expectStatus(await call('POST', `${publicPath}/request-access`, { email: 'guest@example.com' }, guest), 202, 'duplicate submission');
const requests = expectStatus(await call('GET', `/api/v1/shares/${share.id}/access-requests?status=pending`), 200, 'owner inspection');
assert.equal(requests.items.length, 1, 'Duplicate requests must not create extra pending rows');
const approval = expectStatus(await call('POST', `/api/v1/shares/${share.id}/access-requests/${requests.items[0].id}/approve`, {}), 200, 'owner approval');
assert(approval.passcode, 'Approval must mint a normal recipient passcode');
expectStatus(await call('GET', publicPath, undefined, guest), 401, 'approval must not bypass verification');
expectStatus(await call('POST', `${publicPath}/verify`, { email: 'guest@example.com', passcode: approval.passcode }, guest), 200, 'verification after approval');
assert(guest.has('sb_share_claim'), 'Verification must issue a claim cookie');
const delivery = await call('GET', publicPath, undefined, guest);
expectStatus(delivery, 200, 'verified restricted delivery');
assert.equal(delivery.text, payload);
expectStatus(await call('DELETE', `/api/v1/shares/${share.id}/recipients/${approval.recipient.id}`), 204, 'recipient revocation');
assert.notEqual((await call('GET', publicPath, undefined, guest)).status, 200, 'Revoked recipient must not download');
const afterRevoke = expectStatus(await call('GET', `${publicPath}/request-status?email=guest%40example.com`, undefined, guest), 200, 'public status after revocation');
assert.equal(afterRevoke.status, 'none');

expectStatus(await call('POST', `${publicPath}/request-access`, { email: 'denied@example.com' }, denied), 202, 'second request submission');
const pending = expectStatus(await call('GET', `/api/v1/shares/${share.id}/access-requests?status=pending`), 200, 'pending denial inspection');
expectStatus(await call('POST', `/api/v1/shares/${share.id}/access-requests/${pending.items[0].id}/deny`, { reason: 'Smoke check denial' }), 204, 'owner denial');
assert.notEqual((await call('POST', `${publicPath}/verify`, { email: 'denied@example.com', passcode: 'invalid' }, denied)).status, 200);
assert.notEqual((await call('GET', publicPath, undefined, denied)).status, 200);
const audit = expectStatus(await call('GET', '/api/v1/audit/events?limit=200'), 200, 'audit query');
for (const event of ['shares.access_requested', 'shares.access_request_approved', 'shares.access_request_denied', 'shares.accessed']) {
  assert(audit.items?.some(item => item.event_type === event), `Audit must contain ${event}`);
}
console.log('PASS: login, SPA, encrypted vault round-trip, temporary share, restricted request/dedupe/approval/verification/delivery/revocation/denial, audit.');
console.log(`Retained sample box: ${name} (password: local-smoke-box-password).`);
