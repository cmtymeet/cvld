import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createIssuer, createHolder, createVerifier, createMemoryReceiptStore,
} from '../src/index.js';
import { makeGate, makeAuthenticator, NOW, ORIGIN, RP_ID, POLICY } from './fixtures.js';

let base;
function fixture() {
  if (!base) {
    const gates = Object.fromEntries(POLICY.factors.map((factor) => [factor, makeGate(factor)]));
    const issuer = createIssuer({
      issuerId: 'https://issuer.example/cvld', policy: POLICY,
      attesters: Object.fromEntries(Object.entries(gates).map(([id, gate]) => [id, gate.public])),
      receiptStore: createMemoryReceiptStore({ maxEntries: 100 }),
      maxCredentialLifetimeSeconds: 900, clock: () => NOW,
    });
    base = { gates, issuer };
  }
  return base;
}
function verifier(issuer, overrides = {}) {
  return createVerifier({
    publicIssuer: issuer.public, policy: POLICY, origin: ORIGIN, rpID: RP_ID,
    clock: () => NOW, challengeLifetimeSeconds: 120, maxPendingChallenges: 20,
    maxPresentationBytes: 100_000, requireUserVerification: true, ...overrides,
  });
}
async function member({ factor = 'phone', validUntil = NOW + 600 } = {}) {
  const { issuer, gates } = fixture();
  const holder = createHolder();
  const offer = issuer.offer();
  const pending = holder.request(issuer.public, offer);
  const attestation = gates[factor].attest(offer, pending.request, POLICY, { validUntil });
  const issued = await issuer.issue({ offer, request: pending.request, attestations: [attestation] });
  pending.accept(issued);
  return { issuer, holder, issued, pending, offer, attestation };
}
async function attempt(v, holder, issuer, authenticator = makeAuthenticator()) {
  const challenge = v.begin(authenticator.credential, ORIGIN);
  const presentation = holder.present(issuer.public, challenge);
  const authentication = authenticator.assert(challenge.authentication.challenge);
  return { id: challenge.id, audience: ORIGIN, presentation, authentication };
}

test('real blind credential issuance, proof and passkey assertion produce only true', async () => {
  const { issuer, holder, issued } = await member();
  const v = verifier(issuer);
  assert.equal(await v.verify(await attempt(v, holder, issuer)), true);
  assert.equal(issued.rev_reg_id, null);
});

test('each independently permitted factor admits a holder', async () => {
  for (const factor of POLICY.factors) {
    const { issuer, holder } = await member({ factor });
    const v = verifier(issuer);
    assert.equal(await v.verify(await attempt(v, holder, issuer)), true);
  }
});

test('issuer rejects a forged attestation signature before producing credentials', async () => {
  const { issuer, gates } = fixture();
  const holder = createHolder();
  const offer = issuer.offer();
  const pending = holder.request(issuer.public, offer);
  const attestation = gates.phone.attest(offer, pending.request);
  attestation.signature = Buffer.alloc(64).toString('base64url');
  await assert.rejects(issuer.issue({ offer, request: pending.request, attestations: [attestation] }));
});

test('an attestation cannot be moved to another blinded holder request', async () => {
  const { issuer, gates } = fixture();
  const offer = issuer.offer();
  const one = createHolder().request(issuer.public, offer);
  const two = createHolder().request(issuer.public, offer);
  const attestation = gates.phone.attest(offer, one.request);
  await assert.rejects(issuer.issue({ offer, request: two.request, attestations: [attestation] }));
});

test('concurrent reuse of one gate receipt issues at most one credential', async () => {
  const { issuer, gates } = fixture();
  const offer = issuer.offer();
  const pending = createHolder().request(issuer.public, offer);
  const attestation = gates.phone.attest(offer, pending.request);
  const input = { offer, request: pending.request, attestations: [attestation] };
  const results = await Promise.allSettled([issuer.issue(input), issuer.issue(input)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
});

test('a credential cannot be processed with another holder secret', async () => {
  const { issuer, issued } = await member();
  const other = createHolder().request(issuer.public, issuer.offer());
  assert.throws(() => other.accept(issued));
});

test('a proof is rejected under another audience, session or policy', async () => {
  const { issuer, holder } = await member();
  for (const mutate of [
    (input) => ({ ...input, audience: 'https://another.example' }),
    (input) => ({ ...input, id: 'invented-session' }),
    (input) => ({ ...input, presentation: { ...input.presentation, proof: {} } }),
  ]) {
    const v = verifier(issuer);
    assert.equal(await v.verify(mutate(await attempt(v, holder, issuer))), false);
  }
  assert.throws(() => verifier(issuer, { policy: { ...POLICY, version: '2' } }));
});

test('a proof cannot be transplanted between fresh passkey sessions', async () => {
  const { issuer, holder } = await member();
  const v = verifier(issuer);
  const first = await attempt(v, holder, issuer);
  const second = await attempt(v, holder, issuer);
  assert.equal(await v.verify({ ...second, presentation: first.presentation }), false);
});

test('a genuine proof cannot bypass a forged passkey signature', async () => {
  const { issuer, holder } = await member();
  const v = verifier(issuer);
  const input = await attempt(v, holder, issuer);
  input.authentication.response.signature = Buffer.alloc(70).toString('base64url');
  assert.equal(await v.verify(input), false);
});

test('a wrong origin, RP ID or missing user verification fails authentication', async () => {
  const { issuer, holder } = await member();
  for (const options of [{ origin: 'https://attacker.example' }, { rpID: 'attacker.example' }, { flags: 1 }]) {
    const v = verifier(issuer);
    const auth = makeAuthenticator();
    const c = v.begin(auth.credential, ORIGIN);
    const presentation = holder.present(issuer.public, c);
    assert.equal(await v.verify({ id: c.id, audience: ORIGIN, presentation, authentication: auth.assert(c.authentication.challenge, options) }), false);
  }
});

test('a session is consumed atomically and cannot be replayed', async () => {
  const { issuer, holder } = await member();
  const v = verifier(issuer);
  const input = await attempt(v, holder, issuer);
  const results = await Promise.all([v.verify(input), v.verify(input)]);
  assert.deepEqual(results.sort(), [false, true]);
});

test('renewed presentations of a reusable credential work without a ban record', async () => {
  const { issuer, holder } = await member();
  const v = verifier(issuer);
  const first = await attempt(v, holder, issuer);
  const second = await attempt(v, holder, issuer);
  assert.notDeepEqual(first.presentation, second.presentation);
  assert.equal(await v.verify(first), true);
  assert.equal(await v.verify(second), true);
});

test('a credential cannot authorize a challenge that outlives its hidden expiry', async () => {
  const { issuer, holder } = await member({ validUntil: NOW + 10 });
  const v = verifier(issuer);
  const challenge = v.begin(makeAuthenticator().credential, ORIGIN);
  assert.throws(() => holder.present(issuer.public, challenge));
});

test('a login challenge expires at the configured boundary', async () => {
  const { issuer, holder } = await member();
  let time = NOW;
  const v = verifier(issuer, { clock: () => time });
  const input = await attempt(v, holder, issuer);
  time += 120;
  assert.equal(await v.verify(input), false);
});

test('proof output does not disclose factor receipts, secret or exact expiry', async () => {
  const { issuer, holder, attestation } = await member();
  const v = verifier(issuer);
  const input = await attempt(v, holder, issuer);
  const encoded = JSON.stringify(input.presentation);
  assert.equal(encoded.includes(attestation.receiptId), false);
  assert.equal(encoded.includes(String(attestation.validUntil)), false);
  assert.deepEqual(Object.keys(input.presentation.requested_proof.revealed_attrs), ['policy']);
  assert.deepEqual(input.presentation.requested_proof.self_attested_attrs, {});
});

test('security configuration must be explicit and malformed proofs fail closed', async () => {
  const { issuer } = fixture();
  assert.throws(() => createVerifier({ publicIssuer: issuer.public, policy: POLICY }));
  const v = verifier(issuer);
  assert.equal(await v.verify({}), false);
  const c = v.begin(makeAuthenticator().credential, ORIGIN);
  assert.equal(await v.verify({ id: c.id, audience: ORIGIN, presentation: 'x'.repeat(100_001), authentication: {} }), false);
});
