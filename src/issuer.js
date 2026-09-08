import { createPublicKey, verify } from 'node:crypto';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { encodeAttestation, issuanceDigest, jsonAndRelease, normalizePolicy, policyDigest, requireClock, requirePositive, requireText } from './encoding.js';
const { Schema, CredentialDefinition, CredentialOffer, Credential } = anoncreds;

export function createIssuer(options) {
  const issuerId = requireText(options.issuerId, 'issuer ID');
  const policy = normalizePolicy(options.policy);
  const digest = policyDigest(policy);
  const clock = requireClock(options.clock);
  const maximumLifetime = requirePositive(options.maxCredentialLifetimeSeconds, 'credential lifetime');
  if (typeof options.receiptStore?.claimAll !== 'function') throw new TypeError('Atomic receipt store required');
  const receiptStore = options.receiptStore;
  const attesters = new Map(Object.entries(options.attesters ?? {}).map(([id, entry]) => {
    requireText(id, 'attester ID');
    if (!policy.factors.includes(entry.factor)) throw new TypeError('Attester factor is disabled');
    const publicKey = createPublicKey(entry.publicKey);
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 attester key required');
    return [id, { factor: entry.factor, publicKey }];
  }));
  if (!policy.factors.every((factor) => [...attesters.values()].some((entry) => entry.factor === factor))) throw new TypeError('Missing factor attester');
  const schemaId = `${issuerId}/schema/1`;
  const credentialDefinitionId = `${issuerId}/credential/${digest}`;
  const schema = jsonAndRelease(Schema.create({ name: 'cvld-eligibility', issuerId, version: '1', attributeNames: ['policy', 'eligible', 'valid_until'] }));
  const created = CredentialDefinition.create({ schemaId, issuerId, schema, signatureType: 'CL', supportRevocation: false, tag: digest });
  const credentialDefinition = jsonAndRelease(created.credentialDefinition);
  const credentialDefinitionPrivate = jsonAndRelease(created.credentialDefinitionPrivate);
  const keyCorrectnessProof = jsonAndRelease(created.keyCorrectnessProof);
  const publicIssuer = { issuerId, schemaId, credentialDefinitionId, schema, credentialDefinition, keyCorrectnessProof, policyDigest: digest };
  return {
    get public() { return structuredClone(publicIssuer); },
    offer() {
      return jsonAndRelease(CredentialOffer.create({ schemaId, credentialDefinitionId, keyCorrectnessProof }));
    },
    async issue({ offer, request, attestations }) {
      try {
        const now = clock();
        if (!Array.isArray(attestations) || attestations.length < 1 || attestations.length > policy.factors.length) throw new Error();
        if (offer.cred_def_id !== credentialDefinitionId || offer.schema_id !== schemaId || request.cred_def_id !== credentialDefinitionId) throw new Error();
        const requestHash = issuanceDigest(offer, request);
        const factors = new Set();
        const receipts = [];
        let validUntil = now + maximumLifetime;
        for (const attestation of attestations) {
          const attester = attesters.get(attestation.keyId);
          if (!attester || attestation.factor !== attester.factor || factors.has(attestation.factor) ||
              attestation.issuanceDigest !== requestHash || attestation.policyDigest !== digest ||
              attestation.validUntil <= now || attestation.validUntil > now + maximumLifetime ||
              !verify(null, encodeAttestation(attestation), attester.publicKey, Buffer.from(attestation.signature, 'base64url'))) throw new Error();
          factors.add(attestation.factor);
          receipts.push(JSON.stringify([issuerId, attestation.keyId, attestation.receiptId]));
          validUntil = Math.min(validUntil, attestation.validUntil);
        }
        if (policy.mode === 'all' && !policy.factors.every((factor) => factors.has(factor))) throw new Error();
        if (!(await receiptStore.claimAll(receipts, validUntil, now))) throw new Error();
        return jsonAndRelease(Credential.create({
          credentialDefinition, credentialDefinitionPrivate, credentialOffer: offer, credentialRequest: request,
          attributeRawValues: { policy: digest, eligible: '1', valid_until: String(validUntil) },
        }));
      } catch {
        // Provider values and native-library errors must not become public errors.
        throw new Error('Eligibility issuance rejected');
      }
    },
  };
}
