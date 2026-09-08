import { randomBytes } from 'node:crypto';
import { presentationRequest } from './requests.js';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { hash, policyDigest, requireClock, requirePositive, requireText } from './encoding.js';
const { Nonce, Presentation, anoncredsNodeJS } = anoncreds;

export function createVerifier(options) {
  const publicIssuer = structuredClone(options.publicIssuer);
  const digest = policyDigest(options.policy);
  if (publicIssuer?.policyDigest !== digest) throw new TypeError('Issuer policy does not match');
  const clock = requireClock(options.clock);
  const lifetime = requirePositive(options.challengeLifetimeSeconds, 'challenge lifetime');
  const maxPending = requirePositive(options.maxPendingChallenges, 'challenge capacity');
  const maxBytes = requirePositive(options.maxPresentationBytes, 'presentation limit');
  const origin = requireText(options.origin, 'origin');
  const rpID = requireText(options.rpID, 'RP ID');
  if (typeof options.requireUserVerification !== 'boolean') throw new TypeError('Explicit user verification policy required');
  const requireUV = options.requireUserVerification;
  const pending = new Map();
  const policyEncoding = anoncredsNodeJS.encodeCredentialAttributes({ attributeRawValues: [digest] })[0];
  return {
    // credential is trusted, previously registered WebAuthn verification material.
    begin(credential, audience) {
      requireText(audience, 'audience');
      requireText(credential?.id, 'credential ID');
      if (!(credential.publicKey instanceof Uint8Array) || !Number.isSafeInteger(credential.counter) || credential.counter < 0) throw new TypeError('Registered passkey required');
      const now = clock();
      for (const [id, value] of pending) if (value.expiresAt <= now) pending.delete(id);
      if (pending.size >= maxPending) throw new Error('Challenge capacity reached');
      const id = randomBytes(32).toString('base64url');
      const expiresAt = requirePositive(now + lifetime, 'challenge expiry');
      const request = presentationRequest(publicIssuer, Nonce.generate(), expiresAt);
      const authentication = {
        challenge: hash(JSON.stringify(['cvld.login.v1', id, audience, digest, request.nonce, expiresAt, credential.id, hash(credential.publicKey)])),
        rpId: rpID, userVerification: requireUV ? 'required' : 'preferred',
        allowCredentials: [{ id: credential.id, type: 'public-key' }],
      };
      const challenge = { id, audience, policyDigest: digest, expiresAt, request, authentication };
      pending.set(id, { ...structuredClone(challenge), credential, credentialSnapshot: structuredClone(credential) });
      return challenge;
    },
    async verify(input) {
      try {
        const state = pending.get(input?.id);
        if (!state) return false;
        // Consume before asynchronous work so concurrent/replayed requests fail.
        pending.delete(input.id);
        if (state.audience !== input.audience || clock() >= state.expiresAt) return false;
        const encoded = JSON.stringify(input.presentation);
        if (!encoded || Buffer.byteLength(encoded) > maxBytes || typeof input.presentation !== 'object' || input.presentation === null) return false;
        const proof = input.presentation.requested_proof;
        const disclosed = proof?.revealed_attrs?.policy;
        if (disclosed?.raw !== digest || disclosed.encoded !== policyEncoding ||
            Object.keys(proof.revealed_attrs).length !== 1 || Object.keys(proof.self_attested_attrs ?? {}).length !== 0 ||
            input.presentation.identifiers?.length !== 1 || input.presentation.identifiers[0].cred_def_id !== publicIssuer.credentialDefinitionId ||
            input.presentation.identifiers[0].schema_id !== publicIssuer.schemaId || input.presentation.identifiers[0].rev_reg_id !== null) return false;
        const presentation = Presentation.fromJson(input.presentation);
        let eligible;
        try {
          eligible = presentation.verify({
            presentationRequest: state.request,
            schemas: { [publicIssuer.schemaId]: publicIssuer.schema },
            credentialDefinitions: { [publicIssuer.credentialDefinitionId]: publicIssuer.credentialDefinition },
          });
        } finally { presentation.handle.clear(); }
        if (!eligible) return false;
        const result = await verifyAuthenticationResponse({
          response: input.authentication,
          expectedChallenge: state.authentication.challenge,
          expectedOrigin: origin, expectedRPID: rpID,
          credential: state.credentialSnapshot, requireUserVerification: requireUV,
        });
        if (!result.verified || clock() >= state.expiresAt) return false;
        const counter = result.authenticationInfo.newCounter;
        if ((counter > 0 || state.credential.counter > 0) && counter <= state.credential.counter) return false;
        state.credential.counter = counter;
        return true;
      } catch { return false; }
    },
  };
}
