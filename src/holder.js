import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { presentationRequest } from './requests.js';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { jsonAndRelease } from './encoding.js';
const { LinkSecret, CredentialRequest, Credential, Presentation } = anoncreds;

// This object belongs in the holder's process, never in the verifier service.
export function createHolder() {
  const linkSecret = LinkSecret.create();
  let credential;
  return {
    request(publicIssuer, offer) {
      const requestPair = CredentialRequest.create({
        entropy: randomBytes(32).toString('base64url'),
        credentialDefinition: publicIssuer.credentialDefinition,
        linkSecret, linkSecretId: 'cvld-wallet', credentialOffer: offer,
      });
      const request = jsonAndRelease(requestPair.credentialRequest);
      const metadata = jsonAndRelease(requestPair.credentialRequestMetadata);
      let accepted = false;
      return {
        request,
        accept(issued) {
          if (accepted) throw new Error('Credential already processed');
          const received = Credential.fromJson(issued);
          try {
            received.process({ credentialDefinition: publicIssuer.credentialDefinition, credentialRequestMetadata: metadata, linkSecret });
            credential = received.toJson();
            accepted = true;
          } finally { received.handle.clear(); }
        },
      };
    },
    present(publicIssuer, challenge) {
      if (!credential) throw new Error('No holder credential');
      const permittedRequest = presentationRequest(publicIssuer, challenge.request?.nonce, challenge.expiresAt);
      if (!isDeepStrictEqual(challenge.request, permittedRequest)) throw new Error('Unapproved disclosure request');
      if (credential.values.policy.raw !== challenge.policyDigest) throw new Error('Credential policy does not match');
      if (Number(credential.values.valid_until.raw) < challenge.expiresAt) throw new Error('Credential expires before challenge');
      return jsonAndRelease(Presentation.create({
        presentationRequest: challenge.request,
        credentials: [{ credential }],
        credentialsProve: [
          { entryIndex: 0, isPredicate: false, referent: 'policy', reveal: true },
          { entryIndex: 0, isPredicate: true, referent: 'eligible', reveal: true },
          { entryIndex: 0, isPredicate: true, referent: 'valid_until', reveal: true },
        ],
        schemas: { [publicIssuer.schemaId]: publicIssuer.schema },
        credentialDefinitions: { [publicIssuer.credentialDefinitionId]: publicIssuer.credentialDefinition },
        selfAttest: {}, linkSecret,
      }));
    },
  };
}
