export { createIssuer } from './issuer.js';
export { createHolder } from './holder.js';
export { createVerifier } from './verifier.js';
export { createMemoryReceiptStore } from './receipts.js';
export { policyDigest, issuanceDigest, encodeAttestation } from './encoding.js';

// New boundaries under test; implemented after the failing CI run.
export function createPasskeyService() { throw new Error('Enrollment not implemented'); }
export function createMemoryCredentialStore() { throw new Error('Credential storage not implemented'); }
export function createSqliteState() { throw new Error('Durable state not implemented'); }
export function restoreIssuer() { throw new Error('Issuer restoration not implemented'); }
