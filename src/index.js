export { createIssuer } from './issuer.js';
export { createHolder } from './holder.js';
export { createVerifier } from './verifier.js';
export { createMemoryReceiptStore } from './receipts.js';
export { policyDigest, issuanceDigest, encodeAttestation } from './encoding.js';

// New boundaries under test; implemented after the failing CI run.
export { createPasskeyService } from './passkeys.js';
export { createMemoryCredentialStore } from './credential-store.js';
export { createSqliteState } from './sqlite.js';
export function restoreIssuer() { throw new Error('Issuer restoration not implemented'); }
