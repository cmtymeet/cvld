// Portable byte contract; implementations follow the failing behavior tests.
export function createWallet() { throw new Error('Wallet wrapping not implemented'); }
export function unlockWallet() { throw new Error('Wallet unwrapping not implemented'); }
export function sealLocalState() { throw new Error('Local state encryption not implemented'); }
export function openLocalState() { throw new Error('Local state decryption not implemented'); }
export function registerPasskey() { throw new Error('Browser registration not implemented'); }
export function authenticateWithWallet() { throw new Error('Browser PRF not implemented'); }
