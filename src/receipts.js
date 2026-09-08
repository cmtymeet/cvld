import { requirePositive } from './encoding.js';

// For experiments only. A deployed issuer must inject durable, atomic storage.
export function createMemoryReceiptStore({ maxEntries }) {
  requirePositive(maxEntries, 'receipt capacity');
  const entries = new Map();
  return {
    async claimAll(ids, validUntil, now) {
      for (const [id, expiry] of entries) if (expiry <= now) entries.delete(id);
      if (new Set(ids).size !== ids.length || ids.some((id) => entries.has(id)) || entries.size + ids.length > maxEntries) return false;
      for (const id of ids) entries.set(id, validUntil);
      return true;
    },
  };
}
