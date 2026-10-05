import { vi } from 'vitest';

import { EncryptionHandler } from '@rosen-bridge/encryption';

/** Returns the synthetic envelope-signing collaborator used by dispatch controls. */
export const createEncryptionMock = (): EncryptionHandler => {
  return {
    getPk: vi.fn(async () => 'fixture-key'),
    sign: vi.fn(async () => 'fixture-envelope-signature'),
    verify: vi.fn(async () => true),
    getCrypto: () => 'fixture',
  };
};
