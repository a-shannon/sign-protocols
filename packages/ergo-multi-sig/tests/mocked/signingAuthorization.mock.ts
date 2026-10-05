import { GuardDetection } from '@rosen-bridge/detection';
import { EncryptionHandler } from '@rosen-bridge/encryption';

import { testPubs } from '../testData';

/** Provides the unchanged envelope collaborator for one synthetic guard. */
export const createEncryptionMock = (index: number, envelope: string) =>
  ({
    getPk: async () => testPubs[index],
    sign: async () => envelope,
    verify: async () => true,
  }) as unknown as EncryptionHandler;

/** Lists the unchanged synthetic guard roster and peer identifiers. */
export const createGuardDetectionMock = () =>
  ({
    activeGuards: async () =>
      testPubs.map((publicKey, index) => ({
        publicKey,
        index,
        peerId: String(index),
      })),
  }) as unknown as GuardDetection;
