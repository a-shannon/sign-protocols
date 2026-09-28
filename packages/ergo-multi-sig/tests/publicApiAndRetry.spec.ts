import * as wasm from 'ergo-lib-wasm-nodejs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';

import { MultiSigHandler, MultiSigUtils } from '../lib';
import {
  boxJs,
  mockedErgoStateContext,
  testPubs,
  testSecrets,
} from './testData';
import TestUtils from './testUtils/testUtils';
import {
  getChangeBoxJs,
  getOutBoxJs,
  jsToReducedTx,
} from './testUtils/txUtils';

const tree =
  '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';
const out = getOutBoxJs(tree, ['ERG', 10000000]);
const reduced = jsToReducedTx(
  [boxJs],
  [out, getChangeBoxJs([boxJs], [out], tree, 1000000)],
  [],
  1311604,
  1000000,
);
const boxes = [wasm.ErgoBox.from_json(JSON.stringify(boxJs))];
const txId = reduced.unsigned_tx().id().to_str();

async function fixture(beforeContribution?: () => Promise<void>) {
  vi.setSystemTime(0);
  const messageEnc = new ECDSA(testSecrets[0]);
  const submit = vi.fn();
  const guardDetection = new GuardDetection({
    guardsPublicKey: testPubs,
    messageEnc,
    submit,
    getPeerId: async () => testPubs[0],
  });
  guardDetection.activeGuards = async () =>
    testPubs.map((publicKey, index) => ({
      publicKey,
      peerId: publicKey,
      index,
    }));
  const handler = new MultiSigHandler({
    multiSigUtilsInstance: new MultiSigUtils(
      async () => mockedErgoStateContext,
    ),
    messageEnc,
    secretHex: testSecrets[0],
    txSignTimeout: 60,
    submit,
    guardDetection,
    commGuardsPk: [...testPubs],
    ergoGuardPks: [...testPubs],
    beforeContribution,
  });
  await TestUtils.addTx(handler, reduced, 6, [...boxes], []);
  const { transaction, release } = await handler.getQueuedTransaction(txId);
  release();
  transaction.resolve = vi.fn();
  transaction.reject = vi.fn();
  return { handler, transaction };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('public completion API and refused signing retries', () => {
  it('retains the public Promise<void> completion callback contract', async () => {
    const { handler } = await fixture();
    // This assignment is checked by the package type-check, not just Vitest.
    const callback: (bytes: string) => Promise<void> = handler.handleSignedTx;
    await expect(callback('invalid transaction')).resolves.toBeUndefined();
  });

  it.each([0, 1])(
    'rejects a new sign call on a refused entry without replacing retained state (coordinator %s)',
    async (coordinator) => {
      let authorized = true;
      const hook = vi.fn(async () => {
        if (!authorized) throw Error('source invalid');
      });
      const { handler, transaction } = await fixture(hook);
      await handler.generateCommitment(txId, coordinator);
      expect(transaction.secret).toBeDefined();
      authorized = false;
      await expect(
        handler.generateCommitment(txId, coordinator),
      ).rejects.toThrow('source invalid');
      const retained = { ...transaction };
      const hookCalls = hook.mock.calls.length;
      const retry = handler.sign(reduced, 5, [...boxes], []);
      let timeout: ReturnType<typeof setTimeout> | undefined;
      try {
        const outcome = await Promise.race([
          retry.then(
            () => 'resolved',
            (error: unknown) => error,
          ),
          new Promise<string>((resolve) => {
            timeout = setTimeout(() => resolve('still pending'), 100);
          }),
        ]);
        expect(outcome).toBeInstanceOf(Error);
        expect((outcome as Error).message).toBe('Contribution state changed');
      } finally {
        clearTimeout(timeout);
      }
      for (const key of Object.keys(retained) as Array<keyof typeof retained>)
        expect(transaction[key]).toBe(retained[key]);
      expect(hook).toHaveBeenCalledTimes(hookCalls);
      expect(await handler.isInSign(txId)).toBe(true);
    },
  );
});
