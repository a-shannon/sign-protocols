import * as wasm from 'ergo-lib-wasm-nodejs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';

import { MessageType, MultiSigHandler, MultiSigUtils } from '../lib/index.js';
import type { ContributionRequest, InitiateSignPayload } from '../lib/types.js';
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

async function fixture(
  index = 0,
  hook: (request: ContributionRequest) => Promise<void> = async () => {},
) {
  vi.setSystemTime(0);
  const messageEnc = new ECDSA(testSecrets[index]);
  const submit = vi.fn();
  const detection = new GuardDetection({
    guardsPublicKey: testPubs,
    messageEnc,
    submit,
    getPeerId: async () => testPubs[index],
  });
  detection.activeGuards = async () =>
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
    secretHex: testSecrets[index],
    txSignTimeout: 60,
    turnTime: 60,
    submit,
    guardDetection: detection,
    commGuardsPk: [...testPubs],
    ergoGuardPks: [...testPubs],
    beforeContribution: hook,
  });
  await TestUtils.addTx(handler, reduced, 6, [...boxes], []);
  const { transaction, release } = await handler.getQueuedTransaction(txId);
  release();
  transaction.reject = vi.fn();
  // Retain the real communicator and signer; only the outbound network sink is inert.
  return { handler, messageEnc, submit, transaction };
}

function gateEnvelopeSigning(messageEnc: ECDSA) {
  const entered = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const original = messageEnc.sign.bind(messageEnc);
  vi.spyOn(messageEnc, 'sign').mockImplementationOnce(async (message) => {
    entered.resolve();
    await resume.promise;
    return original(message);
  });
  return { entered, resume };
}

async function signingGroup(
  hook?: (request: ContributionRequest) => Promise<void>,
) {
  const members = await Promise.all(
    testSecrets.slice(0, 6).map((_, i) => fixture(i, hook)),
  );
  for (const member of members)
    await member.handler.generateCommitment(txId, 0);
  const coordinator = members[0];
  const addCommitment = (i: number) =>
    coordinator.handler.handleCommitment(
      testPubs[i],
      { txId, commitment: members[i].transaction.commitments[testPubs[i]] },
      'already-verified-test-envelope',
      i,
    );
  for (let i = 1; i < members.length - 1; i++) await addCommitment(i);
  coordinator.submit.mockClear();
  return {
    members,
    coordinator,
    finish: () => addCommitment(members.length - 1),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('contribution authorization through the real transport', () => {
  it('completes a six-signer round through signed envelopes with authorization enabled', async () => {
    const hook = vi.fn<(request: ContributionRequest) => Promise<void>>(
      async () => {},
    );
    const members = await Promise.all(
      testSecrets.slice(0, 6).map((_, i) => fixture(i, hook)),
    );
    const messages: Array<{
      message: string;
      peers: string[];
      sender: string;
    }> = [];
    members.forEach((member, i) => {
      member.submit.mockImplementation((message: string, peers: string[]) => {
        messages.push({ message, peers, sender: testPubs[i] });
      });
    });
    const signed = Promise.all(
      members.map(({ handler }) => handler.sign(reduced, 6, [...boxes], [])),
    );
    // Drain an in-memory network through handleMessage, including real envelope
    // verification; no RPC, native operation or authorization method is mocked.
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(messages.length).toBeGreaterThan(0);
    let delivered = 0;
    while (messages.length) {
      if (++delivered > 30) throw Error('unexpected protocol message loop');
      const { message, peers, sender } = messages.shift()!;
      const recipients = peers.length ? peers : testPubs;
      for (let i = 0; i < members.length; i++)
        if (testPubs[i] !== sender && recipients.includes(testPubs[i]))
          await members[i].handler.handleMessage(message, sender);
    }
    const results = await signed;
    expect(results.map((tx) => tx.id().to_str())).toEqual(
      members.map(() => txId),
    );
    expect(hook.mock.calls.map(([request]) => request.kind).sort()).toEqual([
      ...Array<string>(6).fill('commitment'),
      'coordinator-sign',
      ...Array<string>(5).fill('peer-sign'),
    ]);
    for (const member of members)
      expect(await member.handler.isInSign(txId)).toBe(false);
  });

  it('submits a signed commitment when its context remains current', async () => {
    const f = await fixture(1);
    await f.handler.generateCommitment(txId, 0);
    expect(f.submit).toHaveBeenCalledTimes(1);
    const envelope = JSON.parse(f.submit.mock.calls[0][0]);
    expect(envelope.type).toBe(MessageType.Commitment);
    expect(envelope.payload.txId).toBe(txId);
    expect(envelope.sign).toBeTruthy();
  });

  it('rejects a commitment when the committee changes during envelope signing', async () => {
    const f = await fixture(1);
    const gate = gateEnvelopeSigning(f.messageEnc);
    const pending = f.handler.generateCommitment(txId, 0);
    await gate.entered.promise;
    f.handler.handlePublicKeysChange([...testPubs].reverse());
    gate.resume.resolve();
    await expect(pending).rejects.toThrow('Contribution state changed');
    expect(f.submit).not.toHaveBeenCalled();
    expect(f.transaction.reject).toHaveBeenCalled();
  });

  it('rejects a coordinator request when its turn expires during envelope signing', async () => {
    const f = await fixture(0);
    const gate = gateEnvelopeSigning(f.messageEnc);
    const pending = f.handler.handleMyTurn();
    await gate.entered.promise;
    vi.setSystemTime(60000);
    gate.resume.resolve();
    await expect(pending).rejects.toThrow('Contribution state changed');
    expect(f.submit).not.toHaveBeenCalled();
    expect(f.transaction.reject).toHaveBeenCalled();
  });

  it('rejects initiation when the committee changes during envelope signing', async () => {
    const group = await signingGroup();
    const gate = gateEnvelopeSigning(group.coordinator.messageEnc);
    const pending = group.finish();
    await gate.entered.promise;
    group.coordinator.handler.handlePublicKeysChange([...testPubs].reverse());
    gate.resume.resolve();
    await pending;
    expect(group.coordinator.submit).not.toHaveBeenCalled();
    expect(group.coordinator.transaction.reject).toHaveBeenCalled();
  });

  it('submits a peer proof when its context remains current', async () => {
    const group = await signingGroup();
    await group.finish();
    const initiation = JSON.parse(group.coordinator.submit.mock.calls[0][0]);
    expect(initiation.type).toBe(MessageType.InitiateSign);
    const peer = group.members[1];
    peer.submit.mockClear();
    await peer.handler.initiateSign(testPubs[0], initiation.payload, 0);
    expect(peer.submit).toHaveBeenCalledTimes(1);
    expect(JSON.parse(peer.submit.mock.calls[0][0]).type).toBe(
      MessageType.Sign,
    );
  });

  it('rejects a prepared peer proof after another authorization fails during envelope signing', async () => {
    let valid = true;
    const group = await signingGroup(async () => {
      if (!valid) throw Error('source authorization revoked');
    });
    await group.finish();
    const initiation = JSON.parse(group.coordinator.submit.mock.calls[0][0]);
    expect(initiation.type).toBe(MessageType.InitiateSign);
    const peer = group.members[1];
    peer.submit.mockClear();
    const gate = gateEnvelopeSigning(peer.messageEnc);
    const pending = peer.handler.initiateSign(
      testPubs[0],
      initiation.payload as InitiateSignPayload,
      0,
    );
    await gate.entered.promise;
    valid = false;
    await expect(peer.handler.generateCommitment(txId, 0)).rejects.toThrow(
      'source authorization revoked',
    );
    expect(peer.transaction.reject).toHaveBeenCalled();
    gate.resume.resolve();
    await pending;
    expect(peer.submit).not.toHaveBeenCalled();
  });
});
