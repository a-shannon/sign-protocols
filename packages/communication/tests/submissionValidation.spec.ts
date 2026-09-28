import { afterEach, describe, expect, it, vi } from 'vitest';

import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { EdDSA } from '@rosen-bridge/encryption';

import { Communicator } from '../lib';

class SubmissionCommunicator extends Communicator {
  protected readonly protocolVersion = '1.0.0';
  processMessage = vi.fn();
  publish = this.sendMessage;

  constructor(
    signer: EdDSA,
    submit: (message: string, peers: string[]) => unknown,
    keys: string[],
  ) {
    super(new DummyLogger(), signer, submit, keys);
  }

  deferIndex() {
    const entered = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    const original = this.getIndex;
    this.getIndex = async () => {
      entered.resolve();
      await resume.promise;
      return original();
    };
    return { entered, resume };
  }
}

async function fixture() {
  const signer = new EdDSA(await EdDSA.randomKey());
  const submit = vi.fn();
  const communicator = new SubmissionCommunicator(signer, submit, [
    await signer.getPk(),
  ]);
  return { signer, submit, communicator };
}

afterEach(() => vi.restoreAllMocks());

describe('per-message submission validation', () => {
  it('rechecks after the last asynchronous index lookup and preserves the envelope', async () => {
    const { communicator, submit } = await fixture();
    const gate = communicator.deferIndex();
    const beforeSubmit = vi.fn((): undefined => {
      expect(submit).not.toHaveBeenCalled();
    });
    const pending = communicator.publish(
      'current',
      { value: 1 },
      ['peer'],
      1,
      beforeSubmit,
    );
    await gate.entered.promise;
    expect(beforeSubmit).not.toHaveBeenCalled();
    gate.resume.resolve();
    await pending;
    expect(beforeSubmit).toHaveBeenCalledTimes(1);
    expect(submit).toHaveBeenCalledTimes(1);
    expect(JSON.parse(submit.mock.calls[0][0])).toMatchObject({
      type: 'current',
      payload: { value: 1 },
      timestamp: 1,
      index: 0,
      version: '1.0.0',
    });
  });

  it('prevents submission when state changes at the last asynchronous boundary', async () => {
    const { communicator, submit } = await fixture();
    const gate = communicator.deferIndex();
    let current = true;
    const pending = communicator.publish('stale', {}, [], 1, (): undefined => {
      if (!current) throw Error('stale');
    });
    await gate.entered.promise;
    current = false;
    gate.resume.resolve();
    await expect(pending).rejects.toThrow('stale');
    expect(submit).not.toHaveBeenCalled();
  });

  it('keeps concurrent sends bound to their own validator', async () => {
    const { communicator, signer, submit } = await fixture();
    const entered = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    const original = signer.sign.bind(signer);
    vi.spyOn(signer, 'sign').mockImplementationOnce(async (message) => {
      entered.resolve();
      await resume.promise;
      return original(message);
    });
    const pending = communicator.publish('rejected', {}, [], 1, () => {
      throw Error('refused');
    });
    await entered.promise;
    await communicator.publish('accepted', {}, [], 1, () => undefined);
    resume.resolve();
    await expect(pending).rejects.toThrow('refused');
    expect(submit).toHaveBeenCalledTimes(1);
    expect(JSON.parse(submit.mock.calls[0][0]).type).toBe('accepted');
  });

  it('requires the validator type to be synchronous', () => {
    type Validator = NonNullable<
      Parameters<SubmissionCommunicator['publish']>[4]
    >;
    const valid: Validator = () => undefined;
    // @ts-expect-error Async callbacks would leave submission outside the assertion.
    const invalid: Validator = async () => {};
    expect(valid()).toBeUndefined();
    expect(typeof invalid).toBe('function');
  });
});
