import { vi } from 'vitest';

import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { EncryptionHandler } from '@rosen-bridge/encryption';

import { Communicator } from '../../lib';

/** Exposes protected production methods without replacing their behavior. */
export class TestCommunicator extends Communicator {
  protected readonly protocolVersion = '1.0.0';

  /** Connects a signer, peer keys and submission observer to the actual communicator. */
  constructor(
    signer: EncryptionHandler,
    submitMessage: (msg: string, peers: Array<string>) => unknown,
    guardPks: Array<string>,
  ) {
    super(new DummyLogger(), signer, submitMessage, guardPks);
  }

  /** Delegates the supplied envelope and destination peers to the actual send method. */
  testSendMessage = (
    messageType: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    payload: any,
    peers: Array<string>,
  ) => {
    return this.sendMessage(messageType, payload, peers);
  };

  processMessage = vi.fn();

  /** Resolves the actual configured guard index. */
  mockedGetIndex = async () => await this.getIndex();

  /** Returns the actual communicator clock rounded to seconds. */
  mockedGetDate = () => this.getDate();
}

/** Authorization gate accepted by the actual send method. */
type Gate = (submit: () => void) => Promise<void>;

/** Exposes the actual final-dispatch path with a synthetic signer and transport. */
export class DispatchCommunicator extends Communicator {
  protected readonly protocolVersion = '1.0.0';
  processMessage = vi.fn();
  /** Connects the production communicator to the supplied test collaborators. */
  constructor(
    signer: EncryptionHandler,
    submit: (message: string, peers: string[]) => unknown,
  ) {
    super(new DummyLogger(), signer, submit, ['fixture-key']);
  }
  /** Sends the unchanged fixture envelope through the production authorization gate. */
  send = (gate?: Gate) =>
    this.sendMessage('proof', { txId: 'fixture' }, ['peer'], 1, gate);
}
