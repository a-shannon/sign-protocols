import { vi } from 'vitest';

import { createEncryptionMock } from '../mocked/encryption.mock';
import { DispatchCommunicator } from './testCommunicator';

/** Provides an explicitly released promise for an asynchronous dispatch barrier. */
export const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

/** Builds the actual communicator with isolated encryption and transport collaborators. */
export const fixture = (submit = vi.fn<() => unknown>()) => {
  const signer = createEncryptionMock();
  return {
    signer,
    submit,
    communicator: new DispatchCommunicator(signer, submit),
  };
};
