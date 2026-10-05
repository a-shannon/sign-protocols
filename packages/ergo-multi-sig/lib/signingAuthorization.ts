import { performance } from 'node:perf_hooks';

import {
  BoundSigningAuthorization,
  SigningAuthorizationConfig,
  SigningIdentity,
  SigningPhase,
} from './types';

/** One local attempt; an expired callback can never authorize its replacement. */
export class SigningAttempt {
  private readonly deadline: number;
  private readonly timer: ReturnType<typeof setTimeout>;
  private closed = false;
  private readonly stopped = new AbortController();
  private bound?: BoundSigningAuthorization;

  /** Captures attempt ownership and starts the bounded expiration timer. */
  constructor(
    readonly identity: SigningIdentity,
    timeoutMs: number,
    private readonly isCurrent: () => boolean,
    private readonly onClose: (error: unknown) => void,
  ) {
    this.deadline = performance.now() + timeoutMs;
    this.timer = setTimeout(
      () => this.close(new Error('Signing authorization expired')),
      timeoutMs,
    );
  }

  /** Rejects an expired, closed or replaced signing attempt. */
  assertActive = (): void => {
    if (this.closed || !this.isCurrent() || performance.now() >= this.deadline)
      throw new Error('Signing authorization expired or replaced');
  };

  /** Captures the configured binding only while the attempt remains current. */
  bind = async (config: SigningAuthorizationConfig): Promise<void> => {
    this.assertActive();
    const bound = await config.bind(this.identity);
    this.assertActive();
    if (!bound || typeof bound.withAction !== 'function')
      throw new Error('Signing authorization binding is unavailable');
    this.bound = Object.freeze({ withAction: bound.withAction.bind(bound) });
  };

  /** Invokes one authorized phase action and races completion against attempt revocation. */
  run = async <T>(
    phase: SigningPhase,
    action: () => T | Promise<T>,
  ): Promise<T> => {
    this.assertActive();
    if (!this.bound) throw new Error('Signing authorization is not bound');
    let invoked = false;
    let open = true;
    try {
      const work = this.bound.withAction(phase, () => {
        this.assertActive();
        if (!open || invoked)
          throw new Error('Signing action is no longer available');
        invoked = true;
        return action();
      });
      const result = await new Promise<T>((resolve, reject) => {
        /** Rejects phase completion when the signing attempt is aborted. */
        const stop = () =>
          reject(new Error('Signing authorization expired or replaced'));
        this.stopped.signal.addEventListener('abort', stop, { once: true });
        Promise.resolve(work)
          .then(resolve, reject)
          .finally(() => {
            this.stopped.signal.removeEventListener('abort', stop);
          });
        if (this.stopped.signal.aborted) stop();
      });
      this.assertActive();
      if (!invoked) throw new Error('Signing action was not authorized');
      return result;
    } catch (error) {
      this.close(error);
      throw error;
    } finally {
      open = false;
    }
  };

  /** Closes the attempt once, aborts pending work and notifies its owner. */
  close = (error: unknown): void => {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.timer);
    this.stopped.abort();
    this.onClose(error);
  };
}

/** Validates timeout, pending-capacity and binder requirements. */
export const validateSigningAuthorization = (
  config: SigningAuthorizationConfig,
): void => {
  if (
    !Number.isSafeInteger(config.timeoutMs) ||
    config.timeoutMs < 1 ||
    config.timeoutMs > 2147483647 ||
    !Number.isSafeInteger(config.maxPending) ||
    config.maxPending < 1 ||
    config.maxPending > 1024 ||
    typeof config.bind !== 'function'
  )
    throw new Error('Invalid signing authorization bounds');
};
