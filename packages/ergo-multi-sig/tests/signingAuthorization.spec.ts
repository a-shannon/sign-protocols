import {
  MultiSigHandler,
  MultiSigUtils,
  SigningAuthorizationConfig,
  SigningIdentity,
  SigningPhase,
} from '../lib';
import {
  createEncryptionMock,
  createGuardDetectionMock,
} from './mocked/signingAuthorization.mock';
import { mockedErgoStateContext, testPubs, testSecrets } from './testData';
import {
  identityFields,
  outboundTypes,
  invalidTimeouts,
} from './testData/signingAuthorization';
import { fixture, signedBytes, tick } from './testUtils/signingAuthorization';
import TestUtils from './testUtils/testUtils';

let held: boolean;
let identities: SigningIdentity[];
let phases: SigningPhase[];
let policy: SigningAuthorizationConfig;
let handler: MultiSigHandler;
let utils: MultiSigUtils;
let f: ReturnType<typeof fixture>;
let submit: ReturnType<typeof vi.fn>;
const outcomes: Promise<unknown>[] = [];
/** Queues the real fixture and observes its settlement for deterministic cleanup. */
const queue = () => {
  const promise = handler.sign(f.reduced, 6, f.boxes, []);
  outcomes.push(promise.catch(() => undefined));
  return promise;
};
/** Constructs a real handler with the current isolated collaborators and policy. */
const make = (authorization = policy) => {
  const instance = new MultiSigHandler({
    multiSigUtilsInstance: utils,
    messageEnc: createEncryptionMock(0, 'envelope'),
    secretHex: testSecrets[0],
    txSignTimeout: 1,
    submit,
    guardDetection: createGuardDetectionMock(),
    commGuardsPk: [...testPubs],
    ergoGuardPks: [...testPubs],
    signingAuthorization: authorization,
  });
  vi.spyOn(instance, 'isMyTurn').mockResolvedValue(false);
  vi.spyOn(instance, 'getCurrentTurnInd').mockReturnValue(0);
  return instance;
};
beforeEach(() => {
  held = false;
  identities = [];
  phases = [];
  submit = vi.fn();
  f = fixture();
  utils = new MultiSigUtils(async () => mockedErgoStateContext);
  policy = {
    timeoutMs: 1000,
    maxPending: 2,
    bind: async (identity) => {
      identities.push(identity);
      return {
        withAction: async (phase, action) => {
          phases.push(phase);
          if (held) throw new Error('source held');
          return action();
        },
      };
    },
  };
  handler = make();
});
afterEach(async () => {
  for (const attempt of handler['attempts'].values())
    attempt.close(new Error('test cleanup'));
  await Promise.all(outcomes.splice(0));
  vi.restoreAllMocks();
});

describe('SigningAttempt', () => {
  describe('run', () => {
    /**
     * @target SigningAttempt.run binds immutable complete identity and owns independent WASM copies
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Queue the actual reduced transaction, inspect frozen identity and independent copies, then free caller-owned WASM inputs
     * @expected
     * - Binds immutable complete identity and owns independent WASM copies
     */
    it('binds immutable complete identity and owns independent WASM copies', async () => {
      queue();
      await tick();
      const { transaction, release } = await handler.getQueuedTransaction(f.id);
      release();
      expect(transaction.tx).not.toBe(f.reduced);
      expect(transaction.boxes[0]).not.toBe(f.boxes[0]);
      expect(identities[0]).toEqual({
        txId: f.id,
        reducedTxBytes: Buffer.from(f.reduced.sigma_serialize_bytes()).toString(
          'hex',
        ),
        inputBoxBytes: [
          Buffer.from(f.boxes[0].sigma_serialize_bytes()).toString('hex'),
        ],
        dataInputBoxBytes: [],
        publicKey: testPubs[0],
        requiredSign: 6,
        guardPublicKeys: testPubs,
      });
      expect(Object.isFrozen(identities[0])).toEqual(true);
      expect(Object.isFrozen(identities[0].inputBoxBytes)).toEqual(true);
      expect(Object.isFrozen(identities[0].guardPublicKeys)).toEqual(true);
      f.reduced.free();
      f.boxes[0].free();
      await handler.generateCommitment(f.id);
      expect(transaction.secret).toBeDefined();
      expect(phases).toEqual(['queue', 'commitment']);
    });

    /**
     * @target SigningAttempt.run denies queue admission and settles the caller
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Hold the source before queue admission
     * @expected
     * - Denies queue admission and settles the caller
     */
    it('denies queue admission and settles the caller', async () => {
      held = true;
      await expect(queue()).rejects.toThrow('held');
      expect(await handler.isInSign(f.id)).toEqual(false);
      expect(handler['attempts'].size).toEqual(0);
    });

    /**
     * @target SigningAttempt.run denies the actual commitment sink after queue admission
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Admit the queue, hold the source and spy on the wallet prover before generating a commitment
     * @expected
     * - Denies the actual commitment sink after queue admission
     */
    it('denies the actual commitment sink after queue admission', async () => {
      const result = queue();
      await tick();
      held = true;
      const prover = vi.spyOn(handler, 'getProver' as never);
      await expect(handler.generateCommitment(f.id)).rejects.toThrow('held');
      expect(prover).not.toHaveBeenCalled();
      await expect(result).rejects.toThrow('held');
    });

    /**
     * @target SigningAttempt.run does not authorize a peer-created placeholder
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Insert a peer-created queue placeholder and attempt commitment generation
     * @expected
     * - Does not authorize a peer-created placeholder
     */
    it('does not authorize a peer-created placeholder', async () => {
      await TestUtils.addTx(handler, f.reduced, 6, f.boxes, []);
      const prover = vi.spyOn(handler, 'getProver' as never);
      await expect(handler.generateCommitment(f.id)).rejects.toThrow(
        'No local signing',
      );
      expect(prover).not.toHaveBeenCalled();
      expect(identities).toHaveLength(0);
    });

    /**
     * @target SigningAttempt.run rejects duplicate local attempts without replacing callbacks
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Queue a local attempt, submit the same transaction again and compare the retained transaction object
     * @expected
     * - Rejects duplicate local attempts without replacing callbacks
     */
    it('rejects duplicate local attempts without replacing callbacks', async () => {
      queue();
      await tick();
      const { transaction, release } = await handler.getQueuedTransaction(f.id);
      release();
      await expect(handler.sign(f.reduced, 6, f.boxes)).rejects.toThrow(
        'already active',
      );
      const current = await handler.getQueuedTransaction(f.id);
      current.release();
      expect(current.transaction).toBe(transaction);
      expect(identities).toHaveLength(1);
    });

    /**
     * @target SigningAttempt.run rejects stale waiters instead of adopting a newly authorized queue
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Hold a placeholder semaphore, queue a new attempt and release the stale waiter
     * @expected
     * - Rejects stale waiters instead of adopting a newly authorized queue
     */
    it('rejects stale waiters instead of adopting a newly authorized queue', async () => {
      const placeholder = await handler.getQueuedTransaction(f.id);
      queue();
      await tick();
      const stale = handler.getQueuedTransaction(f.id);
      placeholder.release();
      await expect(stale).rejects.toThrow('queue changed');
      const current = await handler.getQueuedTransaction(f.id);
      current.release();
      expect(current.transaction).not.toBe(placeholder.transaction);
    });

    /**
     * @target SigningAttempt.run expires while binding is stalled and refuses late queue mutation after retry
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Pause the policy binder until expiry, release it and queue a replacement attempt
     * @expected
     * - Expires while binding is stalled and refuses late queue mutation after retry
     */
    it('expires while binding is stalled and refuses late queue mutation after retry', async () => {
      let release!: () => void;
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      const bind = policy.bind;
      policy.bind = async (identity) => {
        await barrier;
        return bind(identity);
      };
      policy.timeoutMs = 20;
      handler = make();
      await expect(queue()).rejects.toThrow('expired');
      expect(await handler.isInSign(f.id)).toEqual(false);
      release();
      await tick();
      expect(await handler.isInSign(f.id)).toEqual(false);
      queue();
      await tick();
      expect(await handler.isInSign(f.id)).toEqual(true);
    });

    /**
     * @target SigningAttempt.run releases the queue semaphore when admission policy stalls past expiry
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Pause the first admission action until expiry, queue a replacement and resume the old action
     * @expected
     * - Releases the queue semaphore when admission policy stalls past expiry
     */
    it('releases the queue semaphore when admission policy stalls past expiry', async () => {
      let release!: () => void;
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      let first = true;
      policy.timeoutMs = 100;
      policy.bind = async () => ({
        withAction: async (phase, action) => {
          if (phase === 'queue' && first) {
            first = false;
            await barrier;
          }
          return action();
        },
      });
      handler = make();
      await expect(queue()).rejects.toThrow('expired');
      queue();
      await tick();
      const replacement = await handler.getQueuedTransaction(f.id);
      replacement.release();
      expect(replacement.transaction.tx).toBeDefined();
      release();
      await tick();
      const current = await handler.getQueuedTransaction(f.id);
      current.release();
      expect(current.transaction).toBe(replacement.transaction);
    });

    /**
     * @target SigningAttempt.run refuses a deferred commitment action after its attempt expires
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Pause the commitment policy action until expiry, then resume it while observing the prover sink
     * @expected
     * - Refuses a deferred commitment action after its attempt expires
     */
    it('refuses a deferred commitment action after its attempt expires', async () => {
      let release!: () => void;
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      policy.timeoutMs = 25;
      policy.bind = async () => ({
        withAction: async (phase, action) => {
          if (phase === 'commitment') await barrier;
          return action();
        },
      });
      handler = make();
      const result = queue();
      await tick();
      const prover = vi.spyOn(handler, 'getProver' as never);
      const committing = handler.generateCommitment(f.id);
      outcomes.push(committing.catch(() => undefined));
      await expect(result).rejects.toThrow('expired');
      release();
      await expect(committing).rejects.toThrow('expired');
      expect(prover).not.toHaveBeenCalled();
    });

    /**
     * @target SigningAttempt.run rejects changed %s before wallet invocation
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Mutate only the selected identity field after admission and attempt commitment generation
     * @expected
     * - Rejects changed %s before wallet invocation
     */
    it.each(identityFields)(
      'rejects changed %s before wallet invocation',
      async (field) => {
        queue();
        await tick();
        const { transaction, release } = await handler.getQueuedTransaction(
          f.id,
        );
        release();
        if (field === 'requiredSigner') transaction.requiredSigner = 1;
        if (field === 'boxes') transaction.boxes = [];
        if (field === 'tx') transaction.tx = fixture(10000001).reduced;
        if (field === 'dataBoxes') transaction.dataBoxes = [f.boxes[0]];
        if (field === 'publicKey')
          vi.spyOn(handler, 'getPk').mockReturnValue(testPubs[1]);
        if (field === 'peers')
          handler.handlePublicKeysChange([...testPubs].reverse());
        const prover = vi.spyOn(handler, 'getProver' as never);
        await expect(handler.generateCommitment(f.id)).rejects.toThrow(
          'identity changed',
        );
        expect(prover).not.toHaveBeenCalled();
      },
    );

    /**
     * @target SigningAttempt.run denies participant signing after acquiring the queue semaphore
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Start participant signing behind the held queue semaphore, revoke admission and release the semaphore
     * @expected
     * - Denies participant signing after acquiring the queue semaphore
     */
    it('denies participant signing after acquiring the queue semaphore', async () => {
      const result = queue();
      await tick();
      await handler.generateCommitment(f.id);
      const queued = await handler.getQueuedTransaction(f.id);
      const commitment = queued.transaction.commitments[testPubs[0]];
      const prover = vi.spyOn(handler, 'getProver' as never);
      const signing = handler.initiateSign(
        '0',
        {
          txId: f.id,
          committedInds: [0],
          cmts: [commitment],
          simulated: [],
          simulatedProofs: [],
        },
        0,
      );
      held = true;
      queued.release();
      await signing;
      expect(phases).toContain('sign');
      expect(prover).not.toHaveBeenCalled();
      await expect(result).rejects.toThrow('held');
    });

    /**
     * @target SigningAttempt.run denies coordinator signing after the asynchronous simulated hint extraction
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Generate actual commitments and revoke admission immediately after asynchronous hint extraction
     * @expected
     * - Denies coordinator signing after the asynchronous simulated hint extraction
     */
    it('denies coordinator signing after the asynchronous simulated hint extraction', async () => {
      const result = queue();
      await tick();
      await handler.generateCommitment(f.id);
      const queued = await handler.getQueuedTransaction(f.id);
      queued.release();
      const commitments = [queued.transaction.commitments[testPubs[0]]];
      for (let index = 1; index < 6; index++) {
        const other = await TestUtils.generateMultiSigHandlerInstance(
          testSecrets[index],
          vi.fn(),
          testPubs,
        );
        await TestUtils.addTx(other, f.reduced, 6, f.boxes, []);
        await other.generateCommitment(f.id);
        const item = await other.getQueuedTransaction(f.id);
        commitments.push(item.transaction.commitments[testPubs[index]]);
        item.release();
      }
      queued.transaction.coordinator = 0;
      for (let index = 1; index < 5; index++)
        queued.transaction.commitments[testPubs[index]] = commitments[index];
      const extract = utils.extract_hints;
      const extracted = vi
        .spyOn(utils, 'extract_hints')
        .mockImplementation(async (...args) => {
          const hints = await extract(...args);
          held = true;
          return hints;
        });
      const prover = vi.spyOn(handler, 'getProver' as never);
      await handler.handleCommitment(
        '5',
        { txId: f.id, commitment: commitments[5] },
        'signature',
        5,
      );
      expect(extracted).toHaveBeenCalledOnce();
      expect(phases).toContain('sign');
      expect(prover).not.toHaveBeenCalled();
      await expect(result).rejects.toThrow('held');
    });

    /**
     * @target SigningAttempt.run gates final %s transport after asynchronous envelope signing
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Revoke admission during envelope signing for the selected protocol message
     * @expected
     * - Gates final %s transport after asynchronous envelope signing
     */
    it.each(outboundTypes)(
      'gates final %s transport after asynchronous envelope signing',
      async (type) => {
        const result = queue();
        await tick();
        const queued = await handler.getQueuedTransaction(f.id);
        queued.release();
        handler['messageEnc'].sign = async () => {
          held = true;
          return 'signed-envelope';
        };
        await expect(
          handler['sendMessage'](
            type,
            { txId: f.id },
            ['peer'],
            1,
            ...handler['finalDispatch'](queued.transaction),
          ),
        ).rejects.toThrow('held');
        expect(submit).not.toHaveBeenCalled();
        await expect(result).rejects.toThrow('held');
      },
    );

    /**
     * @target SigningAttempt.run actual commitment send is denied when hold arises after wallet work
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Admit commitment work, then revoke admission while its outgoing envelope is signed
     * @expected
     * - Actual commitment send is denied when hold arises after wallet work
     */
    it('actual commitment send is denied when hold arises after wallet work', async () => {
      const result = queue();
      await tick();
      handler['messageEnc'].sign = async () => {
        held = true;
        return 'signed-envelope';
      };
      await expect(handler.generateCommitment(f.id, 1)).rejects.toThrow('held');
      expect(phases).toContain('commitment');
      expect(phases).toContain('outbound');
      expect(submit).not.toHaveBeenCalled();
      await expect(result).rejects.toThrow('held');
    });

    /**
     * @target SigningAttempt.run releases authorization before waiting for transport completion
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Keep transport pending and inspect the policy lease both inside submission and afterward
     * @expected
     * - Releases authorization before waiting for transport completion
     */
    it('releases authorization before waiting for transport completion', async () => {
      let leased = false;
      let complete!: () => void;
      const pendingTransport = new Promise<void>((resolve) => {
        complete = resolve;
      });
      policy.bind = async () => ({
        withAction: async (_phase, action) => {
          leased = true;
          try {
            return await action();
          } finally {
            leased = false;
          }
        },
      });
      handler = make();
      queue();
      await tick();
      const queued = await handler.getQueuedTransaction(f.id);
      queued.release();
      submit.mockImplementation(() => {
        expect(leased).toEqual(true);
        return pendingTransport;
      });
      const sending = handler['sendMessage'](
        'approve',
        { txId: f.id },
        ['peer'],
        1,
        ...handler['finalDispatch'](queued.transaction),
      );
      await tick();
      expect(submit).toHaveBeenCalledOnce();
      expect(leased).toEqual(false);
      complete();
      await sending;
    });

    /**
     * @target SigningAttempt.run freshly authorizes result consumption after asynchronous input verification
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Return valid input verification while revoking admission before result consumption
     * @expected
     * - Freshly authorizes result consumption after asynchronous input verification
     */
    it('freshly authorizes result consumption after asynchronous input verification', async () => {
      const result = queue();
      await tick();
      vi.spyOn(utils, 'verifyInput').mockImplementation(async () => {
        held = true;
        return true;
      });
      await handler.handleSignedTx(signedBytes(f.reduced));
      await expect(result).rejects.toThrow('held');
      expect(phases).toContain('result');
      expect(await handler.isInSign(f.id)).toEqual(false);
    });

    /**
     * @target SigningAttempt.run allows exact completed transaction broadcast after queue removal and lease release
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Consume the exact signed fixture, send those bytes after queue removal and reject changed completed bytes
     * @expected
     * - Allows exact completed transaction broadcast after queue removal and lease release
     */
    it('allows exact completed transaction broadcast after queue removal and lease release', async () => {
      let leased = false;
      policy.bind = async () => ({
        withAction: async (_phase, action) => {
          leased = true;
          try {
            return await action();
          } finally {
            leased = false;
          }
        },
      });
      handler = make();
      const result = queue();
      await tick();
      const queued = await handler.getQueuedTransaction(f.id);
      queued.release();
      const bytes = signedBytes(f.reduced);
      vi.spyOn(utils, 'verifyInput').mockResolvedValue(true);
      const received = result.then((tx) => {
        expect(leased).toEqual(false);
        return tx;
      });
      await handler.handleSignedTx(bytes);
      expect((await received).id().to_str()).toEqual(f.id);
      expect(await handler.isInSign(f.id)).toEqual(false);
      await handler['sendMessage'](
        'signedTx',
        { txBytes: bytes },
        ['peer'],
        1,
        ...handler['finalDispatch'](queued.transaction, bytes),
      );
      expect(submit).toHaveBeenCalledOnce();
      await expect(
        handler['sendMessage'](
          'signedTx',
          { txBytes: 'different' },
          ['peer'],
          1,
          ...handler['finalDispatch'](queued.transaction, 'different'),
        ),
      ).rejects.toThrow('identity changed');
      expect(submit).toHaveBeenCalledOnce();
    });

    /**
     * @target SigningAttempt.run rejects old final dispatch after expiry and a same-id replacement
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Capture an old dispatch gate, expire its attempt, admit a replacement and invoke the old gate
     * @expected
     * - Rejects old final dispatch after expiry and a same-id replacement
     */
    it('rejects old final dispatch after expiry and a same-id replacement', async () => {
      policy.timeoutMs = 25;
      handler = make();
      const first = queue();
      await tick();
      const old = await handler.getQueuedTransaction(f.id);
      old.release();
      const oldGate = handler['finalDispatch'](old.transaction);
      await expect(first).rejects.toThrow('expired');
      queue();
      await tick();
      await expect(
        handler['sendMessage'](
          'commitment',
          { txId: f.id },
          ['peer'],
          1,
          ...oldGate,
        ),
      ).rejects.toThrow('expired');
      expect(submit).not.toHaveBeenCalled();
      expect(await handler.isInSign(f.id)).toEqual(true);
    });

    /**
     * @target SigningAttempt.run rejects exact completed transaction broadcast after its deadline
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Complete the exact signed fixture, wait beyond its deadline and try to broadcast its bytes
     * @expected
     * - Rejects exact completed transaction broadcast after its deadline
     */
    it('rejects exact completed transaction broadcast after its deadline', async () => {
      policy.timeoutMs = 30;
      handler = make();
      const result = queue();
      await tick();
      const queued = await handler.getQueuedTransaction(f.id);
      queued.release();
      const bytes = signedBytes(f.reduced);
      vi.spyOn(utils, 'verifyInput').mockResolvedValue(true);
      await handler.handleSignedTx(bytes);
      expect((await result).id().to_str()).toEqual(f.id);
      expect(await handler.isInSign(f.id)).toEqual(false);
      await new Promise((resolve) => setTimeout(resolve, 40));
      await expect(
        handler['sendMessage'](
          'signedTx',
          { txBytes: bytes },
          ['peer'],
          1,
          ...handler['finalDispatch'](queued.transaction, bytes),
        ),
      ).rejects.toThrow('expired');
      expect(submit).not.toHaveBeenCalled();
      expect(handler['attempts'].size).toEqual(0);
    });

    /**
     * @target SigningAttempt.run does not let delayed result verification delete a replacement attempt
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Pause old result verification until expiry, queue a replacement and resume the old verification
     * @expected
     * - Does not let delayed result verification delete a replacement attempt
     */
    it('does not let delayed result verification delete a replacement attempt', async () => {
      policy.timeoutMs = 25;
      handler = make();
      const first = queue();
      await tick();
      let release!: () => void;
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      vi.spyOn(utils, 'verifyInput').mockImplementation(async () => {
        await barrier;
        return true;
      });
      const finishing = handler.handleSignedTx(signedBytes(f.reduced));
      await expect(first).rejects.toThrow('expired');
      queue();
      release();
      await finishing;
      await tick();
      expect(await handler.isInSign(f.id)).toEqual(true);
    });

    /**
     * @target SigningAttempt.run completes a real fixture protocol with all five sends freshly authorized
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Relay real messages among all synthetic guard handlers and complete actual commitments, proofs and results
     * @expected
     * - Completes a real fixture protocol with all five sends freshly authorized
     */
    it('completes a real fixture protocol with all five sends freshly authorized', async () => {
      const peers: MultiSigHandler[] = [];
      const messages: string[] = [];
      const relays: Promise<unknown>[] = [];
      const counts: Record<string, number> = {};
      const relay = (encoded: string, destinations: string[]) => {
        const message = JSON.parse(encoded);
        messages.push(message.type);
        const work = Promise.all(
          destinations.map((destination) =>
            peers[Number(destination)].processMessage(
              message.type,
              message.payload,
              message.sign,
              message.index,
              String(message.index),
              message.timestamp,
            ),
          ),
        );
        relays.push(work.catch(() => undefined));
        return work;
      };
      try {
        for (let index = 0; index < testSecrets.length; index++) {
          const peer = new MultiSigHandler({
            multiSigUtilsInstance: new MultiSigUtils(
              async () => mockedErgoStateContext,
            ),
            messageEnc: createEncryptionMock(index, 'fixture'),
            secretHex: testSecrets[index],
            txSignTimeout: 2,
            submit: relay,
            guardDetection: createGuardDetectionMock(),
            commGuardsPk: [...testPubs],
            ergoGuardPks: [...testPubs],
            signingAuthorization: {
              timeoutMs: 2000,
              maxPending: 2,
              bind: async () => ({
                withAction: async (phase, action) => {
                  counts[phase] = (counts[phase] ?? 0) + 1;
                  return action();
                },
              }),
            },
          });
          vi.spyOn(peer, 'isMyTurn').mockResolvedValue(false);
          vi.spyOn(peer, 'getCurrentTurnInd').mockReturnValue(0);
          peers.push(peer);
        }
        const results = peers.map((peer) => peer.sign(f.reduced, 6, f.boxes));
        outcomes.push(
          ...results.map((result) => result.catch(() => undefined)),
        );
        await tick();
        vi.mocked(peers[0].isMyTurn).mockResolvedValue(true);
        await peers[0].handleMyTurnForTx(f.id);
        const signed = await Promise.all(results);
        expect(signed.every((tx) => tx.id().to_str() === f.id)).toEqual(true);
        expect(new Set(messages)).toEqual(
          new Set([
            'generateCommitment',
            'commitment',
            'initiateSign',
            'sign',
            'signedTx',
          ]),
        );
        expect(counts.outbound).toEqual(messages.length);
        expect(counts.result).toEqual(10);
      } finally {
        for (const peer of peers)
          for (const attempt of peer['attempts'].values())
            attempt.close(new Error('test cleanup'));
        await Promise.all(relays);
      }
    });

    /**
     * @target SigningAttempt.run rejects invalid proof without allowing completed outbound
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Return invalid input verification and attempt completed transaction dispatch
     * @expected
     * - Rejects invalid proof without allowing completed outbound
     */
    it('rejects invalid proof without allowing completed outbound', async () => {
      const result = queue();
      await tick();
      const queued = await handler.getQueuedTransaction(f.id);
      queued.release();
      const bytes = signedBytes(f.reduced);
      vi.spyOn(utils, 'verifyInput').mockResolvedValue(false);
      await handler.handleSignedTx(bytes);
      await expect(result).rejects.toContain('invalid');
      await expect(
        handler['sendMessage'](
          'signedTx',
          { txBytes: bytes },
          ['peer'],
          1,
          ...handler['finalDispatch'](queued.transaction, bytes),
        ),
      ).rejects.toThrow('identity changed');
      expect(submit).not.toHaveBeenCalled();
    });

    /**
     * @target SigningAttempt.run bounds concurrent distinct attempts and rejects invalid required counts
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Fill pending capacity with one transaction, submit a distinct one, release capacity and test each invalid signer count
     * @expected
     * - Bounds concurrent distinct attempts and rejects invalid required counts
     */
    it('bounds concurrent distinct attempts and rejects invalid required counts', async () => {
      policy.maxPending = 1;
      handler = make();
      queue();
      await tick();
      const other = fixture(10000001);
      expect(other.id).not.toEqual(f.id);
      await expect(handler.sign(other.reduced, 6, other.boxes)).rejects.toThrow(
        'capacity',
      );
      for (const attempt of handler['attempts'].values())
        attempt.close(new Error('release capacity'));
      for (const count of [0, -1, 1.5, testPubs.length + 1])
        await expect(handler.sign(f.reduced, count, f.boxes)).rejects.toThrow(
          'required signer',
        );
    });

    /**
     * @target SigningAttempt.run revokes a policy callback that was retained instead of executed
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Retain the commitment action without invoking it and invoke it after authorization returns
     * @expected
     * - Revokes a policy callback that was retained instead of executed
     */
    it('revokes a policy callback that was retained instead of executed', async () => {
      let retained!: () => unknown;
      policy.bind = async () => ({
        withAction: async (phase, action) => {
          if (phase === 'commitment') {
            retained = action;
            return undefined as never;
          }
          return action();
        },
      });
      handler = make();
      const result = queue();
      await tick();
      const prover = vi.spyOn(handler, 'getProver' as never);
      await expect(handler.generateCommitment(f.id)).rejects.toThrow(
        'not authorized',
      );
      expect(() => retained()).toThrow('expired');
      expect(prover).not.toHaveBeenCalled();
      await expect(result).rejects.toThrow('not authorized');
    });
  });
});

describe('validateSigningAuthorization', () => {
  /**
   * @target validateSigningAuthorization rejects invalid timeout %s
   * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
   * @scenario
   * - Construct a real handler with only the selected timeout bound changed
   * @expected
   * - Rejects invalid timeout %s
   */
  it.each(invalidTimeouts)('rejects invalid timeout %s', (timeoutMs) => {
    expect(() => make({ ...policy, timeoutMs })).toThrow('bounds');
  });
});
