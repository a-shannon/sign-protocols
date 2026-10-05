import { describe, expect, it, vi, beforeEach } from 'vitest';

import { EdDSA } from '@rosen-bridge/encryption';

import { payload, protocolVersion } from './testData';
import { createGuardEncryptions } from './testUtils/communication';
import { deferred, fixture } from './testUtils/dispatch';
import { TestCommunicator } from './testUtils/testCommunicator';

describe('Communicator', () => {
  let guardMessageEncs: Array<EdDSA>;
  let guardPks: Array<string>;

  beforeEach(async () => {
    ({ guardMessageEncs, guardPks } = await createGuardEncryptions());
  });

  describe('getIndex', () => {
    const mockSubmit = vi.fn();

    /**
     * @target Communicator.getIndex should return exception when pk of guard doesn't exist between guardPks
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - override current guard message encryption with wrong
     * - create communicator
     * - call getIndex
     * @expected
     * - must throw Error
     */
    it("should return exception when pk of guard doesn't exist between guardPks", async () => {
      guardMessageEncs[1] = new EdDSA(await EdDSA.randomKey());
      const communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
      await expect(communicator.mockedGetIndex()).rejects.toThrow(Error);
    });

    /**
     * @target Communicator.getIndex should return correct index
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - create communicator and assign guardMessageEnc with index 1 as current guard
     * - call getIndex
     * @expected
     * - should return correct index 1
     */
    it('should return correct index', async () => {
      const communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
      await expect(communicator.mockedGetIndex()).resolves.toEqual(1);
    });
  });

  describe('getDate', () => {
    let communicator: TestCommunicator;

    beforeEach(async () => {
      const mockSubmit = vi.fn();
      communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
    });

    /**
     * @target Communicator.getDate should return current timestamp rounded to seconds
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - mock Date.now to return 1685683305125
     * - call getDate
     * @expected
     * - must return 1685683305
     */
    it('should return current timestamp rounded to seconds', () => {
      const currentTime = 1685683305;
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000 + 125);
      const res = communicator.mockedGetDate();
      expect(res).toEqual(currentTime);
    });
  });

  describe('sendMessage', () => {
    let communicator: TestCommunicator;
    let mockSubmit = vi.fn();

    beforeEach(async () => {
      mockSubmit = vi.fn();
      communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
    });

    /**
     * @target Communicator.sendMessage should call submit message
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - mock submitMessage function
     * - call with specified argument
     * @expected
     * - mocked function must call once
     * - first argument must be as a json contain expected values
     */
    it('should call submit message', async () => {
      const currentTime = 1685683141;
      const publicKey = await guardMessageEncs[1].getPk();
      const sign = await guardMessageEncs[1].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      await communicator.testSendMessage('msg', payload, []);
      const expected = {
        type: 'msg',
        payload: payload,
        sign: sign,
        publicKey: publicKey,
        timestamp: currentTime,
        index: 1,
        version: protocolVersion,
      };
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      const callArgs = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(callArgs).toEqual(expected);
    });

    /**
     * @target Communicator.sendMessage checks the gate after asynchronous envelope signing and suppresses a held send
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Pause envelope signing, revoke admission, then release signing
     * @expected
     * - Checks the gate after asynchronous envelope signing and suppresses a held send
     */
    it('checks the gate after asynchronous envelope signing and suppresses a held send', async () => {
      const { signer, communicator, submit } = fixture();
      const waiting = deferred();
      const entered = deferred();
      let allowed = true;
      vi.spyOn(signer, 'sign').mockImplementation(async () => {
        entered.resolve();
        await waiting.promise;
        return 'fixture-signature';
      });
      const pending = communicator.send(async (dispatch) => {
        if (!allowed) throw new Error('held');
        dispatch();
      });
      const result = pending.then(
        () => undefined,
        (error: unknown) => error,
      );
      await entered.promise;
      allowed = false;
      waiting.resolve();
      expect(await result).toEqual(new Error('held'));
      expect(submit).not.toHaveBeenCalled();
    });

    /**
     * @target Communicator.sendMessage checks after the final asynchronous index lookup
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Pause the third public-key lookup, revoke admission, then resume the lookup
     * @expected
     * - Checks after the final asynchronous index lookup
     */
    it('checks after the final asynchronous index lookup', async () => {
      const { signer, communicator, submit } = fixture();
      const waiting = deferred();
      const entered = deferred();
      let calls = 0;
      let allowed = true;
      vi.spyOn(signer, 'getPk').mockImplementation(async () => {
        if (++calls === 3) {
          entered.resolve();
          await waiting.promise;
        }
        return 'fixture-key';
      });
      const pending = communicator.send(async (dispatch) => {
        if (!allowed) throw new Error('held');
        dispatch();
      });
      const result = pending.then(
        () => undefined,
        (error: unknown) => error,
      );
      await entered.promise;
      allowed = false;
      waiting.resolve();
      expect(await result).toEqual(new Error('held'));
      expect(submit).not.toHaveBeenCalled();
    });

    /**
     * @target Communicator.sendMessage releases the gate before waiting for transport completion
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Hold the transport promise after dispatch and inspect the released gate before completing transport
     * @expected
     * - Releases the gate before waiting for transport completion
     */
    it('releases the gate before waiting for transport completion', async () => {
      const transport = deferred();
      const { communicator, submit } = fixture(vi.fn(() => transport.promise));
      let leased = false;
      const gateDone = deferred();
      let finished = false;
      const pending = communicator
        .send(async (dispatch) => {
          leased = true;
          try {
            dispatch();
          } finally {
            leased = false;
            gateDone.resolve();
          }
        })
        .then(() => {
          finished = true;
        });
      await gateDone.promise;
      expect(submit).toHaveBeenCalledTimes(1);
      expect(leased).toEqual(false);
      expect(finished).toEqual(false);
      transport.resolve();
      await pending;
    });

    /**
     * @target Communicator.sendMessage propagates transport rejection after the gate ends
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Dispatch a transport promise that rejects after the gate callback returns
     * @expected
     * - Propagates transport rejection after the gate ends
     */
    it('propagates transport rejection after the gate ends', async () => {
      const { communicator } = fixture(
        vi.fn(() => Promise.reject(new Error('transport failed'))),
      );
      await expect(
        communicator.send(async (dispatch) => {
          dispatch();
        }),
      ).rejects.toThrow('transport failed');
    });

    /**
     * @target Communicator.sendMessage observes transport rejection while an asynchronous gate is still returning
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Reject transport while the gate return is paused, then resume the gate
     * @expected
     * - Observes transport rejection while an asynchronous gate is still returning
     */
    it('observes transport rejection while an asynchronous gate is still returning', async () => {
      const gateReturn = deferred();
      const entered = deferred();
      const { communicator } = fixture(
        vi.fn(() => Promise.reject(new Error('transport failed'))),
      );
      const pending = communicator.send(async (dispatch) => {
        dispatch();
        entered.resolve();
        await gateReturn.promise;
      });
      const result = pending.then(
        () => undefined,
        (error: unknown) => error,
      );
      await entered.promise;
      await new Promise((done) => setTimeout(done, 0));
      gateReturn.resolve();
      expect(await result).toEqual(new Error('transport failed'));
    });

    /**
     * @target Communicator.sendMessage propagates synchronous submission failure
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Throw from the transport submission callback during authorized dispatch
     * @expected
     * - Propagates synchronous submission failure
     */
    it('propagates synchronous submission failure', async () => {
      const { communicator } = fixture(
        vi.fn(() => {
          throw new Error('dispatch failed');
        }),
      );
      await expect(
        communicator.send(async (dispatch) => {
          dispatch();
        }),
      ).rejects.toThrow('dispatch failed');
    });

    /**
     * @target Communicator.sendMessage rejects an unused callback and revokes it when the gate returns
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Retain the dispatch callback without invoking it, then invoke it after the gate returns
     * @expected
     * - Rejects an unused callback and revokes it when the gate returns
     */
    it('rejects an unused callback and revokes it when the gate returns', async () => {
      const { communicator, submit } = fixture();
      let saved!: () => void;
      await expect(
        communicator.send(async (dispatch) => {
          saved = dispatch;
        }),
      ).rejects.toThrow('not authorized');
      expect(() => saved()).toThrow('no longer available');
      expect(submit).not.toHaveBeenCalled();
    });

    /**
     * @target Communicator.sendMessage revokes the callback when the gate rejects
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Retain the dispatch callback and reject the gate before invoking the retained callback
     * @expected
     * - Revokes the callback when the gate rejects
     */
    it('revokes the callback when the gate rejects', async () => {
      const { communicator, submit } = fixture();
      let saved!: () => void;
      await expect(
        communicator.send(async (dispatch) => {
          saved = dispatch;
          throw new Error('held');
        }),
      ).rejects.toThrow('held');
      expect(() => saved()).toThrow('no longer available');
      expect(submit).not.toHaveBeenCalled();
    });

    /**
     * @target Communicator.sendMessage rejects duplicate callback invocation without dispatching twice
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Invoke the same authorized dispatch callback twice
     * @expected
     * - Rejects duplicate callback invocation without dispatching twice
     */
    it('rejects duplicate callback invocation without dispatching twice', async () => {
      const { communicator, submit } = fixture();
      await expect(
        communicator.send(async (dispatch) => {
          dispatch();
          dispatch();
        }),
      ).rejects.toThrow('no longer available');
      expect(submit).toHaveBeenCalledTimes(1);
    });

    /**
     * @target Communicator.sendMessage keeps an unconfigured caller independent of transport completion
     * @dependencies Synthetic encryption, transport and authorization collaborators; actual production handlers
     * @scenario
     * - Send without a gate while the transport completion promise remains pending
     * @expected
     * - Keeps an unconfigured caller independent of transport completion
     */
    it('keeps an unconfigured caller independent of transport completion', async () => {
      const waiting = deferred();
      const { communicator, submit } = fixture(vi.fn(() => waiting.promise));
      await expect(communicator.send()).resolves.toBeUndefined();
      expect(submit).toHaveBeenCalledTimes(1);
      waiting.resolve();
    });
  });

  describe('handleMessage', () => {
    let communicator: TestCommunicator;

    beforeEach(async () => {
      const mockSubmit = vi.fn();
      communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
    });

    /**
     * @target Communicator.handleMessage should pass arguments to process message function when sign is valid
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - generate a message signed with second guard sk
     * - pass to handleMessage
     * @expected
     * - processMessage function called once
     * - message type and payload pass to processMessage
     */
    it('should pass arguments to process message function when sign is valid', async () => {
      const currentTime = 1685683142;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        sign: sign,
        timestamp: currentTime,
        publicKey,
        index: 2,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(1);
      expect(communicator.processMessage).toHaveBeenCalledWith(
        'message',
        payload,
        sign,
        2,
        'guardIndex2',
        currentTime,
      );
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when signature is not valid
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - generate a message signed with second guard sk with index 3 (invalid sign)
     * - pass to handleMessage
     * @expected
     * - processMessage must not call
     */
    it('should not call processMessage when signature is not valid', async () => {
      const currentTime = 1685683143;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey: await guardMessageEncs[3].getPk(),
        timestamp: currentTime,
        sign: sign,
        index: 3,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when signer public key differ from index
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - generate a message signed with second guard sk with index 3 and public key of second guard
     * - pass to handleMessage
     * @expected
     * - processMessage must not call
     */
    it('should not call processMessage when signer public key differ from index', async () => {
      const currentTime = 1685683144;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 3,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when message timed out
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - mock Date.now() to return 1685683141101
     * - generate a valid message with timestamp equals to 60001 milliseconds before
     * - pass to handleMessage
     * @expected
     * - processMessage must not call
     */
    it('should not call processMessage when message timed out', async () => {
      const currentTime = 1685683145;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime - 60001}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime - 61,
        sign: sign,
        index: 2,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when protocol major version differs
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - generate a validly signed message with a different major protocol version
     * - pass to handleMessage
     * @expected
     * - processMessage must not call
     */
    it('should not call processMessage when protocol major version differs', async () => {
      const currentTime = 1685683146;
      const publicKey = await guardMessageEncs[2].getPk();
      const otherVersion = '2.0.0'; // different major than protocolVersion
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${otherVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 2,
        version: otherVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should call processMessage when only the minor/patch protocol version differs
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - generate a validly signed message whose version shares protocolVersion's major but differs in minor/patch
     * - pass to handleMessage
     * @expected
     * - processMessage must be called
     */
    it('should call processMessage when only the minor/patch protocol version differs', async () => {
      const currentTime = 1685683148;
      const publicKey = await guardMessageEncs[2].getPk();
      const otherVersion = `${protocolVersion.split('.')[0]}.9.9`; // same major, different minor/patch
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${otherVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 2,
        version: otherVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledOnce();
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when the version field is tampered with after signing
     * @dependencies Real EdDSA and Communicator; synthetic transport observer
     * @scenario
     * - generate a message signed with the current protocol version
     * - rewrite its version field to a different value before passing to handleMessage
     * @expected
     * - processMessage must not call, since the signature no longer matches the (signed) version
     */
    it('should not call processMessage when the version field is tampered with after signing', async () => {
      const currentTime = 1685683147;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 2,
        version: `${protocolVersion}-tampered`,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });
  });
});
