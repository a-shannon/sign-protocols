import * as wasm from 'ergo-lib-wasm-nodejs';

import { boxJs } from '../testData';
import { signingAuthorizationTree } from '../testData/signingAuthorization';
import { getChangeBoxJs, getOutBoxJs, jsToReducedTx } from './txUtils';

/** Waits one event-loop turn for the real handler queue transition. */
export const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
/** Creates the same reduced Ergo transaction and independent input box for signing controls. */
export const fixture = (amount = 10000000) => {
  const tree = signingAuthorizationTree;
  const output = getOutBoxJs(tree, ['ERG', amount]);
  const change = getChangeBoxJs([boxJs], [output], tree, 1000000);
  const reduced = jsToReducedTx(
    [boxJs],
    [output, change],
    [],
    1311604,
    1000000,
  );
  return {
    reduced,
    boxes: [wasm.ErgoBox.from_json(JSON.stringify(boxJs))],
    id: reduced.unsigned_tx().id().to_str(),
  };
};

/** Serializes the exact unsigned fixture with its original empty proof payload. */
export const signedBytes = (reduced: wasm.ReducedTransaction) =>
  Buffer.from(
    wasm.Transaction.from_unsigned_tx(reduced.unsigned_tx(), [
      new Uint8Array(),
    ]).sigma_serialize_bytes(),
  ).toString('base64');
