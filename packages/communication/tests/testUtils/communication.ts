import { EdDSA } from '@rosen-bridge/encryption';

/** Generates the unchanged ten independent guard signers and their public keys. */
export const createGuardEncryptions = async () => {
  const guardMessageEncs: EdDSA[] = [];
  const guardPks: string[] = [];
  for (let index = 0; index < 10; index++) {
    const sk = new EdDSA(await EdDSA.randomKey());
    guardMessageEncs.push(sk);
    guardPks.push(await sk.getPk());
  }
  return { guardMessageEncs, guardPks };
};
