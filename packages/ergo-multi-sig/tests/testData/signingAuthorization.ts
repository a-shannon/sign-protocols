/** P2PK output tree retained by the authorization transaction fixture. */
export const signingAuthorizationTree =
  '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';

/** Each independently mutated identity field must fail before the wallet sink. */
export const identityFields = [
  /* Required signer count captured at queue admission. */
  'requiredSigner',
  /* Serialized spending input boxes. */
  'boxes',
  /* Guard roster and peer ordering. */
  'peers',
  /* Reduced transaction bytes and identifier. */
  'tx',
  /* Serialized read-only input boxes. */
  'dataBoxes',
  /* Local guard public key. */
  'publicKey',
];

/** Each actual protocol envelope must receive fresh final transport authorization. */
export const outboundTypes = [
  /* Coordinator request for commitments. */
  'generateCommitment',
  /* Participant commitment response. */
  'commitment',
  /* Coordinator signing request. */
  'initiateSign',
  /* Participant signing proof response. */
  'sign',
  /* Completed transaction notification. */
  'signedTx',
];

/** Constructor bounds reject each timeout independently. */
export const invalidTimeouts = [
  /* Zero timeout. */
  0,
  /* Negative timeout. */
  -1,
  /* Non-integral timeout. */
  0.5,
  /* Infinite timeout. */
  Infinity,
  /* Value above the signed 32-bit timer bound. */
  2147483648,
];
