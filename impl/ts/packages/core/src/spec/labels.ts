// Domain-separation labels (spec §5.3–5.7, §8.2, §11.2). Every LP input starts with one.
export const LABELS = {
  kxTranscript: "WAKE/1 kx-transcript",
  taApprove: "WAKE/1 ta-approve",
  webauthnChallenge: "WAKE/1 webauthn-challenge",
  keyC2s: "WAKE/1 key c2s",
  keyS2c: "WAKE/1 key s2c",
  finishedC2s: "WAKE/1 finished c2s",
  finishedS2c: "WAKE/1 finished s2c",
  clientFinished: "WAKE/1 client finished",
  serverFinished: "WAKE/1 server finished",
  msg: "WAKE/1 msg",
  etReq: "WAKE/1 et-req",
  etRes: "WAKE/1 et-res",
} as const;
