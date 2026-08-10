// Deliberate DPoP faults (RFC 9449) for exercising the server's rejection paths.
//
// Each entry targets exactly one step of the server's validation chain
// (typ -> alg -> signature -> htm -> htu -> iat -> ath -> nonce -> jti -> replay), so a rejection can
// be attributed to the step under test rather than to whichever check happens to run first.
//
// This module is data only: both the manual switches and the (future) automated suite read from it,
// so there is a single place where "what should go wrong, and how should the server answer" lives.

/** Which server the request goes to. Decides the expected status and which faults apply. */
export type DpopFaultTarget = "as" | "rs";

/** Where the fault is applied: inside the proof, or to the request carrying it. */
export type DpopFaultStage = "proof" | "request";

export type DpopFaultKey =
  | "typ-wrong"
  | "alg-hs256"
  | "alg-none"
  | "jwk-missing"
  | "jwk-other"
  | "signature-corrupt"
  | "htm-wrong"
  | "htu-wrong"
  | "iat-past"
  | "iat-future"
  | "jti-missing"
  | "jti-reuse"
  | "nonce-missing"
  | "nonce-garbage"
  | "ath-missing"
  | "ath-wrong"
  | "header-omitted";

export interface DpopFault {
  key: DpopFaultKey;
  /** Heading it is listed under, mirroring the order of the server's validation chain. */
  group: string;
  label: string;
  /** What is manipulated, and which server-side check is expected to catch it. */
  description: string;
  stage: DpopFaultStage;
  targets: DpopFaultTarget[];
  /**
   * The OAuth error code the server should answer with. Only this and the status code are treated as
   * pass/fail; error_description is shown but never asserted, because it is prose that may be
   * reworded without the behaviour changing.
   */
  expectedError: "invalid_dpop_proof" | "use_dpop_nonce";
  /**
   * Only meaningful while the server runs with DPoP nonces enabled. With nonces off these requests
   * are accepted, which is correct behaviour rather than a regression.
   */
  requiresNonceMode?: boolean;
  /**
   * Set when the scenario only says something if the request before it was accepted. A proof
   * identifier is recorded as the very last step of validation, so after a rejected proof nothing was
   * stored and "reuse" would resend an identifier the server has never seen.
   */
  requiresAcceptedPredecessor?: boolean;
  /** Set when the outcome cannot be trusted on a target, with the reason to show in the UI. */
  unreliableOn?: { target: DpopFaultTarget; reason: string };
}

export const DPOP_FAULTS: DpopFault[] = [
  {
    key: "typ-wrong",
    group: "Proof header",
    label: "typ is not dpop+jwt",
    description: "Sets typ to jwt, which the first check in the chain must reject.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "alg-hs256",
    group: "Proof header",
    label: "alg is HS256",
    description: "A symmetric algorithm cannot bind a public key, so alg is restricted to ES256.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "alg-none",
    group: "Proof header",
    label: "alg is none, signature empty",
    description: "The unsigned-token attack. Must never be accepted, whatever the rest of the proof says.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "jwk-missing",
    group: "Proof header",
    label: "jwk omitted",
    description: "Without the public key the signature cannot be verified and no jkt can be derived.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "jwk-other",
    group: "Proof header",
    label: "jwk of a different key",
    description:
      "Advertises a key that did not sign the proof. Catches a server that trusts jwk without verifying against it.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },

  {
    key: "signature-corrupt",
    group: "Signature",
    label: "Signature damaged",
    description:
      "Signs normally and then alters the signature, so everything except the signature stays valid.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },

  {
    key: "htm-wrong",
    group: "Proof payload",
    label: "htm is a different method",
    description: "Binds the proof to another HTTP method than the one being used.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "htu-wrong",
    group: "Proof payload",
    label: "htu points elsewhere",
    description: "Binds the proof to another URL, the way a stolen proof replayed at a second endpoint would.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "iat-past",
    group: "Proof payload",
    label: "iat far in the past",
    description: "Beyond the accepted clock skew, so the proof is too old to still be fresh.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "iat-future",
    group: "Proof payload",
    label: "iat far in the future",
    description:
      "A proof minted ahead of time would otherwise stay usable far longer than the freshness window allows.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "jti-missing",
    group: "Proof payload",
    label: "jti omitted",
    description: "Without an identifier a proof cannot be recorded, and replay detection would be blind.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "jti-reuse",
    group: "Proof payload",
    label: "jti of the previous request",
    description:
      "The actual replay: reuses the last jti sent, which the server must have recorded. Do a normal request first.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
    requiresAcceptedPredecessor: true,
    unreliableOn: {
      target: "as",
      reason:
        "The authorization code is spent after the first request, so the second may fail on the grant instead of on the jti. Use a resource call for a clean result.",
    },
  },
  {
    key: "nonce-missing",
    group: "Proof payload",
    label: "nonce omitted",
    description: "Should be answered with a challenge plus a fresh nonce, not with a plain rejection.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "use_dpop_nonce",
    requiresNonceMode: true,
  },
  {
    key: "nonce-garbage",
    group: "Proof payload",
    label: "nonce filled with nonsense",
    description: "A value the server never issued. Same challenge as a missing nonce.",
    stage: "proof",
    targets: ["as", "rs"],
    expectedError: "use_dpop_nonce",
    requiresNonceMode: true,
  },
  {
    key: "ath-missing",
    group: "Proof payload",
    label: "ath omitted",
    description: "Without the access-token hash the proof is not bound to the token it accompanies.",
    stage: "proof",
    targets: ["rs"],
    expectedError: "invalid_dpop_proof",
  },
  {
    key: "ath-wrong",
    group: "Proof payload",
    label: "ath of a different token",
    description: "A proof paired with someone else's token, which is what ath exists to prevent.",
    stage: "proof",
    targets: ["rs"],
    expectedError: "invalid_dpop_proof",
  },

  {
    key: "header-omitted",
    group: "Around the proof",
    label: "No proof sent at all",
    description:
      "Leaves the proof off entirely while the request is otherwise unchanged. Rejected only when the server requires DPoP.",
    stage: "request",
    targets: ["as", "rs"],
    expectedError: "invalid_dpop_proof",
  },
];

/** Status the server answers a rejected proof with: a bad request at the AS, unauthorized at the RS. */
export function expectedStatus(target: DpopFaultTarget): number {
  return target === "as" ? 400 : 401;
}

export function findFault(key: DpopFaultKey): DpopFault | undefined {
  return DPOP_FAULTS.find((fault) => fault.key === key);
}

/** Groups in the order the server evaluates them, so the list reads like the validation chain. */
export function faultGroups(): string[] {
  return [...new Set(DPOP_FAULTS.map((fault) => fault.group))];
}
