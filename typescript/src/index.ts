/**
 * `@tensorwire/btauth`: btauth/1 signed requests and twresp/1 signed
 * responses for Bittensor v11 subnets (TensorWire, spec 11.3).
 *
 * Call `await initCrypto()` once before signing or verifying. The Fastify
 * adapter is `@tensorwire/btauth/fastify`, the Redis replay store
 * `@tensorwire/btauth/redis`.
 *
 * @module
 */
export { StepGuard, monotonicNs } from "./clockstep.js";
export {
    Client,
    ClientError,
    type ClientOptions,
    type MinerResponse,
    type SignedRequest,
    Signer,
    requestTarget,
} from "./client.js";
export {
    CLIENT_CODES,
    type ClientCode,
    type Code,
    type ServerCode,
    TWError,
    errorBody,
    statusOf,
} from "./errors.js";
export type { HeaderInput } from "./headers.js";
export { Keypair, initCrypto, isWeakPublicKey, signatureHex, verifySignature } from "./keys.js";
export { NonceSource, wallClockNs } from "./nonce.js";
export { PROTOCOL, type PayloadInput, type Scheme, bodySha256, buildPayload } from "./payload.js";
export { DEFAULT_HOTKEY_LIMIT, type RateLimit, TokenBuckets } from "./ratelimit.js";
export { SS58Error, SS58_LENGTH, SS58_PREFIX, decodeSS58, encodeSS58 } from "./ss58.js";
export { MemoryStore, type NonceStore, type StoreClocks, secondsToNs } from "./store.js";
export {
    RESP_HEADER,
    RESP_PROTOCOL,
    type ResponseBinding,
    type ResponseExpectation,
    identityHeaders,
    responsePayload,
    signDigest,
    signResponse,
    verifyResponse,
    verifyResponseDigest,
} from "./twresp.js";
export {
    type Caller,
    DEFAULT_ALLOWED_SKEW_S,
    DEFAULT_MAX_AGE_S,
    HEADER,
    type RequestInput,
    Verifier,
    type VerifierConfig,
    verifyRequest,
} from "./verify.js";
