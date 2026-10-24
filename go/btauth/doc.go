// Package btauth implements the btauth/1 signed-request protocol and the
// twresp/1 signed responses of TaoWire (spec Sections 4, 9.1 and 11.4) for
// Bittensor v11 subnets.
//
// A miner wraps its protected routes with [Middleware]: it caps the body,
// verifies the request in the normative order (shape, receiver, freshness,
// signature, replay), stores the nonce only after the signature verifies,
// and hands the handler the verified [Caller] ([CallerFrom]) and the raw body
// ([BodyFrom]). With a [Keypair] it also signs every answer with twresp/1.
// A validator signs requests with [Signer] and checks answers with
// [VerifyResponse].
//
// The verifier is stricter than the Bittensor SDK in the same ways as the
// Python kit: the sender must be an SS58 prefix-42 address, X-Bittensor-*
// headers must not repeat, the nonce is 1 to 20 ASCII digits, the crypto
// header is exactly "ed25519" or "sr25519", the signature is hex digits only,
// signatures over the <Bytes>-wrapped payload are never accepted, and weak
// public keys (whose signature verifies for every message) are refused.
// Every rule has a vector in conformance/vectors/negative.json.
//
// Errors carry the stable tw.* codes and HTTP statuses of spec Appendix A.
package btauth
