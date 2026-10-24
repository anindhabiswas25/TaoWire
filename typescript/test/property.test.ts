// Property tests (fast-check) of the verifier and parsers, fixed run counts.
import fc from "fast-check";
import { beforeAll, it } from "vitest";
import { initCrypto } from "@tensorwire/btauth";
import { arbitraryHeaders, mutatedGolden, ss58Decode, twrespHeaders } from "./properties.js";

beforeAll(initCrypto);

it("arbitrary headers are refused with an auth code", async () => {
    await fc.assert(arbitraryHeaders, { numRuns: 500 });
});

it("a mutated valid request is refused", async () => {
    await fc.assert(mutatedGolden, { numRuns: 500 });
});

it("SS58 decoding fails closed", () => {
    fc.assert(ss58Decode, { numRuns: 2000 });
});

it("twresp/1 verification fails closed", () => {
    fc.assert(twrespHeaders, { numRuns: 1000 });
});
