// Time-boxed fuzz run of the property tests: `TW_FUZZ_SECONDS=300 npm run fuzz`.
// Each property runs until its share of the time is up (no run-count cap).
import fc from "fast-check";
import { beforeAll, expect, it } from "vitest";
import { initCrypto } from "@tensorwire/btauth";
import { arbitraryHeaders, mutatedGolden, ss58Decode, twrespHeaders } from "./properties.js";

const seconds = Number(process.env.TW_FUZZ_SECONDS ?? "20");
const share = (seconds * 1000) / 4;

beforeAll(initCrypto);

function fuzz<T>(name: string, property: fc.IRawProperty<T>): void {
    it(
        name,
        async () => {
            const out = await fc.check(property, {
                numRuns: Number.MAX_SAFE_INTEGER,
                interruptAfterTimeLimit: share,
            });
            console.log(
                `fuzz ${name}: ${out.numRuns} runs in ${(share / 1000).toFixed(0)} s, failed=${out.failed}`,
            );
            expect(out.failed, fc.defaultReportMessage(out) ?? "").toBe(false);
        },
        share + 60_000,
    );
}

fuzz("arbitraryHeaders", arbitraryHeaders);
fuzz("mutatedGolden", mutatedGolden);
fuzz("ss58Decode", ss58Decode);
fuzz("twrespHeaders", twrespHeaders);
