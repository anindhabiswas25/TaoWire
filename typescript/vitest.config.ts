import { defineConfig } from "vitest/config";

// definition of done item 3: >= 90% on the btauth code, per file
const BTAUTH = [
    "verify",
    "store",
    "clockstep",
    "twresp",
    "ss58",
    "keys",
    "payload",
    "headers",
    "nonce",
    "errors",
    "ratelimit",
    "fastify",
    "client",
    "redis",
];
const per = { lines: 90, branches: 90, functions: 90, statements: 90 };

export default defineConfig({
    test: {
        include: ["test/**/*.test.ts"],
        // fuzz.test.ts runs only through `npm run fuzz` (TW_FUZZ_SECONDS set)
        exclude: process.env.TW_FUZZ_SECONDS === undefined ? ["test/fuzz.test.ts"] : [],
        testTimeout: 30_000,
        pool: "forks",
        maxWorkers: 2,
        coverage: {
            provider: "v8",
            include: ["src/**"],
            reporter: ["text", "json-summary"],
            thresholds: {
                ...Object.fromEntries(BTAUTH.map((name) => [`src/${name}.ts`, per])),
                lines: 80,
            },
        },
    },
    resolve: {
        alias: {
            "@tensorwire/btauth/fastify": new URL("./src/fastify.ts", import.meta.url).pathname,
            "@tensorwire/btauth/redis": new URL("./src/redis.ts", import.meta.url).pathname,
            "@tensorwire/btauth": new URL("./src/index.ts", import.meta.url).pathname,
        },
    },
});
