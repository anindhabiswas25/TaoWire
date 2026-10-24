// @ts-check
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
    { ignores: ["dist/", "build/", "coverage/", "docs-api/", "node_modules/"] },
    js.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    {
        languageOptions: {
            parserOptions: {
                projectService: { allowDefaultProject: ["*.js", "scripts/*.mjs", "bench/*.mjs"] },
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            "@typescript-eslint/restrict-template-expressions": [
                "error",
                { allowNumber: true, allowBoolean: true },
            ],
            "no-console": "error",
        },
    },
    {
        files: ["test/**", "bench/**", "examples/**", "scripts/**"],
        rules: { "no-console": "off", "@typescript-eslint/no-non-null-assertion": "off" },
    },
    {
        // plain JavaScript (configs, scripts, the benchmark): no type information
        files: ["**/*.js", "**/*.mjs"],
        ...tseslint.configs.disableTypeChecked,
        languageOptions: {
            globals: { process: "readonly", console: "readonly", Buffer: "readonly", URL: "readonly" },
        },
    },
);
