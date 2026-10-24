// Marks dist/cjs as CommonJS (the package itself is "type": "module").
import { writeFileSync } from "node:fs";
import { URL } from "node:url";
writeFileSync(new URL("../dist/cjs/package.json", import.meta.url), '{"type":"commonjs"}\n');
