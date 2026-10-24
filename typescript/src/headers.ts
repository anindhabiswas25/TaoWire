/**
 * Header input for the verifiers.
 *
 * @module
 */

/**
 * Headers as received. Prefer a list of `[name, value]` pairs or Node's flat
 * `rawHeaders` array: Node's `IncomingHttpHeaders` and fetch `Headers` join a
 * repeated header into one `", "`-separated value, which hides duplicates
 * (the verifier refuses any repeated `X-Bittensor-*` header, spec 4.3).
 * In a record, each element of a `string[]` value counts as one header.
 */
export type HeaderInput =
    | readonly (readonly [string, string])[]
    | readonly string[]
    | Readonly<Record<string, string | readonly string[] | undefined>>;

/** Values by lower-case name, in arrival order. */
export type HeaderMap = Map<string, string[]>;

function add(map: HeaderMap, name: string, value: string): void {
    const key = name.toLowerCase();
    const values = map.get(key);
    if (values === undefined) {
        map.set(key, [value]);
    } else {
        values.push(value);
    }
}

/** Merge `input` by lower-case name, so no spelling escapes the duplicate check. */
export function headerMap(input: HeaderInput): HeaderMap {
    const map: HeaderMap = new Map();
    if (Array.isArray(input)) {
        const list = input as readonly unknown[];
        if (list.length > 0 && typeof list[0] === "string") {
            const flat = list as readonly string[];
            if (flat.length % 2 !== 0) {
                throw new TypeError("rawHeaders must have an even length");
            }
            for (let i = 0; i < flat.length; i += 2) {
                add(map, flat[i] as string, flat[i + 1] as string);
            }
        } else {
            for (const [name, value] of list as readonly (readonly [string, string])[]) {
                add(map, name, value);
            }
        }
        return map;
    }
    for (const [name, value] of Object.entries(input as Record<string, unknown>)) {
        if (typeof value === "string") {
            add(map, name, value);
        } else if (Array.isArray(value)) {
            for (const v of value as unknown[]) {
                add(map, name, String(v));
            }
        }
    }
    return map;
}

/** The first repeated name starting with `prefix`, or `null`. */
export function duplicateWithPrefix(map: HeaderMap, prefix: string): string | null {
    for (const [name, values] of map) {
        if (values.length > 1 && name.startsWith(prefix)) {
            return name;
        }
    }
    return null;
}

/** The single value of `name` (already checked for duplicates), or `undefined`. */
export function single(map: HeaderMap, name: string): string | undefined {
    return map.get(name.toLowerCase())?.[0];
}
