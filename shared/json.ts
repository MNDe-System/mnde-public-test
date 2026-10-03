export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

type ParseSuccess = { ok: true; value: JsonValue };
type ParseFailureReason = "invalid_json_syntax" | "duplicate_json_keys" | "invalid_json_number";
type ParseFailure = { ok: false; reason: ParseFailureReason };
type ParseResult = ParseSuccess | ParseFailure;

type ParserState = {
  source: string;
  index: number;
};

function skipWhitespace(state: ParserState): void {
  while (state.index < state.source.length) {
    const char = state.source[state.index];
    if (char === " " || char === "\n" || char === "\r" || char === "\t") {
      state.index += 1;
      continue;
    }
    return;
  }
}

function isJsonObject(value: JsonValue): value is { [key: string]: JsonValue } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseString(state: ParserState): ParseResult {
  const start = state.index;
  if (state.source[state.index] !== "\"") {
    return { ok: false, reason: "invalid_json_syntax" };
  }

  state.index += 1;
  while (state.index < state.source.length) {
    const char = state.source[state.index];
    if (char === "\"") {
      const rawToken = state.source.slice(start, state.index + 1);
      state.index += 1;
      try {
        return { ok: true, value: JSON.parse(rawToken) as string };
      } catch {
        return { ok: false, reason: "invalid_json_syntax" };
      }
    }

    if (char === "\\") {
      state.index += 1;
      if (state.index >= state.source.length) {
        return { ok: false, reason: "invalid_json_syntax" };
      }
      const escapeChar = state.source[state.index];
      if (escapeChar === "u") {
        const unicodeDigits = state.source.slice(state.index + 1, state.index + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(unicodeDigits)) {
          return { ok: false, reason: "invalid_json_syntax" };
        }
        state.index += 5;
        continue;
      }
      if (!"\"\\/bfnrt".includes(escapeChar)) {
        return { ok: false, reason: "invalid_json_syntax" };
      }
      state.index += 1;
      continue;
    }

    if (char < " ") {
      return { ok: false, reason: "invalid_json_syntax" };
    }

    state.index += 1;
  }

  return { ok: false, reason: "invalid_json_syntax" };
}

function parseNumber(state: ParserState): ParseResult {
  const remaining = state.source.slice(state.index);
  const match = remaining.match(/^-?(0|[1-9]\d*)/);
  if (!match) {
    return { ok: false, reason: "invalid_json_syntax" };
  }

  const token = match[0];
  const nextChar = remaining[token.length];
  if (nextChar === "." || nextChar === "e" || nextChar === "E") {
    return { ok: false, reason: "invalid_json_number" };
  }

  const parsed = Number(token);
  if (!Number.isSafeInteger(parsed)) {
    return { ok: false, reason: "invalid_json_number" };
  }

  state.index += token.length;
  return { ok: true, value: parsed };
}

function parseArray(state: ParserState): ParseResult {
  const arrayValue: JsonValue[] = [];
  state.index += 1;
  skipWhitespace(state);

  if (state.source[state.index] === "]") {
    state.index += 1;
    return { ok: true, value: arrayValue };
  }

  while (state.index < state.source.length) {
    const itemResult = parseValue(state);
    if (!itemResult.ok) {
      return itemResult;
    }
    arrayValue.push(itemResult.value);
    skipWhitespace(state);

    if (state.source[state.index] === "]") {
      state.index += 1;
      return { ok: true, value: arrayValue };
    }
    if (state.source[state.index] !== ",") {
      return { ok: false, reason: "invalid_json_syntax" };
    }
    state.index += 1;
    skipWhitespace(state);
  }

  return { ok: false, reason: "invalid_json_syntax" };
}

function parseObject(state: ParserState): ParseResult {
  const objectValue: Record<string, JsonValue> = {};
  const seenKeys = new Set<string>();

  state.index += 1;
  skipWhitespace(state);
  if (state.source[state.index] === "}") {
    state.index += 1;
    return { ok: true, value: objectValue };
  }

  while (state.index < state.source.length) {
    const keyResult = parseString(state);
    if (!keyResult.ok || typeof keyResult.value !== "string") {
      return { ok: false, reason: keyResult.ok ? "invalid_json_syntax" : keyResult.reason };
    }
    if (seenKeys.has(keyResult.value)) {
      return { ok: false, reason: "duplicate_json_keys" };
    }
    seenKeys.add(keyResult.value);
    skipWhitespace(state);

    if (state.source[state.index] !== ":") {
      return { ok: false, reason: "invalid_json_syntax" };
    }
    state.index += 1;

    const valueResult = parseValue(state);
    if (!valueResult.ok) {
      return valueResult;
    }
    Object.defineProperty(objectValue, keyResult.value, {
      value: valueResult.value,
      enumerable: true,
      configurable: true,
      writable: true
    });
    skipWhitespace(state);

    if (state.source[state.index] === "}") {
      state.index += 1;
      return { ok: true, value: objectValue };
    }
    if (state.source[state.index] !== ",") {
      return { ok: false, reason: "invalid_json_syntax" };
    }
    state.index += 1;
    skipWhitespace(state);
  }

  return { ok: false, reason: "invalid_json_syntax" };
}

function parseValue(state: ParserState): ParseResult {
  skipWhitespace(state);
  const char = state.source[state.index];

  if (char === "{") {
    return parseObject(state);
  }
  if (char === "[") {
    return parseArray(state);
  }
  if (char === "\"") {
    return parseString(state);
  }
  if (char === "-" || (char >= "0" && char <= "9")) {
    return parseNumber(state);
  }
  if (state.source.startsWith("true", state.index)) {
    state.index += 4;
    return { ok: true, value: true };
  }
  if (state.source.startsWith("false", state.index)) {
    state.index += 5;
    return { ok: true, value: false };
  }
  if (state.source.startsWith("null", state.index)) {
    state.index += 4;
    return { ok: true, value: null };
  }
  return { ok: false, reason: "invalid_json_syntax" };
}

export function parseStrictJson(source: string): ParseResult {
  const state: ParserState = { source, index: 0 };
  const valueResult = parseValue(state);
  if (!valueResult.ok) {
    return valueResult;
  }
  skipWhitespace(state);
  if (state.index !== state.source.length) {
    return { ok: false, reason: "invalid_json_syntax" };
  }
  return valueResult;
}

function serializeNumber(value: number): string {
  if (!Number.isSafeInteger(value)) {
    throw new Error("Only safe integers are permitted");
  }
  if (Object.is(value, -0)) {
    return "0";
  }
  return JSON.stringify(value);
}

export function canonicalizeJson(value: JsonValue): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    return serializeNumber(value);
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  if (isJsonObject(value)) {
    const keys = Object.keys(value).sort();
    const pairs = keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`);
    return `{${pairs.join(",")}}`;
  }
  throw new Error("Unsupported JSON value");
}
