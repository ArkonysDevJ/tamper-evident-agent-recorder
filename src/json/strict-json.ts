// SPDX-License-Identifier: AGPL-3.0-or-later
// Strict RFC 8259 parser for the TEAR record domain (Blueprint §4.1, §4.3).
// JSON.parse is not used: it keeps the last of duplicate keys and accepts lone
// surrogates, and both must be rejected here.

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export type StrictJsonErrorKind = 'syntax' | 'duplicate_key' | 'invalid_unicode' | 'non_finite_number';

export class StrictJsonError extends Error {
  readonly kind: StrictJsonErrorKind;
  constructor(kind: StrictJsonErrorKind, message: string) {
    super(message);
    this.name = 'StrictJsonError';
    this.kind = kind;
  }
}

// Nesting limit for the recursive descent. No TEAR row or package nests deeper
// than a few levels, so anything beyond this fails schema validation anyway.
const MAX_DEPTH = 512;

const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

export function newJsonObject(): JsonObject {
  return Object.create(null) as JsonObject;
}

export function hasOwn(obj: JsonObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

export function isJsonObject(v: JsonValue | undefined): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Parses one JSON text strictly. Throws StrictJsonError on any violation. */
export function parseStrictJson(text: string): JsonValue {
  const parser = new Parser(text);
  parser.skipWhitespace();
  const value = parser.parseValue(0);
  parser.skipWhitespace();
  if (parser.pos !== text.length) {
    throw new StrictJsonError('syntax', `unexpected data at offset ${parser.pos}`);
  }
  return value;
}

class Parser {
  pos = 0;
  constructor(private readonly text: string) {}

  skipWhitespace(): void {
    const t = this.text;
    while (this.pos < t.length) {
      const c = t.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else break;
    }
  }

  parseValue(depth: number): JsonValue {
    if (depth > MAX_DEPTH) throw new StrictJsonError('syntax', 'nesting too deep');
    const c = this.text[this.pos];
    switch (c) {
      case '{':
        return this.parseObject(depth);
      case '[':
        return this.parseArray(depth);
      case '"':
        return this.parseString();
      case 't':
        return this.parseLiteral('true', true);
      case 'f':
        return this.parseLiteral('false', false);
      case 'n':
        return this.parseLiteral('null', null);
      default:
        return this.parseNumber();
    }
  }

  private parseLiteral<T extends JsonValue>(word: string, value: T): T {
    if (this.text.startsWith(word, this.pos)) {
      this.pos += word.length;
      return value;
    }
    throw new StrictJsonError('syntax', `invalid literal at offset ${this.pos}`);
  }

  private parseNumber(): number {
    NUMBER_RE.lastIndex = this.pos;
    const m = NUMBER_RE.exec(this.text);
    if (m === null || m[0].length === 0) {
      throw new StrictJsonError('syntax', `unexpected character at offset ${this.pos}`);
    }
    this.pos += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) throw new StrictJsonError('non_finite_number', `number out of range: ${m[0]}`);
    return n;
  }

  private parseString(): string {
    const t = this.text;
    this.pos++; // opening quote
    let out = '';
    let chunkStart = this.pos;
    for (;;) {
      if (this.pos >= t.length) throw new StrictJsonError('syntax', 'unterminated string');
      const c = t.charCodeAt(this.pos);
      if (c === 0x22) {
        out += t.slice(chunkStart, this.pos);
        this.pos++;
        break;
      }
      if (c < 0x20) throw new StrictJsonError('syntax', `unescaped control character at offset ${this.pos}`);
      if (c === 0x5c) {
        out += t.slice(chunkStart, this.pos);
        out += this.parseEscape();
        chunkStart = this.pos;
        continue;
      }
      this.pos++;
    }
    if (!out.isWellFormed()) throw new StrictJsonError('invalid_unicode', 'string contains a lone surrogate');
    return out;
  }

  private parseEscape(): string {
    const t = this.text;
    const e = t[this.pos + 1];
    this.pos += 2;
    switch (e) {
      case '"':
        return '"';
      case '\\':
        return '\\';
      case '/':
        return '/';
      case 'b':
        return '\b';
      case 'f':
        return '\f';
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case 'u': {
        const hex = t.slice(this.pos, this.pos + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new StrictJsonError('syntax', 'invalid \\u escape');
        this.pos += 4;
        return String.fromCharCode(parseInt(hex, 16));
      }
      default:
        throw new StrictJsonError('syntax', 'invalid escape');
    }
  }

  private parseArray(depth: number): JsonValue[] {
    this.pos++;
    const out: JsonValue[] = [];
    this.skipWhitespace();
    if (this.text[this.pos] === ']') {
      this.pos++;
      return out;
    }
    for (;;) {
      this.skipWhitespace();
      out.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      const c = this.text[this.pos];
      this.pos++;
      if (c === ']') return out;
      if (c !== ',') throw new StrictJsonError('syntax', 'expected , or ] in array');
    }
  }

  private parseObject(depth: number): JsonObject {
    this.pos++;
    const out = newJsonObject();
    this.skipWhitespace();
    if (this.text[this.pos] === '}') {
      this.pos++;
      return out;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.pos] !== '"') throw new StrictJsonError('syntax', 'expected object key');
      const key = this.parseString();
      if (hasOwn(out, key)) throw new StrictJsonError('duplicate_key', `duplicate key ${JSON.stringify(key)}`);
      this.skipWhitespace();
      if (this.text[this.pos] !== ':') throw new StrictJsonError('syntax', 'expected :');
      this.pos++;
      this.skipWhitespace();
      out[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      const c = this.text[this.pos];
      this.pos++;
      if (c === '}') return out;
      if (c !== ',') throw new StrictJsonError('syntax', 'expected , or } in object');
    }
  }
}
