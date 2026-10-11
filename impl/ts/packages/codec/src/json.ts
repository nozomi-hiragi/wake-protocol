// Strict I-JSON (RFC 7493) parser on top of RFC 8259 JSON text.
const MAX_DEPTH = 64;

class Parser {
  readonly text: string;
  pos = 0;

  constructor(text: string) {
    this.text = text;
  }

  fail(message: string): never {
    throw new SyntaxError(`${message} at position ${this.pos}`);
  }

  skipWhitespace(): void {
    for (;;) {
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else return;
    }
  }

  parseDocument(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.pos < this.text.length) this.fail("unexpected trailing characters");
    return value;
  }

  parseValue(depth: number): unknown {
    if (this.pos >= this.text.length) this.fail("unexpected end of input");
    const c = this.text[this.pos]!;
    if (c === "{") return this.parseObject(depth + 1);
    if (c === "[") return this.parseArray(depth + 1);
    if (c === '"') return this.parseString();
    if (c === "-" || (c >= "0" && c <= "9")) return this.parseNumber();
    if (this.text.startsWith("true", this.pos)) { this.pos += 4; return true; }
    if (this.text.startsWith("false", this.pos)) { this.pos += 5; return false; }
    if (this.text.startsWith("null", this.pos)) { this.pos += 4; return null; }
    return this.fail("unexpected character");
  }

  enter(depth: number): void {
    if (depth > MAX_DEPTH) throw new RangeError(`nesting deeper than ${MAX_DEPTH}`);
  }

  parseArray(depth: number): unknown[] {
    this.enter(depth);
    this.pos++;
    const out: unknown[] = [];
    this.skipWhitespace();
    if (this.text[this.pos] === "]") { this.pos++; return out; }
    for (;;) {
      this.skipWhitespace();
      out.push(this.parseValue(depth));
      this.skipWhitespace();
      const c = this.text[this.pos];
      if (c === ",") { this.pos++; continue; }
      if (c === "]") { this.pos++; return out; }
      this.fail("expected ',' or ']'");
    }
  }

  parseObject(depth: number): Record<string, unknown> {
    this.enter(depth);
    this.pos++;
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.text[this.pos] === "}") { this.pos++; return out; }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.pos] !== '"') this.fail("expected member name");
      const key = this.parseString();
      if (seen.has(key)) this.fail("duplicate member name");
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.pos] !== ":") this.fail("expected ':'");
      this.pos++;
      this.skipWhitespace();
      const value = this.parseValue(depth);
      // defineProperty keeps "__proto__" as an own data property
      Object.defineProperty(out, key, { value, enumerable: true, writable: true, configurable: true });
      this.skipWhitespace();
      const c = this.text[this.pos];
      if (c === ",") { this.pos++; continue; }
      if (c === "}") { this.pos++; return out; }
      this.fail("expected ',' or '}'");
    }
  }

  parseString(): string {
    this.pos++; // opening quote
    let out = "";
    let start = this.pos;
    for (;;) {
      if (this.pos >= this.text.length) this.fail("unterminated string");
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x22) {
        out += this.text.slice(start, this.pos);
        this.pos++;
        break;
      }
      if (c < 0x20) this.fail("unescaped control character");
      if (c !== 0x5c) { this.pos++; continue; }
      out += this.text.slice(start, this.pos);
      this.pos++;
      const e = this.text[this.pos];
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const hex = this.text.slice(this.pos + 1, this.pos + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("invalid unicode escape");
          out += String.fromCharCode(parseInt(hex, 16));
          this.pos += 4;
          break;
        }
        default: this.fail("invalid escape");
      }
      this.pos++;
      start = this.pos;
    }
    this.checkWellFormed(out);
    return out;
  }

  // Reject lone surrogates, raw or escaped.
  checkWellFormed(s: string): void {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const d = s.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) i++;
        else this.fail("lone surrogate");
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        this.fail("lone surrogate");
      }
    }
  }

  parseNumber(): number {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.text.slice(this.pos, this.pos + 4096));
    if (m === null) this.fail("invalid number");
    const token = m[0];
    const next = this.text[this.pos + token.length];
    if (token.length === 4096 || (next !== undefined && /[0-9.eE+\-]/.test(next))) this.fail("invalid number");
    const n = Number(token);
    if (!Number.isFinite(n)) this.fail("number out of range");
    if (Number.isInteger(n) && !Number.isSafeInteger(n)) this.fail("integer outside the safe range");
    this.pos += token.length;
    return n;
  }
}

/** Parses I-JSON text. Throws SyntaxError for invalid input and RangeError for nesting above 64. */
export function parseIJson(text: string): unknown {
  return new Parser(text).parseDocument();
}
