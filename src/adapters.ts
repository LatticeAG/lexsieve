// Section 5: adapter extraction and serialization for native, MCP, and
// OpenAI surfaces. All pre-candidate failures are closed errors (no
// Decision, no receipt). The FailureEnvelope replaces the return on
// wire-level failures; it carries no tool bytes.

import { ClosedError } from './errors.ts';
import { jcs, parseJson, isObj, type JsonValue } from './jcs.ts';
import type { Candidate, DataEnvelope, TextBlock } from './schema.ts';
import { validateCandidate } from './schema.ts';

export const WIRE_CAP = 262144;
export const TEXT_CAP = 32768;
export const COMPLETION_TIMEOUT_MS = 5000;

export const FAILURE_ENVELOPE = {
  type: 'lexsieve.tool-unavailable.v1',
  trust: 'untrusted',
  notice: 'Tool result unavailable.',
} as const;

export function failureEnvelopeJson(): string {
  return jcs(FAILURE_ENVELOPE as unknown as JsonValue);
}

// Strict UTF-8 decode of wire bytes; invalid input -> INVALID_UTF8.
export function decodeWire(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new ClosedError('INVALID_UTF8', 'wire bytes not UTF-8');
  }
}

// --- native ---------------------------------------------------------------
// The native adapter receives the already-decoded text blocks from the host
// SDK, builds a Candidate with trusted metadata supplied by the caller.
export function nativeExtract(texts: string[]): TextBlock[] {
  const blocks: TextBlock[] = texts.map((text, index) => ({ index, text }));
  checkBlockBounds(blocks);
  return blocks;
}

export function checkBlockBounds(blocks: TextBlock[]): void {
  if (blocks.length < 1 || blocks.length > 8) throw new ClosedError('LIMIT', 'block count');
  let total = 0;
  for (const b of blocks) {
    const n = Buffer.byteLength(b.text, 'utf8');
    if (n > TEXT_CAP) throw new ClosedError('LIMIT', 'block size');
    total += n;
  }
  if (total > TEXT_CAP) throw new ClosedError('LIMIT', 'total size');
}

// --- MCP ------------------------------------------------------------------
// Accepts exactly content, optional structuredContent, optional isError,
// optional _meta at the result level.
export function mcpExtract(result: unknown): { blocks: TextBlock[]; toolError: boolean } {
  if (!isObj(result as JsonValue)) throw new ClosedError('UNSUPPORTED_CONTENT', 'mcp result');
  const o = result as Record<string, JsonValue>;
  for (const k of Object.keys(o)) {
    if (!['content', 'structuredContent', 'isError', '_meta'].includes(k)) {
      throw new ClosedError('UNSUPPORTED_CONTENT', `unexpected member ${k}`);
    }
  }
  if (!Object.prototype.hasOwnProperty.call(o, 'content')) {
    throw new ClosedError('UNSUPPORTED_CONTENT', 'missing content');
  }
  const isError = o['isError'];
  if (isError !== undefined && typeof isError !== 'boolean') {
    throw new ClosedError('UNSUPPORTED_CONTENT', 'isError not boolean');
  }
  const content = o['content'];
  if (!Array.isArray(content) || content.length < 1 || content.length > 8) {
    throw new ClosedError('UNSUPPORTED_CONTENT', 'content shape');
  }
  const texts: string[] = [];
  for (const item of content) {
    if (!isObj(item)) throw new ClosedError('UNSUPPORTED_CONTENT', 'content item');
    const keys = Object.keys(item).sort();
    if (keys.join(',') !== 'text,type') throw new ClosedError('UNSUPPORTED_CONTENT', 'content members');
    if (item['type'] !== 'text') throw new ClosedError('UNSUPPORTED_CONTENT', 'content type');
    if (typeof item['text'] !== 'string') throw new ClosedError('UNSUPPORTED_CONTENT', 'text type');
    texts.push(item['text']);
  }
  if (Object.prototype.hasOwnProperty.call(o, 'structuredContent')) {
    const sc = o['structuredContent'];
    if (!isObj(sc)) throw new ClosedError('UNSUPPORTED_CONTENT', 'structuredContent not object');
    // parsed under the embedded-JSON rules; becomes a final text block of its
    // JCS serialization
    texts.push(jcs(sc));
  }
  const blocks = texts.map((text, index) => ({ index, text }));
  try {
    checkBlockBounds(blocks);
  } catch (e) {
    if (e instanceof ClosedError && e.code === 'LIMIT') throw e;
    throw e;
  }
  return { blocks, toolError: isError === true };
}

// The MCP return serializer replaces the complete result; isError is true
// for tool_error or hold.
export function mcpSerialize(envelope: DataEnvelope, toolError: boolean): JsonValue {
  return {
    content: [{ type: 'text', text: jcs(envelope as unknown as JsonValue) }],
    isError: toolError || envelope.disposition === 'hold',
  };
}

export function mcpSerializeFailure(): JsonValue {
  return {
    content: [{ type: 'text', text: failureEnvelopeJson() }],
    isError: true,
  };
}

// --- OpenAI ---------------------------------------------------------------
export function openaiExtract(output: unknown): { blocks: TextBlock[]; toolError: false } {
  if (typeof output !== 'string') throw new ClosedError('UNSUPPORTED_CONTENT', 'output not string');
  const blocks = [{ index: 0, text: output }];
  checkBlockBounds(blocks);
  return { blocks, toolError: false };
}

export function openaiSerialize(envelope: DataEnvelope, toolCallId: string): JsonValue {
  return { role: 'tool', tool_call_id: toolCallId, content: jcs(envelope as unknown as JsonValue) };
}

export function openaiSerializeFailure(toolCallId: string): JsonValue {
  return { role: 'tool', tool_call_id: toolCallId, content: failureEnvelopeJson() };
}

// --- wire-cap framing (section 5.3) ----------------------------------------

// Validates raw wire bytes against the transport cap and UTF-8, then parses
// to JSON for the MCP adapter path. Returns the decoded text.
export function receiveWire(bytes: Uint8Array): string {
  if (bytes.length > WIRE_CAP) throw new ClosedError('LIMIT', 'wire cap');
  return decodeWire(bytes);
}
