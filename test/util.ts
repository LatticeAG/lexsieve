// Structural JSON comparison (order-insensitive object members).
import { jcs, type JsonValue } from '../src/jcs.ts';

export function deepEqualJson(a: unknown, b: unknown): boolean {
  try {
    return jcs(a as JsonValue) === jcs(b as JsonValue);
  } catch {
    return false;
  }
}
