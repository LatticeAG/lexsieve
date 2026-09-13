// Locked ID prefixes for protocol 1 and suffix generation.
// Every ID is `<prefix>_` + 21 nanoid characters from [A-Za-z0-9_-].
// IDs are correlation labels, not bearer capabilities; case-sensitive compare.

import { nanoid21 } from './crypto.ts';
import { ClosedError } from './errors.ts';

export const ID_PREFIXES = [
  'lsreq', 'lsres', 'lsdec', 'lsrcp', 'lsq',
  'lsten', 'lsgw', 'lsrun', 'lscall', 'lspack', 'lskey', 'lsbatch',
] as const;

export type IdPrefix = (typeof ID_PREFIXES)[number];

const SUFFIX_RE = /^[A-Za-z0-9_-]{21}$/;

export function isValidId(prefix: IdPrefix, id: unknown): id is string {
  return (
    typeof id === 'string' &&
    id.startsWith(prefix + '_') &&
    SUFFIX_RE.test(id.slice(prefix.length + 1))
  );
}

export function requireId(prefix: IdPrefix, id: unknown, what: string): string {
  if (!isValidId(prefix, id)) throw new ClosedError('INVALID_REQUEST', `bad ${what} id`);
  return id;
}

// Sequential ID allocator interface. Production uses the CSPRNG allocator;
// the conformance harness injects the fixed fixture allocator (A, B, C ...).
export interface IdAllocator {
  next(prefix: IdPrefix): string;
}

export function csprngAllocator(): IdAllocator {
  return { next: (prefix) => `${prefix}_${nanoid21()}` };
}
