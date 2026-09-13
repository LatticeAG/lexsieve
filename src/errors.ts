// Error codes and the two failure layers.
//
// Closed errors (ClosedError) are raised before a valid Candidate exists or
// when the engine cannot produce a signed Decision; they produce no receipt.
// Hold reasons are committed Decision verdicts. Some names are shared between
// the layers (LIMIT, UNSUPPORTED_CONTENT, INVALID_UTF8, DEADLINE); the layers
// are distinguished by whether a committed Decision exists.

export type ErrorCode =
  | 'INVALID_REQUEST'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'STALE_POLICY'
  | 'NOT_READY'
  | 'RATE_LIMITED'
  | 'BAD_SIGNATURE'
  | 'CHAIN_GAP'
  | 'STORAGE_UNAVAILABLE'
  | 'UNSUPPORTED_VERSION'
  | 'DEADLINE'
  | 'INTERNAL';

// Closed adapter/extraction errors share names with hold reasons where the
// failure class is identical.
export type ClosedErrorCode = ErrorCode | 'LIMIT' | 'UNSUPPORTED_CONTENT' | 'INVALID_UTF8' | 'FINDING_LIMIT';

const RETRYABLE = new Set<ErrorCode | string>([
  'NOT_READY',
  'RATE_LIMITED',
  'CHAIN_GAP',
  'STORAGE_UNAVAILABLE',
  'DEADLINE',
]);

export class ClosedError extends Error {
  readonly code: ClosedErrorCode;
  readonly retryable: boolean;

  constructor(code: ClosedErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'ClosedError';
    this.code = code;
    this.retryable = RETRYABLE.has(code);
  }
}

// Hosted/paid surfaces that are outside the OSS core fail with this type.
// Distinct from ClosedError: it is not an RPC-layer error code but an
// explicit non-implementation boundary (spec 8.2).
export class NotImplementedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotImplementedError';
  }
}

export function rpcError(code: ErrorCode | ClosedErrorCode, requestId: string): {
  v: 1;
  error: { code: string; retryable: boolean; request_id: string };
} {
  return {
    v: 1,
    error: { code, retryable: RETRYABLE.has(code), request_id: requestId },
  };
}
