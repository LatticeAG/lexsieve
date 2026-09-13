// Section 7: the LexShield return-policy port. evaluateReturn is an
// in-process port called once per valid screening, including local holds.
// The built-in static adapter accepts detector decisions while preserving
// holds; its hash is pinned and its use is visible in the snapshot.

import { ClosedError } from './errors.ts';
import { sha256Hex } from './crypto.ts';
import { validatePolicyResponse, type PolicyRequest, type PolicyResponse } from './schema.ts';

export const STATIC_POLICY_HASH = sha256Hex('LexSieve/static-policy/v1');

export interface LexShieldPort {
  policyHash: string;
  evaluateReturn(req: PolicyRequest): PolicyResponse;
}

// Explicit built-in static adapter: always allows; the engine's local holds
// are preserved by the monotonic merge in the policy stage.
export class StaticLexShield implements LexShieldPort {
  readonly policyHash = STATIC_POLICY_HASH;
  evaluateReturn(_req: PolicyRequest): PolicyResponse {
    return { v: 1, policy_hash: STATIC_POLICY_HASH, disposition: 'allow', reason: 'POLICY_ALLOW' };
  }
}

// Axion LexShield binding: a host-installed in-process port. `binding` names
// the deployment binding; the host supplies the callable at construction.
// This adapter never manufactures a policy result itself.
export class AxionLexShield implements LexShieldPort {
  readonly policyHash: string;
  readonly binding: string;
  private readonly impl: (req: PolicyRequest) => PolicyResponse;
  constructor(binding: string, pinnedPolicyHash: string, impl: (req: PolicyRequest) => PolicyResponse) {
    this.binding = binding;
    this.policyHash = pinnedPolicyHash;
    this.impl = impl;
  }
  evaluateReturn(req: PolicyRequest): PolicyResponse {
    const resp = this.impl(req);
    return validatePolicyResponse(resp);
  }
}

// A LexShield that must exist for `kind:"axion"` but is absent is a
// readiness failure, not a fallback — the caller wires the real binding.
export function missingLexShieldBinding(binding: string): never {
  throw new ClosedError('NOT_READY', `lexshield binding ${binding} not installed`);
}
