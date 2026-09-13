"""Section 7: the LexShield return-policy port. evaluate_return is an
in-process port called once per valid screening, including local holds.
The built-in static adapter accepts detector decisions while preserving
holds; its hash is pinned and its use is visible in the snapshot.
"""

from .crypto import sha256_hex
from .errors import ClosedError
from .schema import validate_policy_response

STATIC_POLICY_HASH = sha256_hex("LexSieve/static-policy/v1")


class StaticLexShield:
    """Explicit built-in static adapter: always allows; the engine's local
    holds are preserved by the monotonic merge in the policy stage."""

    policy_hash = STATIC_POLICY_HASH

    def evaluate_return(self, req):
        return {
            "v": 1,
            "policy_hash": STATIC_POLICY_HASH,
            "disposition": "allow",
            "reason": "POLICY_ALLOW",
        }


class AxionLexShield:
    """Axion LexShield binding: a host-installed in-process port. `binding`
    names the deployment binding; the host supplies the callable at
    construction. This adapter never manufactures a policy result itself."""

    def __init__(self, binding, pinned_policy_hash, impl):
        self.binding = binding
        self.policy_hash = pinned_policy_hash
        self._impl = impl

    def evaluate_return(self, req):
        return validate_policy_response(self._impl(req))


def missing_lexshield_binding(binding):
    """A LexShield that must exist for `kind:"axion"` but is absent is a
    readiness failure, not a fallback — the caller wires the real binding."""
    raise ClosedError("NOT_READY", f"lexshield binding {binding} not installed")
