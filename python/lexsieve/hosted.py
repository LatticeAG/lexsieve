"""Section 8.2 hosted/paid surfaces. These are documented stubs only: the
hosted control plane, pack distribution service, and API transports are
part of LatticeAG's hosted product and are not implemented in the OSS
core. Each entry point fails closed with NotImplementedError and a link.

The pure validation logic behind the hosted surface (tenant-DO telemetry
ingest semantics, publisher verification rules) IS implemented in
telemetry.py and packs.py for conformance testing.
"""

from .errors import NotImplementedError

DOCS = "https://lexsieve.dev/docs/hosted"


class HostedApiClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token

    def pack_pull(self, _req=None):
        raise NotImplementedError(
            f"hosted pack pull is part of the LexSieve hosted service; see {DOCS}"
        )

    def telemetry_ingest(self, _req=None):
        raise NotImplementedError(
            f"hosted telemetry ingest is part of the LexSieve hosted service; see {DOCS}"
        )

    def receipt_get(self, _id=None):
        raise NotImplementedError(
            f"hosted receipt lookup is part of the LexSieve hosted service; see {DOCS}"
        )

    def decision_get(self, _id=None):
        raise NotImplementedError(
            f"hosted decision lookup is part of the LexSieve hosted service; see {DOCS}"
        )

    def pack_publish(self, _req=None):
        raise NotImplementedError(
            f"hosted pack publishing is part of the LexSieve hosted service; see {DOCS}"
        )
