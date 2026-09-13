// Section 8.2 hosted/paid surfaces. These are documented stubs only: the
// hosted control plane, pack distribution service, and API transports are
// part of LatticeAG's hosted product and are not implemented in the OSS
// core. Each entry point fails closed with NotImplementedError and a link.
//
// The pure validation logic behind the hosted surface (tenant-DO telemetry
// ingest semantics, publisher verification rules) IS implemented in
// src/telemetry.ts and src/packs.ts for conformance testing.

import { NotImplementedError } from './errors.ts';

const DOCS = 'https://lexsieve.dev/docs/hosted';

export class HostedApiClient {
  readonly baseUrl: string;
  readonly token: string;
  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  // POST /v1/packs/pull — hosted pack distribution.
  packPull(_req: unknown): never {
    throw new NotImplementedError(
      `hosted pack pull is part of the LexSieve hosted service; see ${DOCS}`,
    );
  }

  // POST /v1/telemetry — hosted telemetry ingest transport.
  telemetryIngest(_req: unknown): never {
    throw new NotImplementedError(
      `hosted telemetry ingest is part of the LexSieve hosted service; see ${DOCS}`,
    );
  }

  // GET /v1/receipts/:id — hosted receipt lookup.
  receiptGet(_id: string): never {
    throw new NotImplementedError(
      `hosted receipt lookup is part of the LexSieve hosted service; see ${DOCS}`,
    );
  }

  // GET /v1/decisions/:id — hosted decision lookup.
  decisionGet(_id: string): never {
    throw new NotImplementedError(
      `hosted decision lookup is part of the LexSieve hosted service; see ${DOCS}`,
    );
  }

  // POST /v1/packs — hosted pack publishing.
  packPublish(_req: unknown): never {
    throw new NotImplementedError(
      `hosted pack publishing is part of the LexSieve hosted service; see ${DOCS}`,
    );
  }
}
