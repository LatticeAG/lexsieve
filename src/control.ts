// Local control socket (spec 12): an owner-only Unix domain socket next to
// the SQLite receipt database. One JCS request per connection of at most
// 16384 bytes, one JCS response, then close; connections expire after
// 5000 ms and reload calls are processed serially.
//
// Peer-UID equality is enforced by filesystem ownership: the socket file is
// created mode 0600 owned by the service uid, and the socket directory is
// expected to be operator-controlled. Node cannot read SO_PEERCRED without a
// native addon; embedding hosts on Linux SHOULD additionally verify peer
// credentials through their own channel.

import { createServer, type Server, type Socket } from 'node:net';
import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { isAbsolute, resolve, sep } from 'node:path';
import { jcs, parseJson, type JsonValue } from './jcs.ts';
import { ClosedError } from './errors.ts';
import { csprngAllocator } from './ids.ts';

export const CONTROL_MAX_REQUEST_BYTES = 16384;
export const CONTROL_CONN_TIMEOUT_MS = 5000;

export interface ControlRequest {
  v: 1;
  command: 'reload';
  config_path: string;
}

export type RpcErrorBody = { v: 1; error: { code: string; retryable: boolean; request_id: string } };

const RETRYABLE = new Set(['NOT_READY', 'RATE_LIMITED', 'CHAIN_GAP', 'STORAGE_UNAVAILABLE', 'DEADLINE']);

export function rpcError(code: string, ids = csprngAllocator()): RpcErrorBody {
  return { v: 1, error: { code, retryable: RETRYABLE.has(code), request_id: ids.next('lsreq') } };
}

function validateControlRequest(v: unknown): ControlRequest {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new ClosedError('INVALID_REQUEST', 'control request');
  }
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 3 || o['v'] !== 1 || o['command'] !== 'reload' || typeof o['config_path'] !== 'string') {
    throw new ClosedError('INVALID_REQUEST', 'control request');
  }
  return { v: 1, command: 'reload', config_path: o['config_path'] };
}

export interface ControlServerOptions {
  socketPath: string;
  // Directory the socket may accept config paths under (startup-approved).
  configDir: string;
  // Performs the reload; returns the new active epoch.
  onReload: (configPath: string) => number;
  ids?: ReturnType<typeof csprngAllocator>;
}

export function startControlServer(opts: ControlServerOptions): Server {
  const ids = opts.ids ?? csprngAllocator();
  const approved = resolve(opts.configDir);
  if (existsSync(opts.socketPath)) unlinkSync(opts.socketPath);

  let chain: Promise<void> = Promise.resolve();

  // allowHalfOpen: the client signals end-of-request with FIN (conn.end);
  // the writable side must stay open until we have written the response.
  const server = createServer({ allowHalfOpen: true }, (conn: Socket) => {
    conn.setTimeout(CONTROL_CONN_TIMEOUT_MS);
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;

    const reply = (body: JsonValue) => {
      if (done) return;
      done = true;
      conn.end(jcs(body) + '\n');
    };

    const handle = () => {
      if (done) return;
      let req: ControlRequest;
      try {
        req = validateControlRequest(parseJson(Buffer.concat(chunks).toString('utf8').trimEnd()));
      } catch (e) {
        reply(rpcError(e instanceof ClosedError ? e.code : 'INVALID_REQUEST', ids));
        return;
      }
      chain = chain.then(() => {
        try {
          const p = resolve(req.config_path);
          if (!isAbsolute(req.config_path) || (p !== approved && !p.startsWith(approved + sep))) {
            reply(rpcError('FORBIDDEN', ids));
            return;
          }
          const epoch = opts.onReload(p);
          reply({ v: 1, active_epoch: epoch });
        } catch (e) {
          reply(rpcError(e instanceof ClosedError ? e.code : 'INTERNAL', ids));
        }
      });
    };

    conn.on('data', (d: Buffer) => {
      if (done) return;
      total += d.length;
      if (total > CONTROL_MAX_REQUEST_BYTES) {
        reply(rpcError('INVALID_REQUEST', ids));
        return;
      }
      chunks.push(d);
    });
    conn.on('end', handle);
    conn.on('timeout', () => {
      reply(rpcError('DEADLINE', ids));
    });
    conn.on('error', () => conn.destroy());
  });

  server.listen(opts.socketPath, () => chmodSync(opts.socketPath, 0o600));
  return server;
}
