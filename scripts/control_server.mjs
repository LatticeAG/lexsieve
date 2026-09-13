// Minimal control-socket daemon for smoke tests and embedder reference:
// serves `lexsieve reload` for one deployment directory.
// usage: node scripts/control_server.mjs <config-path>
import { dirname, resolve } from 'node:path';
import { startControlServer } from '../src/control.ts';
import { loadDeployment, resolvePath } from '../src/config.ts';
import { SqliteSink } from '../src/sqlite.ts';
import { verifyPack, activatePack, configHashOf } from '../src/packs.ts';
import { STATIC_POLICY_HASH } from '../src/lexshield.ts';
import { mkdirSync } from 'node:fs';

const configPath = resolve(process.argv[2]);
const configDir = dirname(configPath);

const server = startControlServer({
  socketPath: resolve(configDir, 'state/lexsieve-control.sock'),
  configDir,
  onReload: (p) => {
    try {
      return reloadOnce(p);
    } catch (e) {
      process.stderr.write(`reload failed: ${e && e.stack || e}\n`);
      throw e;
    }
  },
});

function reloadOnce(p) {
    const dep = loadDeployment(p);
    if (dep.config.receipt_sink.kind !== 'sqlite') throw new Error('unsupported sink');
    const sinkPath = resolvePath(p, dep.config.receipt_sink.path);
    mkdirSync(dirname(sinkPath), { recursive: true });
    const sink = new SqliteSink(sinkPath);
    try {
      sink.open();
      const v = verifyPack(dep.pack, dep.trust, Date.now());
      if (!v.valid) throw new Error(`pack: ${v.reason}`);
      return activatePack(sink, dep.config, dep.trust, dep.pack, Date.now(),
        configHashOf(dep.config), STATIC_POLICY_HASH);
    } finally {
      sink.close();
    }
}

server.on('listening', () => {
  process.stderr.write(`control socket ready\n`);
});
