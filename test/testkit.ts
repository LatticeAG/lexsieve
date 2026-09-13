// Shared test-facing runtime builder over the exact section-19 fixtures.
import { Engine, type EngineDeps } from '../src/engine.ts';
import { MemorySink, type Sink } from '../src/sink.ts';
import { activatePack, configHashOf } from '../src/packs.ts';
import { StaticLexShield, STATIC_POLICY_HASH } from '../src/lexshield.ts';
import type { ScreenResponse } from '../src/schema.ts';
import { C0, CM0, I, P0, T0, letterAllocator, seed } from '../src/eval/fixture19.ts';
import { fakeClock } from './fixtures.ts';
import type { JsonValue } from '../src/jcs.ts';
import type { FakeClock } from './fixtures.ts';

export interface TestRuntime {
  engine: Engine;
  sink: Sink;
  clock: FakeClock;
}

export function buildRuntimeForTest(profile: 'R' | 'M', sink?: Sink): TestRuntime {
  const config = profile === 'M' ? CM0 : C0;
  const s = sink ?? new MemorySink();
  const clock = fakeClock(1000);
  s.open();
  activatePack(s, config, T0, P0, clock.now(), configHashOf(config), STATIC_POLICY_HASH);
  const deps: EngineDeps = {
    sink: s,
    clock,
    ids: letterAllocator(),
    lexshield: new StaticLexShield(),
    signer: { keyId: I('lskey', 'B'), seed },
  };
  return { engine: new Engine(config, deps), sink: s, clock };
}

export function runScreen(rt: TestRuntime, req: JsonValue): ScreenResponse {
  return rt.engine.screen(req);
}
