// Controllable clocks for the eval harness (spec 18): a wall/mono pair the
// vectors advance to simulate stage overruns, and a scripted mono variant.

import type { Clock } from '../engine.ts';

// Controllable clock. `wall` is Unix ms (expiry, recorded_at); `mono` is the
// budget clock the harness advances to simulate stage overruns.
export interface FakeClock extends Clock {
  advanceWall(ms: number): void;
  advanceMono(ms: number): void;
  setWall(ms: number): void;
  setMono(ms: number): void;
  getWall(): number;
  getMono(): number;
}

export function fakeClock(start = 1700000100000): FakeClock {
  const state = { wall: start, mono: 0 };
  return {
    now: () => state.wall,
    mono: () => state.mono,
    advanceWall(ms: number) {
      state.wall += ms;
    },
    advanceMono(ms: number) {
      state.mono += ms;
    },
    setWall(ms: number) {
      state.wall = ms;
    },
    setMono(ms: number) {
      state.mono = ms;
    },
    getWall: () => state.wall,
    getMono: () => state.mono,
  };
}

// A clock whose mono() returns successive scripted values (clamping to the
// last). Used by budget vectors that pin per-stage durations.
export function scriptedClock(monoValues: number[], wall = 1000): FakeClock {
  const state = { wall, i: 0 };
  const next = () => {
    const v = monoValues[Math.min(state.i, monoValues.length - 1)]!;
    state.i++;
    return v;
  };
  return {
    now: () => state.wall,
    mono: next,
    advanceWall(ms: number) {
      state.wall += ms;
    },
    advanceMono(ms: number) {
      const cur = monoValues[Math.min(Math.max(state.i - 1, 0), monoValues.length - 1)]!;
      monoValues[Math.max(state.i - 1, 0)] = cur + ms;
    },
    setWall(ms: number) {
      state.wall = ms;
    },
    setMono(ms: number) {
      monoValues[Math.max(state.i - 1, 0)] = ms;
    },
    getWall: () => state.wall,
    getMono: () => monoValues[Math.min(Math.max(state.i - 1, 0), monoValues.length - 1)]!,
  };
}

