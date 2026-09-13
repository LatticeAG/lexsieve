"""Controllable clocks for the eval harness (spec 18): a wall/mono pair the
vectors advance to simulate stage overruns, and a scripted mono variant.
"""


class FakeClock:
    """`wall` is Unix ms (expiry, recorded_at); `mono` is the budget clock
    the harness advances to simulate stage overruns."""

    def __init__(self, wall=1700000100000, mono=0):
        self.wall = wall
        self.mono_v = mono

    def now(self):
        return self.wall

    def mono(self):
        return self.mono_v

    def advance_wall(self, ms):
        self.wall += ms

    def advance_mono(self, ms):
        self.mono_v += ms

    def set_wall(self, ms):
        self.wall = ms

    def set_mono(self, ms):
        self.mono_v = ms

    def get_wall(self):
        return self.wall

    def get_mono(self):
        return self.mono_v


def fake_clock(start=1700000100000):
    return FakeClock(wall=start, mono=0)


class ScriptedClock(FakeClock):
    """A clock whose mono() returns successive scripted values (clamping to
    the last). Used by budget vectors that pin per-stage durations."""

    def __init__(self, mono_values, wall=1000):
        super().__init__(wall=wall, mono=0)
        self.mono_values = list(mono_values)
        self.i = 0

    def mono(self):
        v = self.mono_values[min(self.i, len(self.mono_values) - 1)]
        self.i += 1
        return v

    def advance_mono(self, ms):
        cur = self.mono_values[min(max(self.i - 1, 0), len(self.mono_values) - 1)]
        self.mono_values[max(self.i - 1, 0)] = cur + ms

    def set_mono(self, ms):
        self.mono_values[max(self.i - 1, 0)] = ms

    def get_mono(self):
        return self.mono_values[min(max(self.i - 1, 0), len(self.mono_values) - 1)]


def scripted_clock(mono_values, wall=1000):
    return ScriptedClock(mono_values, wall)
