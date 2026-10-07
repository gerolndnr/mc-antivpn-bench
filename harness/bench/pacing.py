"""How long the harness waits on a plugin (METHODOLOGY 7.1, "Pacing").

Detection keeps one Pacer per plugin and pass. The other families share one Pacer per plugin for the whole run
(`watch` / `observed`), so what a run learned about a plugin in one family carries into the next. A plugin whose
adapter declares `decides_after_join` (it admits first and kicks later) always gets the full window.
"""
import os

from . import products

OBSERVE_S = 8.0


def subject_interval_s():
    return float(os.environ.get('BENCH_SUBJECT_INTERVAL_S', '5'))


# Detection pacing (METHODOLOGY 7.1). "adaptive": every plugin walks the subjects on its own and learns how long to watch
# an admitted player for a late kick; "fixed": the full window and subject_interval_s() for everyone, as before 8 Oct.
PACING = os.environ.get('BENCH_DETECTION_PACING', 'adaptive')
OBSERVE_MIN_S = 1.5
CALIBRATION = 20
PROBE_EVERY = 10
INTERVAL_START_S, INTERVAL_MIN_S, INTERVAL_MAX_S = 2.0, 1.0, 10.0


class Pacer:
    """How long one plugin gets per subject.

    Watch window: an admitted player stays joined for a while so that a plugin that decides after the join (KauriVPN)
    can still kick them. The first CALIBRATION subjects and every PROBE_EVERY-th one get the full OBSERVE_S; otherwise the
    window is twice the latest kick after the join seen so far, at least OBSERVE_MIN_S. A probe that sees a later kick
    widens it from then on.
    Interval: starts at INTERVAL_START_S; a detection-service 429 or 5xx during the plugin's subject multiplies it by 1.5,
    20 clean subjects in a row divide it by 1.25, within INTERVAL_MIN_S..INTERVAL_MAX_S. A refused-at-login subject needs
    no window at all, so a plugin that decides at login moves on as soon as it has answered.
    """

    def __init__(self, fixed=False, always_full=False):
        self.fixed = fixed
        self.always_full = always_full
        self.count = 0
        self.latest_kick_s = 0.0
        self.kicks = 0
        self.interval = subject_interval_s() if fixed else INTERVAL_START_S
        self.clean = 0
        self.full_windows = 0
        self.observe_s = OBSERVE_S
        self.elapsed_s = 0.0

    def window(self, subject=None, full=None):
        """The watch window for the next admitted player; `full` is the call site's full window (default OBSERVE_S)."""
        full = OBSERVE_S if full is None else full
        self.count += 1
        if self.fixed or self.always_full or self.count <= CALIBRATION or self.count % PROBE_EVERY == 0:
            self.full_windows += 1
            return full
        return min(full, max(OBSERVE_MIN_S, 2 * self.latest_kick_s))

    def observe(self, result, window):
        marks = result.get('marks') or {}
        if result.get('outcome') == 'DENY_PLAY' and 'joined' in marks and 'decided' in marks:
            self.kicks += 1
            self.latest_kick_s = max(self.latest_kick_s, (marks['decided'] - marks['joined']) / 1000)
        if not self.fixed:
            self.observe_s = min(OBSERVE_S, max(OBSERVE_MIN_S, 2 * self.latest_kick_s))

    def after(self, errors):
        if self.fixed:
            return
        if errors:
            self.interval = min(INTERVAL_MAX_S, self.interval * 1.5)
            self.clean = 0
            return
        self.clean += 1
        if self.clean >= 20:
            self.interval = max(INTERVAL_MIN_S, self.interval / 1.25)
            self.clean = 0

    def summary(self):
        return dict(mode='fixed' if self.fixed else 'adaptive', observe_s=round(self.observe_s, 2),
                    latest_kick_after_join_s=round(self.latest_kick_s, 2), kicks_after_join=self.kicks,
                    full_windows=self.full_windows, subjects=self.count, final_interval_s=round(self.interval, 2),
                    elapsed_s=self.elapsed_s)




_shared = {}


def shared(product_id):
    """The run-wide Pacer of one plugin, for every family except detection."""
    if product_id not in _shared:
        try:
            late = bool(products.adapter(product_id).get('decides_after_join'))
        except (OSError, ValueError):
            late = False
        _shared[product_id] = Pacer(fixed=PACING == 'fixed', always_full=late)
    return _shared[product_id]


def watch(product_id, full):
    """Watch window for one admitted player of `product_id`, at most `full` seconds."""
    return shared(product_id).window(full=full)


def observed(product_id, result, window):
    shared(product_id).observe(result, window)
    return result


def summaries():
    return {pid: p.summary() for pid, p in _shared.items()}
