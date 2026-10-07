"""Provider score (METHODOLOGY 7.9), without dependencies: the README overview job imports it with bare Python."""


# Score (METHODOLOGY 7.9): 100 x (share caught - 3 x share of home and mobile players refused), minus 5 points per second
# of median answer time (at most 10), floored at 0. Unanswered addresses already count as not caught, so quotas and
# errors are inside "caught"; speed only breaks near-ties.
REFUSAL_WEIGHT = 3
SPEED_POINTS_PER_S = 5
SPEED_POINTS_MAX = 10


def score(s, caught=None, refused=None):
    """Score of one summary entry; `caught`/`refused` override the shares (for the 95 % range)."""
    r = s['caught'] / s['bad'] if caught is None and s['bad'] else (caught or 0)
    f = s['refused'] / s['good'] if refused is None and s['good'] else (refused or 0)
    speed = min(SPEED_POINTS_MAX, SPEED_POINTS_PER_S * (s.get('ms_p50') or 0) / 1000)
    return round(max(0.0, 100 * (r - REFUSAL_WEIGHT * f) - speed), 1)


def score_range(s):
    """95 % range from the Wilson intervals of both shares."""
    share = lambda k, n: k / n if n else 0
    caught = s.get('caught_ci') or [share(s['caught'], s['bad'])] * 2
    refused = s.get('refused_ci') or [share(s['refused'], s['good'])] * 2
    return [score(s, caught[0], refused[1]), score(s, caught[1], refused[0])]
