"""
ctfd_anti_cheat.detectors
============================

Every detection heuristic lives here as a function with the signature:

    def detect_<name>() -> list[dict]

Each function returns a list of "event dicts" that the runner persists into
`cm_suspicion_events`. Keeping detectors as plain functions (not classes) makes
them trivial to test in isolation and trivial to disable — the runner skips any
detector whose `enabled.<name>` config flag is "0".

To add a new detector
---------------------
1. Write `def detect_my_thing() -> list[dict]` returning event dicts shaped
   like:
       {
         "detector": "my_thing",
         "user_id": <int>,
         "team_id": <int or None>,
         "related_user_id": <int or None>,
         "challenge_id": <int or None>,
         "severity": <0-100>,
         "detail": "<human readable>",
         "occurred_at": <datetime>,
       }
2. Add it to the DETECTORS dict at the bottom of this file.
3. Add `enabled.my_thing` and any threshold keys to utils.DEFAULTS.

That's it — the runner, the score aggregation, and the UI tables pick it up
automatically.
"""

import math
import statistics
from collections import Counter, defaultdict
from datetime import timedelta

from . import queries as Q
from .utils import cfg_bool, cfg_int, cfg_float, cfg, fingerprint, ip_subnet, geo_lookup
from .models import CMUserAgentLog


# ===========================================================================
#  1. Near-simultaneous solves
# ===========================================================================
def detect_simultaneous():
    """Flag sharing via temporal proximity — tiered confidence:
      < simul.high_conf_sec  (default 30s)  → High confidence, severity 80
      < simul.med_conf_sec   (default 120s) → Medium confidence, severity 55
      < simul.low_conf_sec   (default 300s) → Low signal (monitor), severity 30
    Severity is further raised when the second solver had zero prior fails.
    """
    high_sec  = cfg_int("simul.high_conf_sec", 30)
    med_sec   = cfg_int("simul.med_conf_sec",  120)
    low_sec   = cfg_int("simul.low_conf_sec",  300)
    fails     = Q.fails_per_user_challenge()
    c_names   = Q.challenge_name_map()
    events    = []

    for cid, solves in Q.solves_per_challenge().items():
        chall_name = c_names.get(cid, f"#{cid}")
        for i, a in enumerate(solves):
            for b in solves[i + 1:]:
                delta = (b.date - a.date).total_seconds()
                if delta > low_sec:
                    break
                if delta <= high_sec:
                    base_sev = 80
                    conf     = "HIGH"
                elif delta <= med_sec:
                    base_sev = 55
                    conf     = "MEDIUM"
                else:
                    base_sev = 30
                    conf     = "LOW"
                b_fails   = fails.get((b.user_id, cid), 0)
                zero_fail_boost = 15 if b_fails == 0 else 0
                events.append({
                    "detector": "simultaneous",
                    "user_id": b.user_id,
                    "related_user_id": a.user_id,
                    "challenge_id": cid,
                    "severity": min(base_sev + zero_fail_boost, 100),
                    "detail": (
                        f"[{conf}] '{chall_name}' solved {int(delta)}s after "
                        f"user #{a.user_id} "
                        f"({'0 prior fails — direct flag copy likely' if b_fails == 0 else f'{b_fails} prior fail(s)'})"
                    ),
                    "occurred_at": b.date,
                })
    return events


# ===========================================================================
#  2. Mass solves after first blood
# ===========================================================================
def detect_mass_after_first_blood():
    """A user solves N+ challenges suspiciously quickly *after* someone else
    drew first blood — pattern consistent with riding shared flags.

    'Suspiciously quickly' = solve happened within `ratio_pct` of the time
    that first-blood took relative to challenge release / earliest interaction.
    Since CTFd doesn't track per-user "first viewed" time, we use the spread
    between first-blood and the median solver as the baseline."""
    ratio = cfg_float("mass_fb.ratio_pct", 20.0) / 100.0
    min_count = cfg_int("mass_fb.min_chall_count", 3)
    sev = cfg_int("mass_fb.severity", 50)

    suspect_solves = defaultdict(list)  # user_id -> [(cid, delta_sec)]
    for cid, solves in Q.solves_per_challenge().items():
        if len(solves) < 3:
            continue
        fb = solves[0]
        # Median time from first blood to the rest of the solvers
        deltas = [(s.date - fb.date).total_seconds() for s in solves[1:]]
        try:
            median = statistics.median(deltas)
        except statistics.StatisticsError:
            continue
        if median <= 0:
            continue
        threshold = median * ratio
        for s in solves[1:]:
            d = (s.date - fb.date).total_seconds()
            if d <= threshold:
                suspect_solves[s.user_id].append((cid, d, median))

    events = []
    for uid, hits in suspect_solves.items():
        if len(hits) >= min_count:
            detail = (f"{len(hits)} solves within {int(ratio*100)}% of FB→median time: "
                      + ", ".join(f"#{c}({int(d)}s vs med {int(m)}s)" for c, d, m in hits[:6]))
            events.append({
                "detector": "mass_after_first_blood",
                "user_id": uid,
                "challenge_id": None,
                "severity": min(sev + 5 * (len(hits) - min_count), 100),
                "detail": detail,
                "occurred_at": None,
            })
    return events


# ===========================================================================
#  3. First-try solves on difficult/rare challenges
# ===========================================================================
def detect_first_try_rare():
    """User's first submission on a low-solver-count challenge was correct
    (zero failed attempts before the solve). Legit on easy challs, suspicious
    on rare ones — especially clustered across multiple rare challs for the
    same user."""
    max_solvers = cfg_int("rare.max_solver_count", 5)
    sev = cfg_int("rare.severity", 35)
    fails = Q.fails_per_user_challenge()
    counts = Q.solver_counts()

    per_user = defaultdict(list)
    for cid, solves in Q.solves_per_challenge().items():
        if counts.get(cid, 0) > max_solvers:
            continue
        for s in solves:
            if fails.get((s.user_id, cid), 0) == 0:
                per_user[s.user_id].append((cid, s.date, counts.get(cid, 0)))

    events = []
    for uid, hits in per_user.items():
        # One rare clean solve is plausible. Two+ starts to need explaining.
        if len(hits) >= 2:
            severity = min(sev + 10 * (len(hits) - 1), 100)
            detail = (f"{len(hits)} rare-challenge first-try solves: "
                      + ", ".join(f"#{c}(solvers={n})" for c, _, n in hits[:6]))
            events.append({
                "detector": "first_try_rare",
                "user_id": uid,
                "challenge_id": hits[0][0],
                "severity": severity,
                "detail": detail,
                "occurred_at": hits[0][1],
            })
        elif len(hits) == 1:
            cid, dt, n = hits[0]
            # Only report a single hit if the challenge had <=2 solvers total
            if n <= 2:
                events.append({
                    "detector": "first_try_rare",
                    "user_id": uid,
                    "challenge_id": cid,
                    "severity": sev,
                    "detail": f"First-try solve on chall #{cid} ({n} total solvers, 0 prior fails)",
                    "occurred_at": dt,
                })
    return events


# ===========================================================================
#  4. IP / User-Agent overlap
# ===========================================================================
def detect_ip_ua_overlap():
    """N+ distinct accounts share the same IP (and UA if logged). The most
    common false positive is shared NAT — corporate office, university lab,
    family home. We surface both the IP and the /24 subnet to help admins
    distinguish 'same household' from 'same person, multiple accounts'."""
    min_accounts = cfg_int("overlap.min_accounts", 2)
    sev = cfg_int("overlap.severity", 45)
    events = []

    # IP exact match
    for ip, uids in Q.users_per_ip().items():
        if len(uids) >= min_accounts:
            uid_list = sorted(uids)
            for uid in uid_list:
                others = [u for u in uid_list if u != uid]
                events.append({
                    "detector": "ip_ua_overlap",
                    "user_id": uid,
                    "related_user_id": others[0] if others else None,
                    "challenge_id": None,
                    "severity": sev,
                    "detail": (f"IP {ip} shared with {len(others)} other account(s): "
                               + ", ".join(f"#{u}" for u in others[:8])),
                    "occurred_at": None,
                })

    # Optional UA exact match (only if forward-looking UA capture is enabled
    # AND we actually have rows)
    ua_rows = CMUserAgentLog.query.all()
    if ua_rows:
        by_fp = defaultdict(set)
        for r in ua_rows:
            by_fp[r.fingerprint].add(r.user_id)
        for fp, uids in by_fp.items():
            if len(uids) >= min_accounts:
                uid_list = sorted(uids)
                for uid in uid_list:
                    others = [u for u in uid_list if u != uid]
                    events.append({
                        "detector": "ip_ua_overlap",
                        "user_id": uid,
                        "related_user_id": others[0] if others else None,
                        "challenge_id": None,
                        # Same IP *and* UA is materially stronger than IP alone
                        "severity": min(sev + 15, 100),
                        "detail": (f"IP+UA fingerprint shared with {len(others)} "
                                   f"other account(s) (fp:{fp[:10]}…)"),
                        "occurred_at": None,
                    })
    return events


# ===========================================================================
#  5. Solve pattern correlation
# ===========================================================================
def detect_solve_correlation():
    """Two users solve a large overlapping set of challenges in nearly the
    same order. Pure overlap isn't suspicious (everyone solves the easy ones);
    *order* overlap on a large set is. We use Kendall-tau-style agreement on
    the shared subset, implemented with stdlib only."""
    min_shared = cfg_int("corr.min_shared_solves", 5)
    min_pct = cfg_float("corr.order_match_pct", 80.0)
    sev = cfg_int("corr.severity", 55)

    solves = Q.solves_per_user()
    # Build {user_id: {chall_id: rank}}
    rank = {}
    for uid, sl in solves.items():
        rank[uid] = {s.challenge_id: i for i, s in enumerate(sl)}

    events = []
    uids = sorted(rank.keys())
    for i, a in enumerate(uids):
        for b in uids[i + 1:]:
            shared = set(rank[a]) & set(rank[b])
            if len(shared) < min_shared:
                continue
            shared = list(shared)
            # Count concordant pairs (i,j) where a's order matches b's order
            concordant = 0
            total = 0
            for x in range(len(shared)):
                for y in range(x + 1, len(shared)):
                    cx, cy = shared[x], shared[y]
                    ax, ay = rank[a][cx], rank[a][cy]
                    bx, by = rank[b][cx], rank[b][cy]
                    if (ax - ay) * (bx - by) > 0:
                        concordant += 1
                    total += 1
            if total == 0:
                continue
            pct = 100.0 * concordant / total
            if pct >= min_pct:
                events.append({
                    "detector": "solve_correlation",
                    "user_id": a,
                    "related_user_id": b,
                    "challenge_id": None,
                    "severity": min(sev + int((pct - min_pct) / 2), 100),
                    "detail": (f"Solve-order correlation with user #{b}: "
                               f"{pct:.1f}% concordant on {len(shared)} shared solves"),
                    "occurred_at": None,
                })
    return events


# ===========================================================================
#  6. Velocity anomaly (extra heuristic)
# ===========================================================================
def detect_velocity():
    """Per-user solve rate (solves per minute over their active window) that
    is `velocity.zscore` std-devs above the cohort mean. Cleanly captures
    'one user solving 15 challenges in 10 minutes while everyone else takes
    hours' without hard-coding a 'too fast' constant."""
    z_threshold = cfg_float("velocity.zscore", 3.0)
    min_solves = cfg_int("velocity.min_solves", 5)
    sev = cfg_int("velocity.severity", 30)

    rates = []
    per_user_rate = {}
    for uid, sl in Q.solves_per_user().items():
        if len(sl) < min_solves:
            continue
        span = (sl[-1].date - sl[0].date).total_seconds() / 60.0
        if span <= 0:
            continue
        r = len(sl) / span
        rates.append(r)
        per_user_rate[uid] = (r, sl)

    if len(rates) < 3:
        return []
    mean = statistics.mean(rates)
    stdev = statistics.pstdev(rates) or 1e-9

    events = []
    for uid, (r, sl) in per_user_rate.items():
        z = (r - mean) / stdev
        if z >= z_threshold:
            events.append({
                "detector": "velocity",
                "user_id": uid,
                "challenge_id": None,
                "severity": min(sev + int((z - z_threshold) * 10), 100),
                "detail": (f"{len(sl)} solves at {r:.2f}/min "
                           f"(cohort mean {mean:.2f}, z={z:.2f})"),
                "occurred_at": sl[0].date,
            })
    return events


# ===========================================================================
#  7. Identical wrong-flag submissions (extra heuristic)
# ===========================================================================
def detect_identical_wrong():
    """The same wrong flag string submitted by 2+ users. Strongest "writeup
    being shared in a Discord right now" signal we have — even legitimate
    users rarely independently arrive at the *same wrong answer*."""
    min_users = cfg_int("wrong.min_users", 2)
    sev = cfg_int("wrong.severity", 40)
    events = []

    for provided, hits in Q.fails_by_provided().items():
        users = {uid for uid, _, _ in hits}
        if len(users) < min_users:
            continue
        # Single-character or trivially-short strings are noise (e.g. "a", "1")
        if len(provided) < 4:
            continue
        # Common easy-mode noise like "flag{}", "test", "asdf" — let the admin
        # see them but at lower severity by ignoring submissions that span
        # >10 challenges (suggests a copy-paste habit, not collusion).
        challs = {cid for _, cid, _ in hits}
        if len(challs) > 10:
            continue
        for uid in users:
            others = sorted(users - {uid})
            events.append({
                "detector": "identical_wrong",
                "user_id": uid,
                "related_user_id": others[0] if others else None,
                "challenge_id": next(iter(challs)),
                "severity": min(sev + 5 * (len(users) - min_users), 100),
                "detail": (f"Submitted identical wrong flag {provided!r} also tried by "
                           f"{len(others)} other user(s): "
                           + ", ".join(f"#{u}" for u in others[:6])),
                "occurred_at": hits[0][2],
            })
    return events


# ===========================================================================
#  8. Brute-force pattern (extra heuristic)
# ===========================================================================
def detect_brute_force():
    """N+ failed attempts on the same challenge within a short window.
    On its own this is just "trying hard", but combined with a correct solve
    immediately after, it can indicate flag-format brute forcing rather than
    legitimate problem solving — and combined with *no* eventual solve it can
    indicate scripted poking that admins may want to ban regardless."""
    window = cfg_int("brute.window_sec", 120)
    threshold = cfg_int("brute.failures", 30)
    sev = cfg_int("brute.severity", 25)

    # Group fails by (user, chall)
    grouped = defaultdict(list)
    for uid, cid, ip, dt, typ, prov in Q.submissions_with_ip():
        if typ == "incorrect":
            grouped[(uid, cid)].append(dt)

    events = []
    for (uid, cid), times in grouped.items():
        if len(times) < threshold:
            continue
        times.sort()
        # Sliding window
        for i in range(len(times) - threshold + 1):
            span = (times[i + threshold - 1] - times[i]).total_seconds()
            if span <= window:
                events.append({
                    "detector": "brute_force",
                    "user_id": uid,
                    "challenge_id": cid,
                    "severity": sev,
                    "detail": (f"{threshold}+ failed submissions on chall #{cid} "
                               f"within {int(span)}s (window={window}s)"),
                    "occurred_at": times[i],
                })
                break  # one event per (user, chall) is enough
    return events


# ===========================================================================
#  9. Dormant account burst (extra heuristic)
# ===========================================================================
def detect_dormant_burst():
    """Account quiet for `silent_hours`, then K solves inside `burst_window_min`.
    Captures both 'sleeper handles activated near the end' and 'someone handed
    over their credentials to a stronger friend.'"""
    silent = cfg_int("dormant.silent_hours", 12) * 3600
    burst_count = cfg_int("dormant.burst_count", 5)
    burst_window = cfg_int("dormant.burst_window_min", 30) * 60
    sev = cfg_int("dormant.severity", 30)

    events = []
    for uid, sl in Q.solves_per_user().items():
        if len(sl) < burst_count:
            continue
        for i in range(len(sl) - burst_count + 1):
            window_solves = sl[i:i + burst_count]
            window_span = (window_solves[-1].date - window_solves[0].date).total_seconds()
            if window_span > burst_window:
                continue
            # Was there a `silent` gap immediately before the burst?
            if i == 0:
                # First-ever activity — qualifies if user existed long before
                # but had no solves. Conservative: require i>0.
                continue
            gap = (window_solves[0].date - sl[i - 1].date).total_seconds()
            if gap >= silent:
                events.append({
                    "detector": "dormant_burst",
                    "user_id": uid,
                    "challenge_id": None,
                    "severity": sev,
                    "detail": (f"{burst_count} solves in {int(window_span/60)}min "
                               f"after {int(gap/3600)}h of silence"),
                    "occurred_at": window_solves[0].date,
                })
                break  # one report per user is enough
    return events


# ===========================================================================
# 10. Session swap (same IP+UA, different account, short window)
# ===========================================================================
def detect_session_swap():
    """Same fingerprint (IP+UA) used by two different users within
    `swap.window_sec`. The classic 'pass the laptop' pattern. Falls back to
    IP-only when the UA log isn't populated."""
    window = cfg_int("swap.window_sec", 300)
    sev = cfg_int("swap.severity", 50)
    events = []

    ua_rows = CMUserAgentLog.query.order_by(CMUserAgentLog.seen_at.asc()).all()
    if ua_rows:
        by_fp = defaultdict(list)
        for r in ua_rows:
            by_fp[r.fingerprint].append((r.user_id, r.seen_at))
        for fp, hits in by_fp.items():
            for i in range(len(hits) - 1):
                u1, t1 = hits[i]
                u2, t2 = hits[i + 1]
                if u1 != u2 and (t2 - t1).total_seconds() <= window:
                    events.append({
                        "detector": "session_swap",
                        "user_id": u2,
                        "related_user_id": u1,
                        "challenge_id": None,
                        "severity": sev,
                        "detail": (f"Account #{u2} reused fingerprint {fp[:10]}… "
                                   f"from account #{u1} after {int((t2-t1).total_seconds())}s"),
                        "occurred_at": t2,
                    })
        return events

    # IP-only fallback using Tracking rows
    by_ip = defaultdict(list)
    for uid, ip, dt in Q.tracking_rows():
        if ip and dt:
            by_ip[ip].append((uid, dt))
    for ip, hits in by_ip.items():
        hits.sort(key=lambda x: x[1])
        for i in range(len(hits) - 1):
            u1, t1 = hits[i]
            u2, t2 = hits[i + 1]
            if u1 != u2 and (t2 - t1).total_seconds() <= window:
                events.append({
                    "detector": "session_swap",
                    "user_id": u2,
                    "related_user_id": u1,
                    "challenge_id": None,
                    "severity": max(sev - 10, 10),  # IP-only is weaker than IP+UA
                    "detail": (f"IP {ip} switched from account #{u1} to #{u2} "
                               f"in {int((t2-t1).total_seconds())}s (IP-only match)"),
                    "occurred_at": t2,
                })
    return events


# ===========================================================================
# 11. Shared correct-submission IP
# ===========================================================================
def detect_shared_correct_ip():
    """Multiple distinct accounts submit a correct flag for the same challenge
    from the same IP address. This is one of the strongest possible collusion
    signals — the same device physically submitted winning answers for two or
    more different accounts."""
    sev = cfg_int("shared_ip.severity", 80)

    by_ip_chall = defaultdict(set)
    for uid, cid, ip, dt, typ, prov in Q.submissions_with_ip():
        if typ == "correct" and ip:
            by_ip_chall[(ip, cid)].add(uid)

    events = []
    for (ip, cid), uids in by_ip_chall.items():
        if len(uids) < 2:
            continue
        uid_list = sorted(uids)
        for uid in uid_list:
            others = [u for u in uid_list if u != uid]
            events.append({
                "detector": "shared_correct_ip",
                "user_id": uid,
                "related_user_id": others[0] if others else None,
                "challenge_id": cid,
                "severity": min(sev + 5 * (len(others) - 1), 100),
                "detail": (f"Correct submission for chall #{cid} from same IP {ip} "
                           f"as {len(others)} other account(s): "
                           + ", ".join(f"#{u}" for u in others[:6])),
                "occurred_at": None,
            })
    return events


# ===========================================================================
# 11b. First solver on high-value challenge with no prior failed attempts
# ===========================================================================
def detect_first_solver_high_value():
    """Flag users who were the FIRST to solve a high-value challenge AND had
    zero failed attempts before the correct flag.  Knowing the answer immediately
    on a hard/valuable challenge — with no trial-and-error — is a strong signal
    of flag leakage or inside knowledge.

    Config:
      first_solver.min_value   — minimum challenge point value to consider (default 300)
      first_solver.severity    — base severity per qualifying solve (default 65)
      first_solver.accumulate  — "1" = severity grows with number of such solves (default 1)
    """
    min_val  = cfg_int("first_solver.min_value", 300)
    base_sev = cfg_int("first_solver.severity", 65)
    accumulate = cfg_bool("first_solver.accumulate", True)

    # High-value challenges
    high_val_challs = {
        c.id: c.value
        for c in Challenges.query.filter(Challenges.value >= min_val).all()
    }
    if not high_val_challs:
        return []

    events = []
    for chall_id, chall_value in high_val_challs.items():
        # Who was the first solver?
        first_solve = (
            Solves.query
            .filter_by(challenge_id=chall_id)
            .order_by(Solves.date.asc())
            .first()
        )
        if not first_solve:
            continue

        uid = first_solve.user_id

        # Did they have ANY failed attempts before their correct solve?
        fail_count = (
            Fails.query
            .filter_by(user_id=uid, challenge_id=chall_id)
            .filter(Fails.date < first_solve.date)
            .count()
        )
        if fail_count > 0:
            continue  # They struggled — not suspicious

        # Suspicious: first blood + zero prior failures
        events.append({
            "detector": "first_solver_high_value",
            "user_id": uid,
            "challenge_id": chall_id,
            "severity": base_sev,
            "detail": (
                f"First solver on '{chall_id}' (value {chall_value} pts) "
                f"with 0 failed attempts — immediate correct flag"
            ),
            "occurred_at": first_solve.date,
        })

    if not events:
        return []

    # If accumulate is on, merge events per user and scale severity
    if accumulate:
        from collections import defaultdict
        by_user = defaultdict(list)
        for e in events:
            by_user[e["user_id"]].append(e)
        merged = []
        for uid, evts in by_user.items():
            if len(evts) == 1:
                merged.append(evts[0])
            else:
                chall_ids = [e["challenge_id"] for e in evts]
                total_val  = sum(high_val_challs.get(cid, 0) for cid in chall_ids)
                scaled_sev = min(base_sev + 5 * (len(evts) - 1), 100)
                merged.append({
                    "detector": "first_solver_high_value",
                    "user_id": uid,
                    "challenge_id": chall_ids[0],
                    "severity": scaled_sev,
                    "detail": (
                        f"First solver on {len(evts)} high-value challenge(s) "
                        f"(total {total_val} pts) with 0 failed attempts each"
                    ),
                    "occurred_at": evts[0]["occurred_at"],
                })
        return merged

    return events


# ===========================================================================
# 12. IP diversity (too many source IPs per user)
# ===========================================================================
def detect_ip_diversity():
    """A single account submits or browses from an unusually large number of
    distinct IP addresses. Suggests credential sharing, account hand-off, or
    VPN-hopping to mask coordination with other accounts."""
    max_ips = cfg_int("ip_div.max_ips", 5)
    sev = cfg_int("ip_div.severity", 30)

    events = []
    for uid, ips in Q.ips_per_user().items():
        n = len(ips)
        if n > max_ips:
            events.append({
                "detector": "ip_diversity",
                "user_id": uid,
                "severity": min(sev + (n - max_ips) * 5, 100),
                "detail": (f"{n} distinct IPs used (threshold: {max_ips}): "
                           + ", ".join(sorted(ips)[:10])
                           + ("…" if n > 10 else "")),
                "occurred_at": None,
            })
    return events


# ===========================================================================
# 13. Geographic location anomaly
# ===========================================================================
def detect_location_anomaly():
    """Flag users whose IP addresses originate outside the configured allowed
    region.  Configure via:
      geo.allowed_countries  — ISO-2 codes, e.g. "IN"
      geo.allowed_states     — state/province names, e.g. "Gujarat,Maharashtra"
      geo.allowed_cities     — city names, e.g. "Ahmedabad,Surat,Vadodara"
    At least one list must be non-empty for the detector to run.
    A location is *allowed* when it satisfies ALL non-empty lists simultaneously
    (country AND state AND city when all three are configured).
    """
    if not cfg_bool("geo.enabled", False):
        return []

    def _parse(key):
        return {x.strip().lower() for x in (cfg(key) or "").split(",") if x.strip()}

    allowed_countries = _parse("geo.allowed_countries")
    allowed_states    = _parse("geo.allowed_states")
    allowed_cities    = _parse("geo.allowed_cities")
    flag_unknown      = cfg_bool("geo.flag_unknown", False)

    if not (allowed_countries or allowed_states or allowed_cities):
        return []

    sev = cfg_int("geo.severity", 60)
    events = []

    for uid, ips in Q.ips_per_user().items():
        anomalous = []
        for ip in ips:
            loc = geo_lookup(ip)
            if loc is None:
                if flag_unknown:
                    anomalous.append((ip, {"city": "?", "state": "?", "country_code": "?"}))
                continue
            # Build pass/fail per configured level
            country_pass = (not allowed_countries or
                            loc["country_code"].lower() in allowed_countries)
            state_pass   = (not allowed_states or
                            loc["state"].lower() in allowed_states)
            city_pass    = (not allowed_cities or
                            loc["city"].lower() in allowed_cities)
            if not (country_pass and state_pass and city_pass):
                anomalous.append((ip, loc))

        if anomalous:
            parts = []
            for ip, loc in anomalous[:6]:
                loc_str = ", ".join(filter(None, [
                    loc.get("city"), loc.get("state"), loc.get("country_code")
                ]))
                parts.append(f"{ip} → {loc_str or 'unknown'}")
            events.append({
                "detector": "location_anomaly",
                "user_id": uid,
                "severity": min(sev + 5 * (len(anomalous) - 1), 100),
                "detail": (f"{len(anomalous)} IP(s) outside allowed region: "
                           + "; ".join(parts)),
                "occurred_at": None,
            })
    return events


# ===========================================================================
# 14. Low wrong-attempt ratio — solved many challenges but almost never failed
# ===========================================================================
def detect_low_attempt_ratio():
    """Flag users who solved many challenges with suspiciously few wrong attempts.
    Legitimate players show natural trial-and-error; extremely low ratios suggest
    flags were received directly rather than solved independently.
    Config: low_attempt.min_solves (10), low_attempt.max_ratio (0.5), severity (60).
    """
    min_solves = cfg_int("low_attempt.min_solves", 10)
    max_ratio  = cfg_float("low_attempt.max_ratio", 0.5)
    sev        = cfg_int("low_attempt.severity", 60)

    from CTFd.models import Fails, Solves
    from sqlalchemy import func
    from CTFd.models import db

    solve_rows = (
        db.session.query(Solves.user_id, func.count(Solves.id))
        .group_by(Solves.user_id).all()
    )
    fail_rows = (
        db.session.query(Fails.user_id, func.count(Fails.id))
        .group_by(Fails.user_id).all()
    )
    solve_cnt = {uid: n for uid, n in solve_rows}
    fail_cnt  = {uid: n for uid, n in fail_rows}

    events = []
    for uid, n_solves in solve_cnt.items():
        if n_solves < min_solves:
            continue
        n_fails = fail_cnt.get(uid, 0)
        ratio   = n_fails / n_solves
        if ratio < max_ratio:
            deficit = max_ratio - ratio
            scaled  = min(sev + int(deficit * 40), 95)
            events.append({
                "detector": "low_attempt_ratio",
                "user_id": uid,
                "severity": scaled,
                "detail": (
                    f"{n_solves} correct solves but only {n_fails} wrong attempts "
                    f"(ratio {ratio:.2f} < threshold {max_ratio}) — "
                    f"flags likely received directly"
                ),
                "occurred_at": None,
            })
    return events


# ===========================================================================
# 15. Hard-before-easy solve order
# ===========================================================================
def detect_hard_before_easy():
    """Flag players whose first N solves are exclusively high-value challenges
    with zero wrong attempts on low-value challenges — a sign of receiving flags
    rather than genuinely working up in difficulty.
    Config: hard_easy.first_n (5), hard_easy.hard_min (100), hard_easy.easy_max (50).
    """
    first_n   = cfg_int("hard_easy.first_n", 5)
    hard_min  = cfg_int("hard_easy.hard_min", 100)
    easy_max  = cfg_int("hard_easy.easy_max", 50)
    sev       = cfg_int("hard_easy.severity", 60)

    chall_val = {c.id: c.value for c in Q.all_visible_challenges()}
    fails     = Q.fails_per_user_challenge()
    events    = []

    for uid, solves in Q.solves_per_user().items():
        if len(solves) < first_n:
            continue
        first_solves = solves[:first_n]
        # Are the first N solves all hard challenges?
        hard_first = all(chall_val.get(s.challenge_id, 0) >= hard_min for s in first_solves)
        if not hard_first:
            continue
        # Does the user have zero wrong attempts on any easy challenge?
        easy_zero = not any(
            fails.get((uid, cid), 0) > 0
            for cid, v in chall_val.items()
            if v <= easy_max
        )
        if easy_zero:
            vals = [chall_val.get(s.challenge_id, 0) for s in first_solves]
            events.append({
                "detector": "hard_before_easy",
                "user_id": uid,
                "severity": sev,
                "detail": (
                    f"First {first_n} solves are all hard (≥{hard_min}pt): "
                    f"values {vals} — zero wrong attempts on easy (≤{easy_max}pt) challenges"
                ),
                "occurred_at": first_solves[0].date,
            })
    return events


# ===========================================================================
# 16. Zero wrong attempts on hard challenges (per-challenge level)
# ===========================================================================
def detect_zero_wrong_hard():
    """Flag users who solved multiple hard challenges with exactly zero prior
    wrong attempts on those same challenges.  Easy challenges are excluded
    because guessing right first time is plausible; on hard ones it strongly
    suggests the flag was handed to them.
    Config: zero_wrong.min_count (3), zero_wrong.hard_min (100), severity (65).
    """
    min_count = cfg_int("zero_wrong.min_count", 3)
    hard_min  = cfg_int("zero_wrong.hard_min", 100)
    sev       = cfg_int("zero_wrong.severity", 65)

    chall_val  = {c.id: c.value for c in Q.all_visible_challenges()}
    chall_name = Q.challenge_name_map()
    fails      = Q.fails_per_user_challenge()
    events     = []

    user_zero = defaultdict(list)  # uid -> [(cid, value)]
    for uid, solves in Q.solves_per_user().items():
        for s in solves:
            val = chall_val.get(s.challenge_id, 0)
            if val < hard_min:
                continue
            if fails.get((uid, s.challenge_id), 0) == 0:
                user_zero[uid].append((s.challenge_id, val))

    for uid, hits in user_zero.items():
        if len(hits) < min_count:
            continue
        names = [f"{chall_name.get(cid,'#'+str(cid))} ({v}pt)" for cid, v in hits[:6]]
        events.append({
            "detector": "zero_wrong_hard",
            "user_id": uid,
            "severity": min(sev + (len(hits) - min_count) * 5, 95),
            "detail": (
                f"{len(hits)} hard challenge(s) solved with 0 wrong attempts each: "
                + ", ".join(names)
            ),
            "occurred_at": None,
        })
    return events


# ===========================================================================
# 17. Impossible travel — same user, different geolocations in short window
# ===========================================================================
def detect_impossible_travel():
    """Flag users whose submissions jump between geographically distinct IPs
    within a short time window — possible proxy/VPN rotation or account sharing.
    Config: travel.window_min (60), travel.severity (70).
    Requires geo_lookup to work (python-geoacumen-city installed).
    """
    window_min = cfg_int("travel.window_min", 60)
    sev        = cfg_int("travel.severity", 70)

    from CTFd.models import Submissions
    from sqlalchemy import asc

    # All submissions sorted by user + date
    rows = (
        Submissions.query
        .with_entities(Submissions.user_id, Submissions.ip, Submissions.date)
        .filter(Submissions.ip.isnot(None))
        .order_by(Submissions.user_id, asc(Submissions.date))
        .all()
    )

    # Group by user
    by_user = defaultdict(list)
    for uid, ip, dt in rows:
        if ip and dt:
            by_user[uid].append((dt, ip))

    events = []
    window = timedelta(minutes=window_min)
    geo_cache = {}

    def _loc(ip):
        if ip not in geo_cache:
            geo_cache[ip] = geo_lookup(ip)
        return geo_cache[ip]

    def _region(loc):
        if not loc:
            return None
        return (loc.get("country_code") or "", loc.get("state") or "")

    for uid, timeline in by_user.items():
        seen = []
        for dt, ip in timeline:
            loc   = _loc(ip)
            reg   = _region(loc)
            if reg is None:
                continue
            for prev_dt, prev_ip, prev_reg in seen:
                if (dt - prev_dt) > window:
                    continue
                if reg == prev_reg or prev_ip == ip:
                    continue
                # Different region within the window — flag it
                loc_str      = f"{loc.get('city','?')}, {loc.get('state','?')}, {loc.get('country_code','?')}"
                prev_loc_str = ""
                prev_l = _loc(prev_ip)
                if prev_l:
                    prev_loc_str = f"{prev_l.get('city','?')}, {prev_l.get('state','?')}, {prev_l.get('country_code','?')}"
                gap_min = int((dt - prev_dt).total_seconds() / 60)
                events.append({
                    "detector": "impossible_travel",
                    "user_id": uid,
                    "severity": sev,
                    "detail": (
                        f"Location jump within {gap_min}min: "
                        f"{prev_ip} ({prev_loc_str}) → {ip} ({loc_str})"
                    ),
                    "occurred_at": dt,
                })
                break  # one event per user is enough
            seen.append((dt, ip, reg))
            # Only look back within window
            seen = [(d, i, r) for d, i, r in seen if (dt - d) <= window]
    return events


# ===========================================================================
# 18. Banned user activity — user account has banned=True but has solves
# ===========================================================================
def detect_banned_activity():
    """Flag users who are currently banned in CTFd but still appear in the
    solves table.  This is the highest-confidence cheater signal — they were
    already adjudicated and their activity should be highlighted for score removal.
    Severity: 95 (effectively confirmed).
    """
    from CTFd.models import Solves, Users
    from sqlalchemy import func

    banned = {u.id: u.name for u in Users.query.filter(Users.banned == True).all()}  # noqa: E712
    if not banned:
        return []

    solve_rows = (
        Solves.query
        .with_entities(Solves.user_id, func.count(Solves.id), func.min(Solves.date))
        .filter(Solves.user_id.in_(list(banned)))
        .group_by(Solves.user_id)
        .all()
    )
    events = []
    for uid, n_solves, earliest in solve_rows:
        events.append({
            "detector": "banned_activity",
            "user_id": uid,
            "severity": 95,
            "detail": (
                f"BANNED account '{banned[uid]}' has {n_solves} solve(s) on record. "
                f"Scores should be excluded from the leaderboard."
            ),
            "occurred_at": earliest,
        })
    return events


# ===========================================================================
# 19. Crowd wrong-flag submission
#     Many users submit the same wrong flag → coordinated group guessing
# ===========================================================================
def detect_crowd_wrong_flag():
    """Detect challenges where a specific wrong flag was submitted by a large
    crowd of users — a strong signal of coordinated group discussion/copying.
    Differs from detect_identical_wrong (which flags pairs) by using a higher
    threshold and producing one event per crowd member.
    Config: crowd_wrong.min_users (10), crowd_wrong.severity (65).
    """
    min_users = cfg_int("crowd_wrong.min_users", 10)
    sev       = cfg_int("crowd_wrong.severity", 65)
    chall_name = Q.challenge_name_map()

    # (challenge_id, provided) -> set of user_ids
    crowd = defaultdict(set)
    for provided, entries in Q.fails_by_provided().items():
        for uid, cid, _ in entries:
            crowd[(cid, provided)].add(uid)

    events = []
    for (cid, provided), users in crowd.items():
        if len(users) < min_users:
            continue
        cname = chall_name.get(cid, f"#{cid}")
        for uid in users:
            events.append({
                "detector": "crowd_wrong_flag",
                "user_id": uid,
                "challenge_id": cid,
                "severity": min(sev + (len(users) - min_users) * 2, 90),
                "detail": (
                    f"Submitted crowd wrong flag '{provided[:60]}' on '{cname}' "
                    f"— same wrong answer submitted by {len(users)} users (group coordination)"
                ),
                "occurred_at": None,
            })
    return events


# ===========================================================================
# TEAM-MODE DETECTORS
# ===========================================================================

# ===========================================================================
# T1. Inter-team IP sharing
# ===========================================================================
def detect_inter_team_ip_sharing():
    """Different teams sharing the same IP address. In team mode same-team IP
    sharing is expected; cross-team sharing is suspicious.
    Config: team_ip.min_teams (2), team_ip.severity (70).
    Enable key: enabled.inter_team_ip
    """
    if Q.get_ctfd_mode() != "teams":
        return []

    min_teams = cfg_int("team_ip.min_teams", 2)
    sev = cfg_int("team_ip.severity", 70)
    t_names = Q.team_name_map()
    events = []

    for ip, tids in Q.teams_per_ip().items():
        if len(tids) < min_teams:
            continue
        tid_list = sorted(tids)
        for tid in tid_list:
            others = [t for t in tid_list if t != tid]
            other_names = [t_names.get(t, f"#{t}") for t in others[:6]]
            events.append({
                "detector": "inter_team_ip_sharing",
                "user_id": None,
                "team_id": tid,
                "related_user_id": None,
                "challenge_id": None,
                "severity": min(sev + 5 * (len(others) - 1), 100),
                "detail": (
                    f"Team '{t_names.get(tid, tid)}' shares IP {ip} with "
                    f"{len(others)} other team(s): " + ", ".join(other_names)
                ),
                "occurred_at": None,
            })
    return events


# ===========================================================================
# T2. Inter-team flag sharing
# ===========================================================================
def detect_inter_team_flag_sharing():
    """Members of different teams solving the same challenge within a short
    time window from the same IP — strong cross-team collusion signal.
    Config: team_flag.window_sec (120), team_flag.severity (80).
    Enable key: enabled.inter_team_flag
    """
    if Q.get_ctfd_mode() != "teams":
        return []

    window = cfg_int("team_flag.window_sec", 120)
    sev = cfg_int("team_flag.severity", 80)
    t_names = Q.team_name_map()
    c_names = Q.challenge_name_map()
    events = []

    # Group correct submissions by (challenge_id, ip)
    by_chall_ip = defaultdict(list)
    for uid, cid, ip, dt, typ, prov in Q.submissions_with_ip():
        if typ == "correct" and ip:
            by_chall_ip[(cid, ip)].append((uid, dt))

    # For each group, check if solves from different teams fall within window
    members = Q.team_members()
    # Build uid -> team_id reverse map
    uid_to_team = {}
    for tid, uids in members.items():
        for uid in uids:
            uid_to_team[uid] = tid

    seen = set()
    for (cid, ip), solves in by_chall_ip.items():
        solves.sort(key=lambda x: x[1])
        for i, (u1, t1) in enumerate(solves):
            team1 = uid_to_team.get(u1)
            if team1 is None:
                continue
            for u2, t2 in solves[i + 1:]:
                delta = (t2 - t1).total_seconds()
                if delta > window:
                    break
                team2 = uid_to_team.get(u2)
                if team2 is None or team2 == team1:
                    continue
                pair_key = (min(team1, team2), max(team1, team2), cid)
                if pair_key in seen:
                    continue
                seen.add(pair_key)
                chall_name = c_names.get(cid, f"#{cid}")
                events.append({
                    "detector": "inter_team_flag_sharing",
                    "user_id": u2,
                    "team_id": team2,
                    "related_user_id": u1,
                    "challenge_id": cid,
                    "severity": sev,
                    "detail": (
                        f"'{chall_name}' solved from same IP {ip} by "
                        f"team '{t_names.get(team1, team1)}' (user #{u1}) and "
                        f"team '{t_names.get(team2, team2)}' (user #{u2}) "
                        f"within {int(delta)}s"
                    ),
                    "occurred_at": t2,
                })
    return events


# ===========================================================================
# T3. Team solve-order correlation
# ===========================================================================
def detect_team_solve_correlation():
    """Two teams have highly correlated solve orders — like
    :func:`detect_solve_correlation` but at team level.
    Config: team_corr.min_shared (5), team_corr.order_match_pct (80),
    team_corr.severity (60).
    Enable key: enabled.team_solve_corr
    """
    if Q.get_ctfd_mode() != "teams":
        return []

    min_shared = cfg_int("team_corr.min_shared", 5)
    min_pct = cfg_float("team_corr.order_match_pct", 80.0)
    sev = cfg_int("team_corr.severity", 60)
    t_names = Q.team_name_map()

    # Build {team_id: {chall_id: rank}} from solve order
    team_solves = Q.solves_per_team()
    rank = {}
    for tid, sl in team_solves.items():
        seen_challs = {}
        for s in sl:
            if s.challenge_id not in seen_challs:
                seen_challs[s.challenge_id] = len(seen_challs)
        rank[tid] = seen_challs

    events = []
    tids = sorted(rank.keys())
    for i, a in enumerate(tids):
        for b in tids[i + 1:]:
            shared = set(rank[a]) & set(rank[b])
            if len(shared) < min_shared:
                continue
            shared = list(shared)
            concordant = 0
            total = 0
            for x in range(len(shared)):
                for y in range(x + 1, len(shared)):
                    cx, cy = shared[x], shared[y]
                    ax, ay = rank[a][cx], rank[a][cy]
                    bx, by = rank[b][cx], rank[b][cy]
                    if (ax - ay) * (bx - by) > 0:
                        concordant += 1
                    total += 1
            if total == 0:
                continue
            pct = 100.0 * concordant / total
            if pct >= min_pct:
                events.append({
                    "detector": "team_solve_correlation",
                    "user_id": None,
                    "team_id": a,
                    "related_user_id": None,
                    "challenge_id": None,
                    "severity": min(sev + int((pct - min_pct) / 2), 100),
                    "detail": (
                        f"Team '{t_names.get(a, a)}' solve-order correlation with "
                        f"team '{t_names.get(b, b)}': {pct:.1f}% concordant on "
                        f"{len(shared)} shared solves"
                    ),
                    "occurred_at": None,
                })
    return events


# ===========================================================================
#  Registry — runner iterates this and persists each list
# ===========================================================================
# To disable a single detector at install time, comment its line out here.
# At runtime, flip the matching `enabled.<name>` config key from "1" to "0".
DETECTORS = {
    "simultaneous":           (detect_simultaneous,         "enabled.simultaneous"),
    "mass_after_first_blood": (detect_mass_after_first_blood, "enabled.mass_after_fb"),
    "first_try_rare":         (detect_first_try_rare,       "enabled.first_try_rare"),
    "ip_ua_overlap":          (detect_ip_ua_overlap,        "enabled.ip_ua_overlap"),
    "solve_correlation":      (detect_solve_correlation,    "enabled.solve_correlation"),
    "velocity":               (detect_velocity,             "enabled.velocity"),
    "identical_wrong":        (detect_identical_wrong,      "enabled.identical_wrong"),
    "brute_force":            (detect_brute_force,          "enabled.brute_force"),
    "dormant_burst":          (detect_dormant_burst,        "enabled.dormant_burst"),
    "session_swap":           (detect_session_swap,         "enabled.session_swap"),
    "shared_correct_ip":        (detect_shared_correct_ip,       "enabled.shared_correct_ip"),
    "ip_diversity":             (detect_ip_diversity,            "enabled.ip_diversity"),
    "first_solver_high_value":  (detect_first_solver_high_value, "enabled.first_solver_hv"),
    "location_anomaly":         (detect_location_anomaly,        "geo.enabled"),
    # ── New detectors ──────────────────────────────────────────────────────
    "low_attempt_ratio":        (detect_low_attempt_ratio,       "enabled.low_attempt_ratio"),
    "hard_before_easy":         (detect_hard_before_easy,        "enabled.hard_before_easy"),
    "zero_wrong_hard":          (detect_zero_wrong_hard,         "enabled.zero_wrong_hard"),
    "impossible_travel":        (detect_impossible_travel,       "enabled.impossible_travel"),
    "banned_activity":          (detect_banned_activity,         "enabled.banned_activity"),
    "crowd_wrong_flag":         (detect_crowd_wrong_flag,        "enabled.crowd_wrong_flag"),
    # ── Team-mode detectors ────────────────────────────────────────────────
    "inter_team_ip_sharing":    (detect_inter_team_ip_sharing,   "enabled.inter_team_ip"),
    "inter_team_flag_sharing":  (detect_inter_team_flag_sharing, "enabled.inter_team_flag"),
    "team_solve_correlation":   (detect_team_solve_correlation,  "enabled.team_solve_corr"),
}


def list_detectors():
    return list(DETECTORS.keys())
