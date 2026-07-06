"""
ctfd_anti_cheat.queries
==========================

Pure-read helpers against CTFd's core tables. We never write to them. Keeping
all SQL in one place makes the detectors short and makes it obvious where to
optimize if a large CTFd corpus slows things down.

Note on CTFd internals (verified against current CTFd 3.x):
  * `Submissions` is the parent table. `type = 'correct'` -> Solves,
    `type = 'incorrect'` -> Fails.
  * `Solves` / `Fails` are polymorphic subclasses of `Submissions` and expose
    the same columns: id, challenge_id, user_id, team_id, ip, provided, date.
  * `Tracking` records page-visit IPs: ip, user_id, date.
"""

from collections import defaultdict
from sqlalchemy import func

from CTFd.models import (
    Challenges,
    Fails,
    Solves,
    Submissions,
    Tracking,
    Users,
    db,
)


# ---------------------------------------------------------------------------
#  Basic accessors
# ---------------------------------------------------------------------------
def all_visible_challenges():
    return Challenges.query.filter(Challenges.state == "visible").all()


def all_active_users():
    return Users.query.filter(
        Users.hidden == False, Users.banned == False  # noqa: E712
    ).all()


def admin_user_ids():
    """Return set of user IDs that have admin/superadmin type."""
    return {u.id for u in Users.query.filter(Users.type == "admin").all()}


def user_scores_and_ranks():
    """{user_id: {"score": int, "rank": int, "solve_count": int}}
    Scores are the sum of current challenge values for each user's correct solves.
    Ranks are computed server-side (1 = highest score)."""
    rows = (
        db.session.query(
            Solves.user_id,
            func.sum(Challenges.value).label("score"),
            func.count(Solves.id).label("cnt"),
        )
        .join(Challenges, Solves.challenge_id == Challenges.id)
        .group_by(Solves.user_id)
        .order_by(func.sum(Challenges.value).desc())
        .all()
    )
    result = {}
    for rank, row in enumerate(rows, 1):
        result[row.user_id] = {
            "score": int(row.score or 0),
            "rank": rank,
            "solve_count": int(row.cnt or 0),
        }
    return result


def user_name_map():
    return {u.id: u.name for u in Users.query.all()}


def challenge_name_map():
    return {c.id: c.name for c in Challenges.query.all()}


# ---------------------------------------------------------------------------
#  Solves
# ---------------------------------------------------------------------------
def solves_per_challenge():
    """Return {challenge_id: [Solve, ...]} ordered by solve time ascending.
    First element of each list is the first-blood solve."""
    out = defaultdict(list)
    for s in Solves.query.order_by(Solves.date.asc()).all():
        out[s.challenge_id].append(s)
    return out


def solves_per_user():
    """Return {user_id: [Solve, ...]} ordered by solve time ascending."""
    out = defaultdict(list)
    for s in Solves.query.order_by(Solves.date.asc()).all():
        out[s.user_id].append(s)
    return out


def first_blood_map():
    """{challenge_id: Solve} for the earliest solve of each challenge."""
    fb = {}
    for cid, solves in solves_per_challenge().items():
        if solves:
            fb[cid] = solves[0]
    return fb


def solver_counts():
    """{challenge_id: number_of_distinct_solvers}."""
    rows = (
        db.session.query(Solves.challenge_id, func.count(func.distinct(Solves.user_id)))
        .group_by(Solves.challenge_id)
        .all()
    )
    return {cid: cnt for cid, cnt in rows}


# ---------------------------------------------------------------------------
#  Fails / submissions
# ---------------------------------------------------------------------------
def fails_per_user_challenge():
    """{(user_id, challenge_id): count_of_failed_attempts}"""
    rows = (
        db.session.query(Fails.user_id, Fails.challenge_id, func.count(Fails.id))
        .group_by(Fails.user_id, Fails.challenge_id)
        .all()
    )
    return {(u, c): n for u, c, n in rows}


def submissions_with_ip():
    """All Submissions yielding (user_id, challenge_id, ip, date, type, provided).
    Used by IP-overlap and identical-wrong detectors."""
    q = (
        db.session.query(
            Submissions.user_id,
            Submissions.challenge_id,
            Submissions.ip,
            Submissions.date,
            Submissions.type,
            Submissions.provided,
        )
        .order_by(Submissions.date.asc())
    )
    return q.all()


def fails_by_provided():
    """{provided_text: [(user_id, challenge_id, date), ...]} for failed attempts.
    Used to find identical wrong flags shared across users."""
    out = defaultdict(list)
    rows = (
        db.session.query(
            Fails.provided, Fails.user_id, Fails.challenge_id, Fails.date
        )
        .all()
    )
    for provided, uid, cid, dt in rows:
        if provided and provided.strip():
            out[provided.strip()].append((uid, cid, dt))
    return out


# ---------------------------------------------------------------------------
#  Tracking (IP visits)
# ---------------------------------------------------------------------------
def tracking_rows():
    """All Tracking rows: (user_id, ip, date)."""
    return db.session.query(Tracking.user_id, Tracking.ip, Tracking.date).all()


def ips_per_user():
    """{user_id: set(ip)} unioning Submissions.ip and Tracking.ip."""
    out = defaultdict(set)
    for uid, ip, _ in tracking_rows():
        if ip:
            out[uid].add(ip)
    for uid, _, ip, _, _, _ in submissions_with_ip():
        if ip:
            out[uid].add(ip)
    return out


def users_per_ip():
    """{ip: set(user_id)} — inverse of ips_per_user."""
    out = defaultdict(set)
    for uid, ips in ips_per_user().items():
        for ip in ips:
            out[ip].add(uid)
    return out


# ---------------------------------------------------------------------------
#  Enriched per-user analytics (for dashboard rich columns)
# ---------------------------------------------------------------------------

def first_bloods_per_user():
    """{user_id: [{"challenge_id", "challenge_name", "category", "value",
                   "total_solvers", "solve_time"}, ...]}
    A 'first blood' is the earliest solve on a given challenge.
    """
    # total solvers per challenge
    sc = solver_counts()
    # challenge meta
    chall_meta = {c.id: c for c in Challenges.query.all()}
    # first blood solve per challenge
    fb = first_blood_map()

    out = defaultdict(list)
    for cid, solve in fb.items():
        c = chall_meta.get(cid)
        if not c:
            continue
        out[solve.user_id].append({
            "challenge_id": cid,
            "challenge_name": c.name,
            "category": c.category or "—",
            "value": c.value,
            "total_solvers": sc.get(cid, 1),
            "solve_time": solve.date,
        })
    return dict(out)


def category_solves_per_user():
    """{user_id: {category: count}} — how many challenges per category each user solved."""
    rows = (
        db.session.query(
            Solves.user_id,
            Challenges.category,
            func.count(Solves.id),
        )
        .join(Challenges, Solves.challenge_id == Challenges.id)
        .group_by(Solves.user_id, Challenges.category)
        .all()
    )
    out = defaultdict(dict)
    for uid, cat, cnt in rows:
        out[uid][cat or "other"] = cnt
    return dict(out)


def avg_solve_rank_per_user():
    """{user_id: avg_pct} where avg_pct is 0–100 (0 = always first, 100 = always last).
    For each solve, pct = (position_among_solvers / total_solvers) * 100.
    Averaged over all the user's solves.
    """
    # Load all solves ordered by challenge then date
    all_solves = (
        db.session.query(Solves.user_id, Solves.challenge_id, Solves.date)
        .order_by(Solves.challenge_id, Solves.date)
        .all()
    )
    # Build per-challenge ordered list of user_ids
    chall_solvers = defaultdict(list)
    for uid, cid, _ in all_solves:
        chall_solvers[cid].append(uid)

    user_pcts = defaultdict(list)
    for cid, solvers in chall_solvers.items():
        total = len(solvers)
        for pos, uid in enumerate(solvers, 1):
            user_pcts[uid].append(pos / total * 100)

    return {uid: round(sum(pcts) / len(pcts), 1) for uid, pcts in user_pcts.items()}


# ---------------------------------------------------------------------------
#  Team-mode helpers
# ---------------------------------------------------------------------------
def get_ctfd_mode():
    """Return ``"users"`` or ``"teams"`` based on the CTFd instance config."""
    from CTFd.utils import get_config
    return get_config("user_mode") or "users"


def team_name_map():
    """Return ``{team_id: team_name}`` for every team."""
    from CTFd.models import Teams
    return {t.id: t.name for t in Teams.query.all()}


def team_members():
    """Return ``{team_id: set(user_id)}`` mapping from Users.team_id."""
    out = defaultdict(set)
    for u in Users.query.filter(Users.team_id.isnot(None)).all():
        out[u.team_id].add(u.id)
    return out


def solves_per_team():
    """Return ``{team_id: [Solve, ...]}`` ordered by solve time ascending."""
    out = defaultdict(list)
    for s in Solves.query.filter(Solves.team_id.isnot(None)).order_by(Solves.date.asc()).all():
        out[s.team_id].append(s)
    return out


def ips_per_team():
    """Return ``{team_id: set(ip)}`` — union of all member IPs (submissions + tracking)."""
    members = team_members()
    user_ips = ips_per_user()
    out = {}
    for tid, uids in members.items():
        ips = set()
        for uid in uids:
            ips.update(user_ips.get(uid, set()))
        out[tid] = ips
    return out


def teams_per_ip():
    """Return ``{ip: set(team_id)}`` — inverse of ips_per_team."""
    out = defaultdict(set)
    for tid, ips in ips_per_team().items():
        for ip in ips:
            out[ip].add(tid)
    return out


def team_scores_and_ranks():
    """``{team_id: {"score": int, "rank": int, "solve_count": int}}``
    Like :func:`user_scores_and_ranks` but grouped by team_id."""
    rows = (
        db.session.query(
            Solves.team_id,
            func.sum(Challenges.value).label("score"),
            func.count(Solves.id).label("cnt"),
        )
        .join(Challenges, Solves.challenge_id == Challenges.id)
        .filter(Solves.team_id.isnot(None))
        .group_by(Solves.team_id)
        .order_by(func.sum(Challenges.value).desc())
        .all()
    )
    result = {}
    for rank, row in enumerate(rows, 1):
        result[row.team_id] = {
            "score": int(row.score or 0),
            "rank": rank,
            "solve_count": int(row.cnt or 0),
        }
    return result


def user_ip_locations():
    """{user_id: list[str]} — unique human-readable locations per user (max 8)."""
    from .utils import geo_lookup
    ips_map = ips_per_user()
    out = {}
    for uid, ips in ips_map.items():
        locs = []
        seen_locs = set()
        for ip in list(ips)[:12]:
            loc = geo_lookup(ip)
            if loc:
                parts = [p for p in [loc.get("city"), loc.get("state"), loc.get("country_code")] if p]
                loc_str = ", ".join(parts) if parts else ip
            else:
                loc_str = ip
            if loc_str not in seen_locs:
                seen_locs.add(loc_str)
                locs.append(loc_str)
            if len(locs) >= 8:
                break
        out[uid] = locs
    return out


def fails_before_solve_ratio():
    """{user_id: ratio} where ratio = fraction of their solves that had >= 1 prior fail."""
    fail_map = fails_per_user_challenge()
    s_per_user = solves_per_user()
    out = {}
    for uid, solves in s_per_user.items():
        if not solves:
            continue
        with_prior_fail = sum(1 for s in solves if fail_map.get((uid, s.challenge_id), 0) > 0)
        out[uid] = round(with_prior_fail / len(solves), 3)
    return out
