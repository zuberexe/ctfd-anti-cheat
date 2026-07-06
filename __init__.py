"""
ctfd_anti_cheat
===============

CTFd plugin that scans completed submissions for cheating patterns and
surfaces them in an admin-only dashboard. All routes live under
/admin/anti_cheat and are protected by CTFd's `admins_only` decorator.

Install
-------
1. Copy this directory into `CTFd/plugins/`.
2. Restart CTFd.
3. Visit /admin/anti_cheat as an admin.

Design notes
------------
* No external network calls. No non-stdlib pip deps.
* Detectors live in `detectors.py`; the runner here just iterates them.
* All plugin tables are prefixed `cm_` so they're trivial to drop on uninstall.
* Templates extend `admin/base.html`, so they pick up CTFd's admin chrome.
"""

import csv
import io
import os
import re
import time
from datetime import datetime

from flask import Blueprint, Response, abort, jsonify, redirect, render_template, request, send_from_directory, url_for
from sqlalchemy import desc, func

from CTFd.models import Challenges, Users, db
from CTFd.plugins import register_plugin_assets_directory  # noqa: F401 (kept for reference)
from CTFd.utils.decorators import admins_only

from .detectors import DETECTORS
from .models import (
    CMConfig,
    CMRunMeta,
    CMSuspicionEvent,
    CMUserAgentLog,
)
from . import queries as query_module
from .queries import (
    challenge_name_map, user_name_map, user_scores_and_ranks,
    first_bloods_per_user, category_solves_per_user,
    avg_solve_rank_per_user, user_ip_locations, fails_before_solve_ratio,
)
from .utils import (
    DEFAULTS,
    cfg,
    cfg_bool,
    cfg_int,
    cfg_set,
    fingerprint,
    jsonify_safe,
    seed_defaults,
    to_iso,
)


PLUGIN_NAME = "anti_cheat"
PLUGIN_URL_PREFIX = "/admin/anti_cheat"

# Allowed filename pattern for static assets (prevent path traversal)
_SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$")
# Max length for any single config value
_MAX_CONFIG_VALUE_LEN = 500
# Max length for search/filter inputs
_MAX_SEARCH_LEN = 200


def _validate_detector_names(names):
    """Return only names that exist in DETECTORS. Prevents injection of
    arbitrary strings into the detector runner."""
    if not names:
        return None
    valid = set(DETECTORS.keys())
    filtered = [n for n in names if n in valid]
    return filtered if filtered else None


def _sanitize_config_value(key, value):
    """Clamp and sanitize a config value based on its key pattern."""
    value = str(value).strip()[:_MAX_CONFIG_VALUE_LEN]

    # Boolean keys: force to "0" or "1"
    if key.startswith("enabled.") or key in ("filter.hide_admins", "geo.flag_unknown",
                                              "first_solver.accumulate"):
        return "1" if value.lower() in ("1", "true", "yes", "on") else "0"

    # Numeric integer keys: clamp to reasonable bounds
    int_keys_bounds = {
        "simul.high_conf_sec": (1, 3600),
        "simul.med_conf_sec": (1, 7200),
        "simul.low_conf_sec": (1, 86400),
        "simul.window_sec": (1, 86400),
        "simul.min_severity": (0, 100),
        "mass_fb.min_chall_count": (1, 1000),
        "mass_fb.severity": (0, 100),
        "rare.max_solver_count": (1, 10000),
        "rare.severity": (0, 100),
        "overlap.min_accounts": (2, 100),
        "overlap.severity": (0, 100),
        "corr.min_shared_solves": (2, 1000),
        "corr.severity": (0, 100),
        "velocity.min_solves": (2, 10000),
        "velocity.severity": (0, 100),
        "wrong.min_users": (2, 10000),
        "wrong.severity": (0, 100),
        "brute.window_sec": (1, 86400),
        "brute.failures": (2, 100000),
        "brute.severity": (0, 100),
        "dormant.silent_hours": (1, 720),
        "dormant.burst_count": (2, 1000),
        "dormant.burst_window_min": (1, 1440),
        "dormant.severity": (0, 100),
        "swap.window_sec": (1, 86400),
        "swap.severity": (0, 100),
        "shared_ip.severity": (0, 100),
        "ip_div.max_ips": (1, 1000),
        "ip_div.severity": (0, 100),
        "first_solver.min_value": (1, 100000),
        "first_solver.severity": (0, 100),
        "score.cap": (1, 1000),
        "filter.genuine_min_score": (0, 100),
        "geo.severity": (0, 100),
        "low_attempt.min_solves": (1, 100000),
        "low_attempt.severity": (0, 100),
        "hard_easy.first_n": (1, 100),
        "hard_easy.hard_min": (1, 100000),
        "hard_easy.easy_max": (0, 100000),
        "hard_easy.severity": (0, 100),
        "zero_wrong.min_count": (1, 10000),
        "zero_wrong.hard_min": (1, 100000),
        "zero_wrong.severity": (0, 100),
        "travel.window_min": (1, 10080),
        "travel.severity": (0, 100),
        "crowd_wrong.min_users": (2, 100000),
        "crowd_wrong.severity": (0, 100),
        "team_ip.min_teams": (2, 1000),
        "team_ip.severity": (0, 100),
        "team_flag.window_sec": (1, 86400),
        "team_flag.severity": (0, 100),
        "team_corr.min_shared": (2, 1000),
        "team_corr.severity": (0, 100),
    }
    if key in int_keys_bounds:
        lo, hi = int_keys_bounds[key]
        try:
            return str(max(lo, min(hi, int(float(value)))))
        except (ValueError, TypeError):
            return str(lo)

    # Float keys
    float_keys_bounds = {
        "mass_fb.ratio_pct": (0.0, 100.0),
        "corr.order_match_pct": (0.0, 100.0),
        "velocity.zscore": (0.1, 100.0),
        "low_attempt.max_ratio": (0.0, 10.0),
        "team_corr.order_match_pct": (0.0, 100.0),
    }
    if key in float_keys_bounds:
        lo, hi = float_keys_bounds[key]
        try:
            return str(max(lo, min(hi, float(value))))
        except (ValueError, TypeError):
            return str(lo)

    # String keys (IPs, country codes, etc.): strip dangerous chars
    # Allow alphanumeric, commas, dots, spaces, hyphens only
    value = re.sub(r"[^\w\s,.\-:/]", "", value)
    return value


# ---------------------------------------------------------------------------
#  Detector runner
# ---------------------------------------------------------------------------
def run_detectors(only=None):
    """Run every enabled detector and persist events. Returns a summary dict.
    `only` is an optional iterable of detector names to limit the run to."""
    summary = {}
    for name, (fn, enable_key) in DETECTORS.items():
        if only and name not in only:
            continue
        if cfg(enable_key, "1") != "1":
            summary[name] = {"skipped": True}
            continue
        t0 = time.time()
        try:
            events = fn() or []
        except Exception as e:  # pragma: no cover - defensive
            summary[name] = {"error": str(e)}
            db.session.rollback()
            continue

        # Replace prior events for this detector to keep the table fresh.
        # We never delete admin-confirmed entries — but since we don't have a
        # 'confirmed' flag yet, the simplest behavior is wipe-and-reinsert per
        # detector. If you add a confirmation workflow later, add a WHERE
        # clause here that preserves confirmed rows.
        CMSuspicionEvent.query.filter_by(detector=name).delete()
        for ev in events:
            db.session.add(CMSuspicionEvent(
                detector=ev.get("detector", name),
                user_id=ev["user_id"],
                team_id=ev.get("team_id"),
                related_user_id=ev.get("related_user_id"),
                challenge_id=ev.get("challenge_id"),
                severity=int(ev.get("severity", 10)),
                detail=ev.get("detail", ""),
                occurred_at=ev.get("occurred_at"),
            ))

        # Update run meta
        meta = CMRunMeta.query.filter_by(detector=name).first()
        duration_ms = int((time.time() - t0) * 1000)
        if not meta:
            meta = CMRunMeta(detector=name)
            db.session.add(meta)
        meta.last_run = datetime.utcnow()
        meta.last_event_count = len(events)
        meta.last_duration_ms = duration_ms

        db.session.commit()
        summary[name] = {
            "events": len(events),
            "duration_ms": duration_ms,
        }
    return summary


# ---------------------------------------------------------------------------
#  Score aggregation
# ---------------------------------------------------------------------------
def compute_user_scores(exclude_ids=None):
    """Aggregate cm_suspicion_events into per-user scores."""
    cap = cfg_int("score.cap", 100)
    exclude_ids = exclude_ids or set()
    rows = db.session.query(
        CMSuspicionEvent.user_id,
        CMSuspicionEvent.detector,
        func.sum(CMSuspicionEvent.severity),
        func.count(CMSuspicionEvent.id),
    ).group_by(
        CMSuspicionEvent.user_id, CMSuspicionEvent.detector
    ).all()

    per_user = {}
    for uid, det, sev_sum, cnt in rows:
        if uid in exclude_ids:
            continue
        bucket = per_user.setdefault(uid, {
            "user_id": uid,
            "score": 0,
            "raw": 0,
            "detectors": {},
        })
        bucket["raw"] += int(sev_sum or 0)
        bucket["detectors"][det] = {
            "events": cnt,
            "severity": int(sev_sum or 0),
        }
    for b in per_user.values():
        raw = b["raw"]
        b["score"] = min(int(raw * 0.6 + (len(b["detectors"]) - 1) * 5), cap) if raw else 0
        b["detector_count"] = len(b["detectors"])
    return per_user


def compute_genuine_indicators(exclude_ids=None):
    """Rich genuine-user scoring.

    Signals (each contributes to 0-100 score):
    1.  First blood(s)                    → up to 40 pts
    2.  First blood on rare challenge     → +10 per rare FB
    3.  Early solver (avg rank pct)       → up to 20 pts
    4.  Category diversity                → up to 20 pts
    5.  Prior fails on solved challenges  → up to 25 pts  (shows real struggle)
    6.  Long participation span           → up to 15 pts
    7.  Consistent IP (≤2 sources)        → 10 pts
    8.  High-value solve (≥400 pts chall) → 5 pts
    """
    from .queries import (
        fails_per_user_challenge, ips_per_user, solves_per_user,
    )
    fb_map    = first_bloods_per_user()
    cat_map   = category_solves_per_user()
    rank_map  = avg_solve_rank_per_user()
    fail_map  = fails_per_user_challenge()
    ips       = ips_per_user()
    s_per_u   = solves_per_user()
    chall_val = {c.id: c.value for c in Challenges.query.all()}
    exclude_ids = exclude_ids or set()

    out = {}
    for uid, sl in s_per_u.items():
        if uid in exclude_ids or not sl:
            continue

        score = 0
        signals = {}

        # 1 & 2. First bloods
        fbs = fb_map.get(uid, [])
        fb_count = len(fbs)
        rare_fbs = [fb for fb in fbs if fb["total_solvers"] <= 5]
        score += min(fb_count * 12, 40)
        score += min(len(rare_fbs) * 10, 20)
        signals["first_blood_count"] = fb_count
        signals["rare_first_blood_count"] = len(rare_fbs)
        signals["first_blood_details"] = sorted(fbs, key=lambda x: x["total_solvers"])

        # 3. Average solve rank
        avg_rank = rank_map.get(uid, 100.0)
        if avg_rank <= 15:
            score += 20
        elif avg_rank <= 30:
            score += 14
        elif avg_rank <= 50:
            score += 7
        signals["avg_solve_rank_pct"] = avg_rank

        # 4. Category diversity
        cats = cat_map.get(uid, {})
        n_cats = len(cats)
        score += min(max(n_cats - 1, 0) * 6, 20)
        signals["categories"] = cats
        signals["category_count"] = n_cats

        # 5. Prior failures (genuine struggle)
        prior_fails = sum(1 for s in sl if fail_map.get((uid, s.challenge_id), 0) > 0)
        fail_ratio = prior_fails / len(sl)
        if fail_ratio >= 0.5:
            score += 25
        elif fail_ratio >= 0.3:
            score += 16
        elif fail_ratio >= 0.1:
            score += 8
        signals["fail_ratio"] = round(fail_ratio, 2)

        # 6. Long participation span
        span_h = (sl[-1].date - sl[0].date).total_seconds() / 3600.0 if len(sl) > 1 else 0
        if span_h >= 8:
            score += 15
        elif span_h >= 3:
            score += 8
        elif span_h >= 1:
            score += 4
        signals["span_hours"] = round(span_h, 1)

        # 7. Consistent IP
        ip_count = len(ips.get(uid, set()))
        if ip_count <= 2:
            score += 10
        elif ip_count <= 4:
            score += 4
        signals["ip_count"] = ip_count
        signals["single_ip"] = ip_count == 1

        # 8. Solved a high-value challenge (genuine skill)
        max_chall_val = max((chall_val.get(s.challenge_id, 0) for s in sl), default=0)
        if max_chall_val >= 400:
            score += 5
        signals["max_challenge_value"] = max_chall_val

        # 9. Progressive difficulty — solve order trends easy → hard
        vals_by_time = [chall_val.get(s.challenge_id, 0) for s in sl]
        if len(vals_by_time) >= 4:
            n    = len(vals_by_time)
            mid  = n // 2
            avg_first  = sum(vals_by_time[:mid]) / mid
            avg_second = sum(vals_by_time[mid:]) / (n - mid)
            if avg_second > avg_first * 1.2:   # second half harder than first
                score += 10
                signals["progressive_difficulty"] = True
            else:
                signals["progressive_difficulty"] = False

        # 10. Unique wrong guesses (not crowd-sourced)
        #     A genuine player's wrong answers are personal/exploratory,
        #     not the same 20-person crowd guess.
        crowd_flags = set()
        for provided, entries in query_module.fails_by_provided().items():
            users_on_this = {e[0] for e in entries}
            if len(users_on_this) >= 10:
                # This is a crowd wrong flag
                for entry_uid, entry_cid, _ in entries:
                    crowd_flags.add((entry_uid, entry_cid, provided))

        user_crowd_submissions = sum(
            1 for s in sl
            for (fuid, fcid, fprov) in crowd_flags
            if fuid == uid and fcid == s.challenge_id
        )
        if user_crowd_submissions == 0 and len(sl) >= 3:
            score += 10
            signals["unique_wrong_guesses"] = True
        else:
            signals["unique_wrong_guesses"] = False
            signals["crowd_wrong_count"] = user_crowd_submissions

        # 11. Hard struggle — 5+ wrong attempts before correct on hard challenges
        hard_struggles = sum(
            1 for s in sl
            if chall_val.get(s.challenge_id, 0) >= 100
            and fail_map.get((uid, s.challenge_id), 0) >= 5
        )
        if hard_struggles >= 2:
            score += 15
        elif hard_struggles >= 1:
            score += 8
        signals["hard_struggle_count"] = hard_struggles

        signals["score"] = min(score, 100)
        out[uid] = signals

    return out


def _fmt_time(dt):
    try:
        return dt.strftime("%H:%M UTC")
    except Exception:
        return "?"


def generate_genuine_narrative(uid, name, signals, ctf_ctx, peer_max_fb):
    """Build a rich human-readable paragraph explaining genuine evidence."""
    fb_count   = signals.get("first_blood_count", 0)
    fb_details = signals.get("first_blood_details", [])  # sorted rarest-first
    avg_rank   = signals.get("avg_solve_rank_pct", 100.0)
    cats       = signals.get("categories", {})
    fail_ratio = signals.get("fail_ratio", 0)
    span_h     = signals.get("span_hours", 0)
    score      = ctf_ctx.get("score", 0)
    solve_cnt  = ctf_ctx.get("solve_count", 0)
    rank       = ctf_ctx.get("rank", "?")
    lines      = []

    # Headline
    if fb_count >= 3 and fb_count >= peer_max_fb:
        lines.append(f"🥇 {name} — the strongest genuine signal in the rankings")
    elif fb_count >= 2:
        lines.append(f"🏅 {name} — multiple first bloods, verified genuine")
    elif fb_count == 1:
        lines.append(f"🏅 {name} — first blood achievement")
    elif avg_rank <= 25:
        lines.append(f"⚡ {name} — consistently among the earliest solvers")
    else:
        lines.append(f"✅ {name} — clean, consistent engagement profile")

    # First bloods paragraph
    if fb_details:
        rarest = fb_details[0]
        if fb_count >= 3 and fb_count >= peer_max_fb:
            lines.append(
                f"Racked up {fb_count} first bloods — more than any other player "
                f"— including the challenge with fewest total solvers in the event:"
            )
        elif fb_count >= 2:
            lines.append(f"Achieved {fb_count} first bloods, including the rarest:")
        else:
            lines.append("Achieved first blood on:")

        lines.append(
            f"  • {rarest['challenge_name']} ({rarest['category']}) — "
            f"only {rarest['total_solvers']} solver(s) total, "
            f"solved first at {_fmt_time(rarest.get('solve_time'))}."
        )
        others = fb_details[1:5]
        if others:
            others_str = ", ".join(f['challenge_name'] for f in others)
            lines.append(f"  Also first blood on: {others_str}.")

    # Average solve rank
    if avg_rank <= 50:
        tier = "earliest 15%" if avg_rank <= 15 else ("earliest 30%" if avg_rank <= 30 else "earliest half")
        qualifier = "a strong, consistent signal of real independent skill" if avg_rank <= 30 else "shows consistent speed"
        lines.append(
            f"Average solve-rank of {avg_rank:.1f}% means they were typically among the "
            f"{tier} of solvers on every challenge — {qualifier}."
        )

    # Category diversity
    if len(cats) >= 2:
        cat_str = ", ".join(f"{c} ×{n}" for c, n in sorted(cats.items(), key=lambda x: -x[1])[:6])
        lines.append(f"Solved across {len(cats)} categories: {cat_str}.")

    # Struggle signal
    if fail_ratio >= 0.3:
        lines.append(
            f"Failed before succeeding on {int(fail_ratio * 100)}% of their solves "
            f"— a hallmark of genuine problem-solving rather than copied flags."
        )

    # Hard struggle
    hard_struggles = signals.get("hard_struggle_count", 0)
    if hard_struggles >= 2:
        lines.append(
            f"Showed persistent effort on {hard_struggles} hard challenge(s) "
            f"(5+ wrong attempts each before the correct flag) — genuine skill development."
        )

    # Progressive difficulty
    if signals.get("progressive_difficulty"):
        lines.append("Solve order progresses from easier to harder challenges — natural skill curve.")

    # Unique wrong guesses
    if signals.get("unique_wrong_guesses") and solve_cnt >= 3:
        lines.append(
            "Wrong guesses are personal and exploratory — never submitted the same wrong flag as a crowd of others."
        )

    # Participation span
    if span_h >= 3:
        lines.append(f"Active over {span_h:.0f}+ hours — consistent long-form engagement.")

    return "\n".join(lines)


def generate_suspect_narrative(uid, name, susp_data, ctf_ctx, detector_events):
    """Build a short evidence summary for a suspect."""
    detectors = susp_data.get("detectors", {})
    score     = susp_data.get("score", 0)
    det_count = len(detectors)

    # Find the highest-severity event across all detectors for this user
    worst_evt = None
    worst_det = None
    for det, info in sorted(detectors.items(), key=lambda x: -(x[1].get("severity", 0) if isinstance(x[1], dict) else 0)):
        evts = [e for e in detector_events.get(det, []) if e["user_id"] == uid]
        if evts:
            worst_evt = max(evts, key=lambda e: e["severity"])
            worst_det = det
            break

    lines = []
    if score >= 70:
        lines.append(f"⛔ {name} — high suspicion (score {score}/100, {det_count} detector(s) triggered)")
    elif score >= 40:
        lines.append(f"⚠️ {name} — moderate suspicion (score {score}/100, {det_count} detector(s))")
    else:
        lines.append(f"🔍 {name} — low-level flags (score {score}/100)")

    if worst_evt and worst_det:
        lines.append(f"Primary signal [{worst_det.replace('_', ' ')}]: {worst_evt['detail']}")

    det_names = [d.replace("_", " ") for d in detectors]
    if det_names:
        lines.append(f"Triggered: {', '.join(det_names)}.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  Plugin entry point
# ---------------------------------------------------------------------------
def load(app):
    # 1. Create our tables
    app.db.create_all()
    with app.app_context():
        seed_defaults()

    # 2. Static assets (CSS/JS)
    # register_plugin_assets_directory resolves relative to CWD (/opt/CTFd),
    # but our files live inside the package. Serve them from an absolute path.
    _assets_dir = os.path.join(os.path.dirname(__file__), "assets")

    @app.route(f"/plugins/{PLUGIN_NAME}/assets/<path:filename>")
    def _anti_cheat_static(filename):
        if not _SAFE_FILENAME_RE.match(filename):
            abort(404)
        return send_from_directory(_assets_dir, filename)

    # 3. Optional UA capture hook. Only attaches if forward-looking UA
    # collection is enabled. Wrapped in app context check so config reads work.
    @app.before_request
    def _capture_ua():
        # Only log POSTs to the submission endpoint; everything else is noise.
        # We match by URL path because the Flask endpoint *name* differs
        # between CTFd 3.x minor versions, but the path has been stable.
        if request.method != "POST":
            return
        if not request.path.endswith("/api/v1/challenges/attempt"):
            return
        if not cfg_bool("enabled.ua_capture", False):
            return
        # Lazy import to avoid circulars at module load
        from CTFd.utils.user import get_current_user
        u = get_current_user()
        if not u:
            return
        raw_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        ip = raw_ip.split(",")[0].strip()[:45]
        ua = (request.headers.get("User-Agent") or "")[:500]
        fp = fingerprint(ip, ua)
        db.session.add(CMUserAgentLog(user_id=u.id, ip=ip, ua=ua, fingerprint=fp))
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    # 4. Blueprint with admin-only routes
    bp = Blueprint(
        PLUGIN_NAME,
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @bp.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @bp.before_request
    def _check_csrf():
        """Enforce CSRF nonce on all state-changing requests."""
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        from flask import session as flask_session
        expected = flask_session.get("nonce")
        if not expected:
            abort(403)
        nonce = (request.headers.get("CSRF-Token")
                 or request.headers.get("X-CSRF-Token")
                 or (request.get_json(silent=True) or {}).get("nonce")
                 or request.form.get("nonce"))
        if not nonce or nonce != expected:
            abort(403)

    @bp.route("", methods=["GET"])
    @bp.route("/", methods=["GET"])
    @admins_only
    def dashboard():
        show_admins = request.args.get("show_admins", "0") == "1"
        # Respect the stored default but let URL param override it
        hide_by_default = cfg_bool("filter.hide_admins", True)
        if show_admins:
            admin_ids = set()
        elif hide_by_default:
            admin_ids = query_module.admin_user_ids()
        else:
            admin_ids = set()

        per_user  = compute_user_scores(exclude_ids=admin_ids)
        genuine   = compute_genuine_indicators(exclude_ids=admin_ids)
        u_names   = user_name_map()
        c_names   = challenge_name_map()
        ctx       = user_scores_and_ranks()
        fb_map    = first_bloods_per_user()
        cat_map   = category_solves_per_user()
        rank_map  = avg_solve_rank_per_user()
        loc_map   = user_ip_locations()

        # Peer stat: max first-blood count among non-admin users (for narrative context)
        peer_max_fb = max(
            (len(fbs) for uid, fbs in fb_map.items() if uid not in admin_ids),
            default=1,
        )

        # ── per-detector event tables ────────────────────────────────────────
        all_det_names = list(DETECTORS.keys())
        detector_events = {}
        for det_name in all_det_names:
            rows = (CMSuspicionEvent.query
                    .filter_by(detector=det_name)
                    .order_by(desc(CMSuspicionEvent.severity), desc(CMSuspicionEvent.id))
                    .all())
            if admin_ids:
                rows = [e for e in rows if e.user_id not in admin_ids]
            detector_events[det_name] = [{
                "id":              e.id,
                "user_id":         e.user_id,
                "user_name":       u_names.get(e.user_id, f"user#{e.user_id}"),
                "related_user_id": e.related_user_id,
                "related_name":    (u_names.get(e.related_user_id, f"user#{e.related_user_id}")
                                    if e.related_user_id else ""),
                "challenge_id":    e.challenge_id,
                "challenge_name":  (c_names.get(e.challenge_id, f"#{e.challenge_id}")
                                    if e.challenge_id else ""),
                "severity":        e.severity,
                "detail":          e.detail,
                "occurred_at":     to_iso(e.occurred_at),
                "ctf_score":       ctx.get(e.user_id, {}).get("score", 0),
                "ctf_rank":        ctx.get(e.user_id, {}).get("rank", "—"),
                "solve_count":     ctx.get(e.user_id, {}).get("solve_count", 0),
                "categories":      cat_map.get(e.user_id, {}),
                "first_bloods":    len(fb_map.get(e.user_id, [])),
                "avg_rank_pct":    rank_map.get(e.user_id, 100.0),
                "locations":       loc_map.get(e.user_id, []),
                "genuine_score":   genuine.get(e.user_id, {}).get("score", 0),
            } for e in rows]

        # ── All suspects, ranked by suspicion score ──────────────────────────
        suspects = sorted(per_user.values(), key=lambda r: r["score"], reverse=True)
        for i, s in enumerate(suspects):
            uid  = s["user_id"]
            name = u_names.get(uid, f"user#{uid}")
            g    = genuine.get(uid, {})
            uc   = ctx.get(uid, {})
            s["rank"]          = i + 1
            s["name"]          = name
            s["genuine_score"] = g.get("score", 0)
            s["genuine_meta"]  = g
            s["ctf_score"]     = uc.get("score", 0)
            s["ctf_rank"]      = uc.get("rank", "—")
            s["solve_count"]   = uc.get("solve_count", 0)
            s["categories"]    = cat_map.get(uid, {})
            s["first_bloods"]  = len(fb_map.get(uid, []))
            s["avg_rank_pct"]  = rank_map.get(uid, 100.0)
            s["locations"]     = loc_map.get(uid, [])
            # Narrative top reason
            s["narrative"]     = generate_suspect_narrative(uid, name, s, uc, detector_events)

        # ── Genuine users ─────────────────────────────────────────────────────
        # Show everyone whose genuine score meets the minimum threshold.
        # We do NOT require zero suspicion — many innocent players get minor
        # flags from broad detectors (crowd wrong flags, lab NAT IP, etc.).
        # Configurable via filter.genuine_min_score (default 50).
        genuine_min = cfg_int("filter.genuine_min_score", 50)
        genuine_users = []
        for uid, uc in ctx.items():
            if uid in admin_ids:
                continue
            g = genuine.get(uid, {})
            if g.get("score", 0) < genuine_min:
                continue
            susp_score = per_user.get(uid, {}).get("score", 0)
            name = u_names.get(uid, f"user#{uid}")
            genuine_users.append({
                "user_id":       uid,
                "name":          name,
                "ctf_score":     uc["score"],
                "ctf_rank":      uc["rank"],
                "solve_count":   uc["solve_count"],
                "genuine_score": g.get("score", 0),
                "susp_score":    susp_score,
                "genuine_meta":  g,
                "categories":    cat_map.get(uid, {}),
                "first_bloods":  len(fb_map.get(uid, [])),
                "avg_rank_pct":  rank_map.get(uid, 100.0),
                "locations":     loc_map.get(uid, []),
                "narrative":     generate_genuine_narrative(uid, name, g, uc, peer_max_fb),
            })
        # Sort by genuine score descending, then CTF rank ascending
        genuine_users.sort(key=lambda r: r["ctf_rank"] if isinstance(r["ctf_rank"], int) else 9999)

        # Detector status
        meta = {m.detector: m for m in CMRunMeta.query.all()}
        detector_status = []
        for name, (_, enable_key) in DETECTORS.items():
            m = meta.get(name)
            detector_status.append({
                "name": name,
                "enabled": cfg(enable_key, "1") == "1",
                "last_run": to_iso(m.last_run) if m else "",
                "events": m.last_event_count if m else 0,
                "duration_ms": m.last_duration_ms if m else 0,
                "filtered_count": len(detector_events.get(name, [])),
            })

        # Flatten detector_events into a JSON-serialisable dict for the modal
        det_events_flat = {}
        for det_name, evts in detector_events.items():
            det_events_flat[det_name] = [
                {
                    "user_id":      e.get("user_id"),
                    "severity":     e.get("severity", 0),
                    "detail":       e.get("detail", ""),
                    "occurred_at":  to_iso(e.get("occurred_at")),
                    "challenge_name": e.get("challenge_name", ""),
                }
                for e in evts
            ]

        return render_template(
            "anti_cheat/dashboard.html",
            suspects=suspects,
            genuine_users=genuine_users,
            detector_events=detector_events,
            detector_status=detector_status,
            detector_names=all_det_names,
            total_events=CMSuspicionEvent.query.count(),
            total_users_flagged=len(per_user),
            total_genuine=len(genuine_users),
            show_admins=show_admins,
            admins_hidden=bool(admin_ids),
            detector_events_json=jsonify_safe(det_events_flat),
            user_names_json=jsonify_safe({u.id: u.name for u in Users.query.all()}),
        )

    # ── helpers shared by export routes ────────────────────────────────────
    def _build_export_data(show_admins=False):
        """Return (suspects, genuine_users) with full context for export."""
        hide_by_default = cfg_bool("filter.hide_admins", True)
        if show_admins:
            admin_ids = set()
        elif hide_by_default:
            admin_ids = query_module.admin_user_ids()
        else:
            admin_ids = set()

        per_user  = compute_user_scores(exclude_ids=admin_ids)
        genuine   = compute_genuine_indicators(exclude_ids=admin_ids)
        u_names   = user_name_map()
        ctx       = user_scores_and_ranks()
        fb_map    = first_bloods_per_user()
        cat_map   = category_solves_per_user()
        rank_map  = avg_solve_rank_per_user()
        loc_map   = user_ip_locations()

        all_det_names = list(DETECTORS.keys())
        detector_events = {}
        for det_name in all_det_names:
            rows = (CMSuspicionEvent.query
                    .filter_by(detector=det_name)
                    .order_by(desc(CMSuspicionEvent.severity))
                    .all())
            if admin_ids:
                rows = [e for e in rows if e.user_id not in admin_ids]
            detector_events[det_name] = [{"user_id": e.user_id, "severity": e.severity, "detail": e.detail} for e in rows]

        suspects = sorted(per_user.values(), key=lambda r: r["score"], reverse=True)
        for i, s in enumerate(suspects):
            uid  = s["user_id"]
            name = u_names.get(uid, f"user#{uid}")
            uc   = ctx.get(uid, {})
            g    = genuine.get(uid, {})
            s["suspect_rank"] = i + 1
            s["name"]          = name
            s["ctf_score"]     = uc.get("score", 0)
            s["ctf_rank"]      = uc.get("rank", "—")
            s["solve_count"]   = uc.get("solve_count", 0)
            s["categories"]    = cat_map.get(uid, {})
            s["first_bloods"]  = len(fb_map.get(uid, []))
            s["avg_rank_pct"]  = rank_map.get(uid, 100.0)
            s["locations"]     = loc_map.get(uid, [])
            s["genuine_score"] = g.get("score", 0)
            s["narrative"]     = generate_suspect_narrative(uid, name, s, uc, detector_events)

        suspects.sort(key=lambda r: r["ctf_rank"] if isinstance(r["ctf_rank"], int) else 9999)
        for i, s in enumerate(suspects):
            s["suspect_rank"] = i + 1

        peer_max_fb = max((len(fbs) for uid, fbs in fb_map.items() if uid not in admin_ids), default=1)
        genuine_min = cfg_int("filter.genuine_min_score", 50)
        genuine_users = []
        for uid, uc in ctx.items():
            if uid in admin_ids:
                continue
            g = genuine.get(uid, {})
            if g.get("score", 0) < genuine_min:
                continue
            name = u_names.get(uid, f"user#{uid}")
            genuine_users.append({
                "user_id":       uid,
                "name":          name,
                "ctf_score":     uc["score"],
                "ctf_rank":      uc["rank"],
                "solve_count":   uc["solve_count"],
                "genuine_score": g.get("score", 0),
                "categories":    cat_map.get(uid, {}),
                "first_bloods":  len(fb_map.get(uid, [])),
                "avg_rank_pct":  rank_map.get(uid, 100.0),
                "locations":     loc_map.get(uid, []),
                "narrative":     generate_genuine_narrative(uid, name, g, uc, peer_max_fb),
            })
        genuine_users.sort(key=lambda r: r["ctf_rank"] if isinstance(r["ctf_rank"], int) else 9999)
        return suspects, genuine_users

    @bp.route("/export/csv")
    @admins_only
    def export_csv():
        show_admins = request.args.get("show_admins", "0") == "1"
        suspects, genuine_users = _build_export_data(show_admins)

        buf = io.StringIO()
        w   = csv.writer(buf)

        # ── Suspects sheet ──
        w.writerow(["=== SUSPECTS ==="])
        w.writerow(["Suspect#", "User", "CTF Rank", "CTF Score", "Solves",
                    "Challenges by Category", "First Bloods", "Avg Solve Rank %",
                    "Suspicion Score", "Genuine Score", "Detectors Triggered",
                    "Locations", "Reason / Narrative"])
        for s in suspects:
            cats_str = " | ".join(f"{c}:{n}" for c, n in sorted(s["categories"].items()))
            dets_str = ", ".join(s.get("detectors", {}).keys())
            locs_str = "; ".join(s["locations"])
            w.writerow([
                s["suspect_rank"],
                s["name"],
                s["ctf_rank"],
                s["ctf_score"],
                s["solve_count"],
                cats_str,
                s["first_bloods"],
                f"{s['avg_rank_pct']:.1f}",
                s["score"],
                s["genuine_score"],
                dets_str,
                locs_str,
                s["narrative"].replace("\n", " | "),
            ])

        w.writerow([])
        w.writerow(["=== GENUINE USERS ==="])
        w.writerow(["No#", "User", "CTF Rank", "CTF Score", "Solves",
                    "Challenges by Category", "First Bloods", "Avg Solve Rank %",
                    "Genuine Score", "Locations", "Evidence Narrative"])
        for i, u in enumerate(genuine_users, 1):
            cats_str = " | ".join(f"{c}:{n}" for c, n in sorted(u["categories"].items()))
            locs_str = "; ".join(u["locations"])
            w.writerow([
                i,
                u["name"],
                u["ctf_rank"],
                u["ctf_score"],
                u["solve_count"],
                cats_str,
                u["first_bloods"],
                f"{u['avg_rank_pct']:.1f}",
                u["genuine_score"],
                locs_str,
                u["narrative"].replace("\n", " | "),
            ])

        buf.seek(0)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=anti_cheat_{ts}.csv"},
        )

    @bp.route("/export/pdf")
    @admins_only
    def export_pdf():
        show_admins = request.args.get("show_admins", "0") == "1"
        suspects, genuine_users = _build_export_data(show_admins)

        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak,
            )
            from reportlab.lib.enums import TA_LEFT, TA_CENTER
        except ImportError:
            return "reportlab not installed — cannot generate PDF.", 500

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=landscape(A4),
            leftMargin=1.5*cm, rightMargin=1.5*cm,
            topMargin=1.5*cm, bottomMargin=1.5*cm,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("title", parent=styles["Heading1"], fontSize=14, spaceAfter=6)
        sub_style   = ParagraphStyle("sub",   parent=styles["Normal"], fontSize=7, leading=9)
        head_style  = ParagraphStyle("head",  parent=styles["Normal"], fontSize=7, textColor=colors.white)

        def cell(text, style=sub_style):
            return Paragraph(str(text), style)

        ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        story  = []

        # ── Cover heading ──
        story.append(Paragraph(f"Anti-Cheat Report — {ts_str}", title_style))
        story.append(Paragraph(
            f"{len(suspects)} suspect(s) flagged · {len(genuine_users)} confirmed-clean player(s)",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.4*cm))

        # ── Suspects table ──
        story.append(Paragraph("Suspects — Ranked by Suspicion Score", styles["Heading2"]))
        story.append(Spacer(1, 0.2*cm))

        s_header = ["#", "User", "CTF\nRank", "Score", "Solves",
                    "Categories", "1st\nBloods", "Avg\nRank%",
                    "Susp.\nScore", "Gen.\nScore", "Detectors", "Locations", "Primary Reason"]
        s_col_w  = [0.7*cm, 3.2*cm, 1.3*cm, 1.5*cm, 1.2*cm,
                    3.5*cm, 1.2*cm, 1.3*cm,
                    1.3*cm, 1.3*cm, 3.5*cm, 3.5*cm, 6.0*cm]

        s_data = [[cell(h, head_style) for h in s_header]]
        for s in suspects:
            cats_str = "\n".join(f"{c}: {n}" for c, n in sorted(s["categories"].items()))
            dets_str = "\n".join(s.get("detectors", {}).keys())
            locs_str = "\n".join(s["locations"][:3])
            # First line of narrative only for PDF readability
            narr_first = s["narrative"].split("\n")[0] if s["narrative"] else ""
            s_data.append([
                cell(s["suspect_rank"]),
                cell(s["name"]),
                cell(s["ctf_rank"]),
                cell(s["ctf_score"]),
                cell(s["solve_count"]),
                cell(cats_str),
                cell(s["first_bloods"]),
                cell(f"{s['avg_rank_pct']:.1f}%"),
                cell(s["score"]),
                cell(s["genuine_score"]),
                cell(dets_str),
                cell(locs_str),
                cell(narr_first),
            ])

        def _tbl_style(header_color):
            return TableStyle([
                ("BACKGROUND",   (0,0), (-1,0), header_color),
                ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
                ("FONTSIZE",     (0,0), (-1,-1), 7),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.Color(0.96,0.96,0.98)]),
                ("GRID",         (0,0), (-1,-1), 0.3, colors.Color(0.8,0.8,0.8)),
                ("VALIGN",       (0,0), (-1,-1), "TOP"),
                ("TOPPADDING",   (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",(0,0), (-1,-1), 3),
            ])

        s_tbl = Table(s_data, colWidths=s_col_w, repeatRows=1)
        s_tbl.setStyle(_tbl_style(colors.Color(0.6, 0.1, 0.1)))
        story.append(s_tbl)
        story.append(PageBreak())

        # ── Genuine users table ──
        story.append(Paragraph("Genuine Players — Zero Suspicion Flags", styles["Heading2"]))
        story.append(Spacer(1, 0.2*cm))

        g_header = ["#", "User", "CTF\nRank", "Score", "Solves",
                    "Categories", "1st\nBloods", "Avg\nRank%",
                    "Gen.\nScore", "Locations", "Evidence Summary"]
        g_col_w  = [0.7*cm, 3.2*cm, 1.3*cm, 1.5*cm, 1.2*cm,
                    3.5*cm, 1.2*cm, 1.3*cm,
                    1.3*cm, 3.5*cm, 7.0*cm]

        g_data = [[cell(h, head_style) for h in g_header]]
        for i, u in enumerate(genuine_users, 1):
            cats_str = "\n".join(f"{c}: {n}" for c, n in sorted(u["categories"].items()))
            locs_str = "\n".join(u["locations"][:3])
            narr_first = u["narrative"].split("\n")[0] if u["narrative"] else ""
            g_data.append([
                cell(i),
                cell(u["name"]),
                cell(u["ctf_rank"]),
                cell(u["ctf_score"]),
                cell(u["solve_count"]),
                cell(cats_str),
                cell(u["first_bloods"]),
                cell(f"{u['avg_rank_pct']:.1f}%"),
                cell(u["genuine_score"]),
                cell(locs_str),
                cell(narr_first),
            ])

        g_tbl = Table(g_data, colWidths=g_col_w, repeatRows=1)
        g_tbl.setStyle(_tbl_style(colors.Color(0.1, 0.45, 0.1)))
        story.append(g_tbl)

        doc.build(story)
        buf.seek(0)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
        return Response(
            buf.getvalue(),
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=anti_cheat_{ts}.pdf"},
        )

    @bp.route("/run", methods=["POST"])
    @admins_only
    def run_now():
        if request.is_json:
            data = request.get_json(silent=True) or {}
            detector = data.get("detector")
            if detector and not isinstance(detector, str):
                abort(400)
            only = _validate_detector_names([detector]) if detector else None
        else:
            raw = request.form.getlist("detector") or None
            only = _validate_detector_names(raw) if raw else None
        summary = run_detectors(only=only)
        if request.is_json or request.headers.get("Accept", "").startswith("application/json"):
            return jsonify(summary)
        return redirect(url_for(f"{PLUGIN_NAME}.dashboard"))

    @bp.route("/user/<int:user_id>", methods=["GET"])
    @admins_only
    def user_detail(user_id):
        user = Users.query.filter_by(id=user_id).first_or_404()
        u_names = user_name_map()
        c_names = challenge_name_map()
        events = (
            CMSuspicionEvent.query.filter_by(user_id=user_id)
            .order_by(desc(CMSuspicionEvent.severity), desc(CMSuspicionEvent.id))
            .all()
        )
        event_rows = [{
            "detector": e.detector,
            "severity": e.severity,
            "detail": e.detail,
            "related": u_names.get(e.related_user_id, "") if e.related_user_id else "",
            "related_id": e.related_user_id,
            "challenge": c_names.get(e.challenge_id, "") if e.challenge_id else "",
            "challenge_id": e.challenge_id,
            "occurred_at": to_iso(e.occurred_at),
        } for e in events]

        per_user = compute_user_scores().get(user_id, {})
        genuine = compute_genuine_indicators().get(user_id, {})

        return render_template(
            "anti_cheat/user_detail.html",
            user=user,
            events=event_rows,
            score=per_user.get("score", 0),
            genuine=genuine,
        )

    @bp.route("/config", methods=["GET", "POST"])
    @admins_only
    def config_page():
        if request.method == "POST":
            for key in DEFAULTS.keys():
                if key in request.form:
                    cfg_set(key, _sanitize_config_value(key, request.form[key]))
            # Capture toggle for UA logging
            if "enabled.ua_capture" in request.form:
                cfg_set("enabled.ua_capture", "1")
            else:
                cfg_set("enabled.ua_capture", "0")
            return redirect(url_for(f"{PLUGIN_NAME}.config_page"))

        # Group keys by detector for the UI
        grouped = {}
        for k in DEFAULTS.keys():
            section = k.split(".", 1)[0]
            grouped.setdefault(section, []).append((k, cfg(k, DEFAULTS[k])))
        # Stable section order (include new detectors + filter section)
        order = ["enabled", "filter", "geo", "simul", "mass_fb", "rare", "overlap",
                 "corr", "velocity", "wrong", "brute", "dormant", "swap",
                 "shared_ip", "ip_div", "first_solver", "score",
                 "low_attempt", "hard_easy", "zero_wrong", "travel",
                 "crowd_wrong", "team_ip", "team_flag", "team_corr"]
        grouped = [(s, grouped[s]) for s in order if s in grouped]

        return render_template(
            "anti_cheat/config.html",
            grouped=grouped,
            ua_capture=cfg_bool("enabled.ua_capture", False),
            detectors=list(DETECTORS.keys()),
        )

    @bp.route("/reset", methods=["POST"])
    @admins_only
    def reset():
        """Wipe all events. Config is preserved."""
        CMSuspicionEvent.query.delete()
        CMRunMeta.query.delete()
        db.session.commit()
        if request.is_json:
            return jsonify({"success": True})
        return redirect(url_for(f"{PLUGIN_NAME}.dashboard"))

    # 5. Register blueprint at /admin/anti_cheat
    app.register_blueprint(bp, url_prefix=PLUGIN_URL_PREFIX)

    # 6. Also expose /admin/plugins/ctfd_anti_cheat → config page so CTFd's
    # legacy "Plugin Config" panel works.
    @app.route(f"/admin/plugins/{PLUGIN_NAME}", methods=["GET"])
    @admins_only
    def _legacy_config():
        return redirect(url_for(f"{PLUGIN_NAME}.config_page"))
