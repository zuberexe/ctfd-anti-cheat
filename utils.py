"""
ctfd_anti_cheat.utils
========================

Small helpers used across detectors. Kept dependency-free (stdlib only).
"""

import hashlib
import ipaddress
import json
from datetime import datetime

from CTFd.models import db

from .models import CMConfig


# ---------------------------------------------------------------------------
#  Default thresholds
# ---------------------------------------------------------------------------
# >>> TUNE HERE <<<  These defaults are seeded into cm_config on first load.
# Admins can then override them from the Settings page without editing code.
# Each detector reads its own keys via cfg_int / cfg_float / cfg_bool below.
DEFAULTS = {
    # Lab / campus NAT IPs to exclude from IP-sharing analysis (comma-separated)
    # Example: "27.109.22.18" is the NFSU campus NAT — not inherently suspicious
    "lab.known_ips":            "",

    # Simultaneous solve — tiered confidence thresholds (seconds)
    "simul.high_conf_sec":      "30",   # < 30s = HIGH confidence flag share
    "simul.med_conf_sec":       "120",  # 30–120s = MEDIUM
    "simul.low_conf_sec":       "300",  # 120–300s = LOW signal

    # Master enable flags — flip these to disable a whole detector
    "enabled.simultaneous":     "1",
    "enabled.mass_after_fb":    "1",
    "enabled.first_try_rare":   "1",
    "enabled.ip_ua_overlap":    "1",
    "enabled.solve_correlation":"1",
    "enabled.velocity":         "1",
    "enabled.identical_wrong": "1",
    "enabled.brute_force":      "1",
    "enabled.dormant_burst":    "1",
    "enabled.session_swap":     "1",

    # ---- per-detector knobs ----
    # Near-simultaneous solves: two users solving the same chall within N sec
    "simul.window_sec":         "60",
    "simul.min_severity":       "40",

    # Mass solves after first blood: solve within X% of first-blood time on
    # N or more challenges (suggests piggy-backing on someone else's flag)
    "mass_fb.ratio_pct":        "20",     # solved within 20% of FB time
    "mass_fb.min_chall_count":  "3",      # on at least 3 challenges
    "mass_fb.severity":         "50",

    # First-try solves on rare challenges (solver_count <= threshold AND zero
    # failed attempts before the correct one)
    "rare.max_solver_count":    "5",
    "rare.severity":            "35",

    # IP/UA overlap: N+ distinct accounts sharing a fingerprint
    "overlap.min_accounts":     "2",
    "overlap.severity":         "45",

    # Solve correlation: % of solved challenges in identical order with peer
    "corr.min_shared_solves":   "5",
    "corr.order_match_pct":     "80",
    "corr.severity":            "55",

    # Velocity: solves-per-minute z-score above this is anomalous
    "velocity.zscore":          "3.0",
    "velocity.min_solves":      "5",
    "velocity.severity":        "30",

    # Identical wrong-flag submissions: same wrong flag submitted by N+ users
    "wrong.min_users":          "2",
    "wrong.severity":           "40",

    # Brute force: N failures within window seconds on one challenge
    "brute.window_sec":         "120",
    "brute.failures":           "30",
    "brute.severity":           "25",

    # Dormant burst: account inactive for N hours then K solves within M min
    "dormant.silent_hours":     "12",
    "dormant.burst_count":      "5",
    "dormant.burst_window_min": "30",
    "dormant.severity":         "30",

    # Session swap: same IP+UA used by different users within N seconds
    "swap.window_sec":          "300",
    "swap.severity":            "50",

    # First solver on high-value challenge with zero prior failed attempts
    "enabled.first_solver_hv":      "1",
    "first_solver.min_value":       "300",   # minimum challenge point value
    "first_solver.severity":        "65",
    "first_solver.accumulate":      "1",     # scale severity when user hits multiple

    # Shared correct IP: multiple accounts submit correct flag from same IP
    "shared_ip.severity":       "80",
    "enabled.shared_correct_ip": "1",

    # IP diversity: user submitting from more than N distinct IPs
    "ip_div.max_ips":           "5",
    "ip_div.severity":          "30",
    "enabled.ip_diversity":     "1",

    # Score model
    "score.cap":                "100",   # per-user score is capped here

    # Filter: hide admin accounts from all detection results by default
    "filter.hide_admins":       "1",
    # Minimum genuine score (0-100) required to appear in the Genuine Users tab
    # Lower this if too few users appear; raise it to show only the strongest cases
    "filter.genuine_min_score": "50",

    # Low wrong-attempt ratio — many solves but almost no failures
    "enabled.low_attempt_ratio": "1",
    "low_attempt.min_solves":   "10",   # require at least N correct solves
    "low_attempt.max_ratio":    "0.5",  # flag if wrong/correct ratio < this
    "low_attempt.severity":     "60",

    # Hard-before-easy solve order
    "enabled.hard_before_easy": "1",
    "hard_easy.first_n":        "5",    # look at first N solves
    "hard_easy.hard_min":       "100",  # 'hard' challenge threshold (pts)
    "hard_easy.easy_max":       "50",   # 'easy' challenge threshold (pts)
    "hard_easy.severity":       "60",

    # Zero wrong attempts on hard challenges
    "enabled.zero_wrong_hard":  "1",
    "zero_wrong.min_count":     "3",    # flag if N+ hard solves have 0 prior fails
    "zero_wrong.hard_min":      "100",
    "zero_wrong.severity":      "65",

    # Impossible travel — same user, different geolocations within window
    "enabled.impossible_travel":"1",
    "travel.window_min":        "60",   # minutes
    "travel.severity":          "70",

    # Banned user activity
    "enabled.banned_activity":  "1",

    # Crowd wrong-flag — same wrong answer submitted by many users
    "enabled.crowd_wrong_flag": "1",
    "crowd_wrong.min_users":    "10",   # how many users = 'crowd'
    "crowd_wrong.severity":     "65",

    # Location anomaly: flag IPs outside allowed regions
    # Set geo.enabled to "1" and fill at least one of the allow-lists.
    # Values are comma-separated; match is case-insensitive.
    # country uses ISO 2-letter codes (IN, US, GB …)
    "geo.enabled":              "0",
    "geo.allowed_countries":    "",    # e.g. "IN"
    "geo.allowed_states":       "",    # e.g. "Gujarat,Maharashtra"
    "geo.allowed_cities":       "",    # e.g. "Ahmedabad,Surat,Vadodara,Gandhinagar"
    "geo.severity":             "60",
    "geo.flag_unknown":         "0",   # "1" = flag IPs that couldn't be geolocated

    # Inter-team IP sharing (team mode only)
    "enabled.inter_team_ip":    "1",
    "team_ip.min_teams":        "2",
    "team_ip.severity":         "70",

    # Inter-team flag sharing (team mode only)
    "enabled.inter_team_flag":  "1",
    "team_flag.window_sec":     "120",
    "team_flag.severity":       "80",

    # Team solve-order correlation (team mode only)
    "enabled.team_solve_corr":  "1",
    "team_corr.min_shared":     "5",
    "team_corr.order_match_pct":"80",
    "team_corr.severity":       "60",
}


# ---------------------------------------------------------------------------
#  Config helpers
# ---------------------------------------------------------------------------
def seed_defaults():
    """Insert any missing default keys. Existing values are NOT overwritten."""
    existing = {c.key for c in CMConfig.query.all()}
    for k, v in DEFAULTS.items():
        if k not in existing:
            db.session.add(CMConfig(k, v))
    db.session.commit()


def cfg(key, default=None):
    row = CMConfig.query.filter_by(key=key).first()
    return row.value if row else default


def cfg_int(key, default=0):
    try:
        return int(cfg(key, default))
    except (TypeError, ValueError):
        return default


def cfg_float(key, default=0.0):
    try:
        return float(cfg(key, default))
    except (TypeError, ValueError):
        return default


def cfg_bool(key, default=False):
    v = cfg(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def cfg_set(key, value):
    row = CMConfig.query.filter_by(key=key).first()
    if row:
        row.value = str(value)
    else:
        db.session.add(CMConfig(key, str(value)))
    db.session.commit()


# ---------------------------------------------------------------------------
#  Misc
# ---------------------------------------------------------------------------
def fingerprint(ip, ua):
    """Stable hash of (ip, ua) used to bucket sessions in CMUserAgentLog."""
    return hashlib.sha256(f"{ip or ''}|{ua or ''}".encode("utf-8")).hexdigest()


def ip_subnet(ip, prefix=24):
    """Reduce an IP to its /24 (v4) or /48 (v6) for "same network" comparisons.
    Returns the original string if parsing fails — we never want to crash a
    detector because somebody had a malformed forwarded header."""
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            prefix = 48
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net.network_address)
    except (ValueError, TypeError):
        return ip


def geo_lookup(ip):
    """Return {country_code, country, state, city} for an IP, or None on failure.
    Uses the dbip-city-lite database bundled with python-geoacumen-city."""
    if not ip or ip in ("127.0.0.1", "::1"):
        return None
    try:
        import maxminddb
        import geoacumen_city
        import os
        db_path = os.path.join(
            os.path.dirname(geoacumen_city.__file__),
            "db", "dbip-city-lite-latest.mmdb",
        )
        with maxminddb.open_database(db_path) as reader:
            r = reader.get(ip)
        if not r:
            return None
        subdivisions = r.get("subdivisions") or []
        return {
            "country_code": r.get("country", {}).get("iso_code", ""),
            "country":      r.get("country", {}).get("names", {}).get("en", ""),
            "state":        subdivisions[0].get("names", {}).get("en", "") if subdivisions else "",
            "city":         r.get("city", {}).get("names", {}).get("en", ""),
        }
    except Exception:
        return None


def to_iso(dt):
    """Safe datetime -> ISO string for templates/JSON."""
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.isoformat(sep=" ", timespec="seconds")
    return str(dt)


def jsonify_safe(obj):
    """json.dumps that escapes HTML entities to prevent XSS when embedded
    in <script> blocks via Jinja2's |safe filter."""
    def _default(o):
        if isinstance(o, datetime):
            return to_iso(o)
        return str(o)
    raw = json.dumps(obj, default=_default)
    # Escape characters that could break out of a <script> context or
    # enable HTML injection. Same approach as Flask/Jinja2's tojson filter.
    return (raw
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("'", "\\u0027")
            )
