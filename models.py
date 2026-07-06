"""
ctfd_anti_cheat.models
=========================

All plugin-owned tables live here. We deliberately do NOT add columns to core
CTFd tables (Users, Submissions, etc.) so the plugin can be uninstalled cleanly
and so CTFd upgrades never collide with us.

Tables:
    cm_config            -- key/value config (thresholds, toggles)
    cm_suspicion_events  -- one row per detection hit, joined back to user+chall
    cm_ua_log            -- optional forward-looking UA capture (populated by
                            request hook when feature is enabled)
    cm_run_meta          -- last-run timestamps & summary per detector
"""

from CTFd.models import db


# ---------------------------------------------------------------------------
#  Config k/v store
# ---------------------------------------------------------------------------
class CMConfig(db.Model):
    """Plugin configuration. We keep a separate table instead of reusing
    CTFd's `Configs` so admins can wipe plugin state without touching core."""

    __tablename__ = "cm_config"

    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text)

    def __init__(self, key, value):
        self.key = key
        self.value = value


# ---------------------------------------------------------------------------
#  Detection events
# ---------------------------------------------------------------------------
class CMSuspicionEvent(db.Model):
    """One row per detection hit. The dashboard aggregates these into per-user
    suspicion scores. Keeping events atomic (rather than rolling up into a
    single per-user record) means we can show admins the *why* not just the
    *who*."""

    __tablename__ = "cm_suspicion_events"

    id = db.Column(db.Integer, primary_key=True)
    detector = db.Column(db.String(64), nullable=False, index=True)
    # Subject of the event. user_id is always set; team_id only in team mode.
    user_id = db.Column(db.Integer, index=True, nullable=False)
    team_id = db.Column(db.Integer, index=True, nullable=True)
    # Optional second party (e.g. the other user in a near-simultaneous solve)
    related_user_id = db.Column(db.Integer, index=True, nullable=True)
    # Optional challenge anchor
    challenge_id = db.Column(db.Integer, index=True, nullable=True)
    # Severity 0-100, used to weight the per-user suspicion score
    severity = db.Column(db.Integer, nullable=False, default=10)
    # Free-text human-readable explanation shown in the UI
    detail = db.Column(db.Text)
    # When the suspicious *behavior* happened (not when we detected it)
    occurred_at = db.Column(db.DateTime, index=True)
    # When we wrote this row
    created_at = db.Column(db.DateTime, server_default=db.func.now())


# ---------------------------------------------------------------------------
#  Optional forward-looking UA capture
# ---------------------------------------------------------------------------
class CMUserAgentLog(db.Model):
    """CTFd's `Tracking` table stores IP but not User-Agent. If admins enable
    UA capture in the config page, our `before_request` hook writes a row here
    for every submission attempt. UA overlap detection uses this when present
    and silently falls back to IP-only matching when empty."""

    __tablename__ = "cm_ua_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    ip = db.Column(db.String(64), index=True)
    ua = db.Column(db.String(512), index=True)
    # SHA-256 of (ip|ua) — denormalized for cheap GROUP BY in queries
    fingerprint = db.Column(db.String(64), index=True)
    seen_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)


# ---------------------------------------------------------------------------
#  Detector run bookkeeping
# ---------------------------------------------------------------------------
class CMRunMeta(db.Model):
    """One row per detector, updated each time it runs. Lets the dashboard
    show 'last scanned' and 'events created' without re-counting every load."""

    __tablename__ = "cm_run_meta"

    detector = db.Column(db.String(64), primary_key=True)
    last_run = db.Column(db.DateTime)
    last_event_count = db.Column(db.Integer, default=0)
    last_duration_ms = db.Column(db.Integer, default=0)
