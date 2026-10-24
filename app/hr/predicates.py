"""Policy predicates for the HR domain. They register into the same table as the IT predicates (additive) and,
like them, look only at trusted tables and the validated tool arguments, never at ticket text."""
from app.warden.policy import predicate


def _candidate(f):
    return f._row("SELECT * FROM hr_candidates WHERE candidate_id = ?", f.arg("candidate_id"))


@predicate
def hr_candidate_missing(f):
    return _candidate(f) is None


@predicate
def hr_not_hiring_manager(f):
    """The requester (from the users table) is not the candidate's hiring manager. False when the candidate is
    unknown: hr_candidate_missing covers that."""
    c = _candidate(f)
    return c is not None and c["hiring_manager_id"] != f.requester_id


def _asset(f):
    return f._row("SELECT * FROM hr_assets WHERE asset_id = ?", f.arg("asset_id"))


@predicate
def hr_asset_unavailable(f):
    a = _asset(f)
    return a is None or a["status"] != "available"


@predicate
def hr_asset_high_spec(f):
    a = _asset(f)
    return a is not None and a["asset_class"] == "high_spec"


def _app(f):
    return f._row("SELECT * FROM hr_apps WHERE app = ?", f.arg("app"))


@predicate
def hr_app_restricted(f):
    """A restricted application, or one the catalogue does not know."""
    a = _app(f)
    return a is None or a["sensitivity"] == "restricted"


@predicate
def hr_app_sensitive(f):
    a = _app(f)
    return a is not None and a["sensitivity"] == "sensitive"
