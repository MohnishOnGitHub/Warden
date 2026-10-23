"""Policy engine: match rules from config/policy.yaml against trusted facts.

evaluate_policy() never sees ticket text. It gets the tool call, the requester id
(from the users table, via the caller) and the ticket id, and looks everything else
up in the directory. Any error inside it means BLOCK (fail closed).
"""
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.db import ROOT
from app.models import ActionStatus
from app.tools import TOOLS

POLICY_PATH = ROOT / "config" / "policy.yaml"

ALLOW, REQUIRE_APPROVAL, BLOCK = "ALLOW", "REQUIRE_APPROVAL", "BLOCK"
SEVERITY = {ALLOW: 0, REQUIRE_APPROVAL: 1, BLOCK: 2}

IT_ROLES = ("it_staff", "it_admin")
# Closing a ticket must always stay possible, so these never count towards P003.
CLOSING_TOOLS = ("resolve_ticket", "escalate_to_human")
# actions.status values that count as a write used up on the ticket.
COUNTED_STATUSES = (ActionStatus.EXECUTED, ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED_EXECUTED)


class PolicyConfigError(Exception):
    """policy.yaml is invalid. Raised at load time so a bad file stops startup."""


class PolicyError(Exception):
    """A fact needed for a decision is missing. Caught by evaluate_policy, which then blocks."""


# Facts ----------------------------------------------------------------------

class Facts:
    """Lazy, cached lookups of everything a predicate may ask about this call."""

    def __init__(self, conn, tool_name, raw_args, requester_id, ticket_id, limits):
        self.conn = conn
        self.tool_name = tool_name
        self.raw_args = raw_args
        self.requester_id = requester_id
        self.ticket_id = ticket_id
        self.limits = limits

    def _row(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()

    @cached_property
    def spec(self):
        return TOOLS.get(self.tool_name)

    @cached_property
    def args(self):
        """The validated arg model, or None for an unknown tool or invalid args."""
        if self.spec is None:
            return None
        try:
            return self.spec.args_model.model_validate(self.raw_args)
        except ValidationError:
            return None

    def arg(self, name):
        return getattr(self.args, name, None) if self.args is not None else None

    @cached_property
    def requester(self):
        row = self._row("SELECT * FROM users WHERE user_id = ?", self.requester_id)
        if row is None:
            raise PolicyError(f"Unknown requester: {self.requester_id}")
        return row

    @cached_property
    def target_user(self):
        uid = self.arg("user_id")
        return None if uid is None else self._row("SELECT * FROM users WHERE user_id = ?", uid)

    @cached_property
    def group(self):
        name = self.arg("group_name")
        return None if name is None else self._row("SELECT * FROM groups WHERE group_name = ?", name)

    @cached_property
    def device(self):
        did = self.arg("device_id")
        return None if did is None else self._row("SELECT * FROM devices WHERE device_id = ?", did)

    @cached_property
    def package(self):
        pkg = self.arg("package")
        return None if pkg is None else self._row("SELECT * FROM software_catalogue WHERE package = ?", pkg)

    @cached_property
    def service(self):
        host, name = self.arg("host"), self.arg("service_name")
        if host is None or name is None:
            return None
        return self._row("SELECT * FROM services WHERE host = ? AND service_name = ?", host, name)

    @cached_property
    def write_count(self):
        """Write actions already executed or waiting for approval on this ticket."""
        counted = [n for n, s in TOOLS.items() if s.write and n not in CLOSING_TOOLS]
        statuses = [s.value for s in COUNTED_STATUSES]
        row = self._row(
            f"SELECT COUNT(*) FROM actions WHERE ticket_id = ? "
            f"AND status IN ({', '.join('?' for _ in statuses)}) AND tool IN ({', '.join('?' for _ in counted)})",
            self.ticket_id, *statuses, *counted)
        return row[0]


# Predicates -----------------------------------------------------------------
# Each takes Facts and returns a bool. The engine only runs a tool-scoped rule when
# the args are valid, so those predicates may use f.args freely. Rules scoped to "*"
# (P001 to P004) can run with invalid args, so their predicates guard for it.

PREDICATES = {}


def predicate(fn):
    PREDICATES[fn.__name__] = fn
    return fn


@predicate
def tool_unknown(f):
    return f.spec is None


@predicate
def args_invalid(f):
    return f.spec is not None and f.args is None


@predicate
def is_counted_write(f):
    return f.args is not None and f.spec.write and f.tool_name not in CLOSING_TOOLS


@predicate
def write_limit_reached(f):
    return f.write_count >= f.limits["max_writes_per_ticket"]


@predicate
def target_user_missing(f):
    return f.arg("user_id") is not None and f.target_user is None


@predicate
def target_is_self(f):
    return f.arg("user_id") == f.requester_id


@predicate
def requester_is_it(f):
    return f.requester["role"] in IT_ROLES


@predicate
def requester_manages_target(f):
    return f.target_user is not None and f.target_user["manager_id"] == f.requester_id


@predicate
def device_not_owned(f):
    return f.device is None or f.device["owner_id"] != f.requester_id


@predicate
def package_denied(f):
    return f.package is not None and f.package["status"] == "denied"


@predicate
def package_needs_approval_or_unknown(f):
    return f.package is None or f.package["status"] == "needs_approval"


@predicate
def package_approved(f):
    return f.package is not None and f.package["status"] == "approved"


@predicate
def group_missing(f):
    return f.group is None


@predicate
def group_privileged(f):
    return f.group is not None and bool(f.group["privileged"])


@predicate
def group_standard(f):
    return f.group is not None and not f.group["privileged"]


@predicate
def service_not_restartable(f):
    return f.service is None or not f.service["restartable"]


@predicate
def service_restartable(f):
    return f.service is not None and bool(f.service["restartable"])


@predicate
def service_prod(f):
    return f.service is not None and f.service["environment"] == "prod"


@predicate
def service_nonprod(f):
    return f.service is not None and f.service["environment"] == "nonprod"


@predicate
def ticket_id_mismatch(f):
    return f.arg("ticket_id") != f.ticket_id


@predicate
def message_unsafe(f):
    """Agent-written text (not ticket text): too long, looks like a secret, or has a link."""
    text = f.arg("message") or f.arg("summary") or ""
    if len(text) > f.limits["max_message_length"]:
        return True
    return any(p.search(text) for p in f.limits["secret_patterns"] + f.limits["link_patterns"])


# Loading and validation -----------------------------------------------------

@dataclass(frozen=True)
class Rule:
    id: str
    tools: object  # "*" or a tuple of tool names
    when: tuple    # of (predicate_name, negated)
    verdict: str
    reason: str
    approver: str | None = None
    obligations: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    rules: tuple
    default: Rule
    limits: dict


RULE_KEYS = {"id", "tools", "when", "verdict", "reason", "approver", "obligations"}


def _parse_rule(raw):
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"Rule must be a mapping: {raw!r}")
    rid = raw.get("id")
    extra = set(raw) - RULE_KEYS
    if extra:
        raise PolicyConfigError(f"{rid}: unknown keys {sorted(extra)}")
    if raw.get("verdict") not in SEVERITY:
        raise PolicyConfigError(f"{rid}: bad verdict {raw.get('verdict')!r}")
    if not raw.get("reason"):
        raise PolicyConfigError(f"{rid}: missing reason")

    tools = raw.get("tools", ())
    if tools != "*":
        if not isinstance(tools, list) or not tools:
            raise PolicyConfigError(f"{rid}: tools must be '*' or a non-empty list")
        unknown = [t for t in tools if t not in TOOLS]
        if unknown:
            raise PolicyConfigError(f"{rid}: unknown tools {unknown}")
        tools = tuple(tools)

    when = []
    for item in raw.get("when", []):
        negated = item.startswith("not ")
        name = item[4:].strip() if negated else item
        if name not in PREDICATES:
            raise PolicyConfigError(f"{rid}: unknown predicate {name!r}")
        when.append((name, negated))

    approver = raw.get("approver")
    if raw["verdict"] == REQUIRE_APPROVAL and not approver:
        raise PolicyConfigError(f"{rid}: REQUIRE_APPROVAL needs an approver")
    if raw["verdict"] != REQUIRE_APPROVAL and approver:
        raise PolicyConfigError(f"{rid}: only REQUIRE_APPROVAL rules may have an approver")

    obligations = raw.get("obligations") or {}
    if not isinstance(obligations, dict):
        raise PolicyConfigError(f"{rid}: obligations must be a mapping")
    return Rule(rid, tools, tuple(when), raw["verdict"], raw["reason"], approver, obligations)


def _parse_limits(raw):
    try:
        return {
            "max_writes_per_ticket": int(raw["max_writes_per_ticket"]),
            "max_message_length": int(raw["max_message_length"]),
            "secret_patterns": [re.compile(p) for p in raw["secret_patterns"]],
            "link_patterns": [re.compile(p) for p in raw["link_patterns"]],
        }
    except (KeyError, TypeError, ValueError, re.error) as e:
        raise PolicyConfigError(f"Bad limits section: {e!r}") from e


def load_policy(path=POLICY_PATH):
    """Read and validate a policy file. Raises PolicyConfigError on anything wrong."""
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise PolicyConfigError(f"Cannot read {path}: {e}") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise PolicyConfigError("Policy file needs a 'rules' list")

    rules = [_parse_rule(r) for r in raw["rules"]]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise PolicyConfigError(f"Duplicate rule ids: {sorted(dupes)}")

    default_raw = raw.get("default")
    if not isinstance(default_raw, dict) or default_raw.get("id") != "P999":
        raise PolicyConfigError("Policy file needs a 'default' section with id P999")
    default = _parse_rule({**default_raw, "tools": "*"})
    if default.verdict != BLOCK:
        raise PolicyConfigError("The default rule P999 must be BLOCK")
    if "P999" in ids:
        raise PolicyConfigError("P999 is the default and cannot also be a rule")

    return Policy(tuple(rules), default, _parse_limits(raw.get("limits")))


POLICY = load_policy()  # loaded at import: a bad file stops the app at startup


# Evaluation -----------------------------------------------------------------

@dataclass(frozen=True)
class PolicyResult:
    verdict: str
    rule_id: str              # the rule that decided
    rule_ids: tuple           # every rule that matched (stored in actions.policy_rule_ids)
    reason: str
    approver_id: str | None = None
    obligations: dict = field(default_factory=dict)
    needs_judge: bool = False


def _rule_matches(rule, facts):
    if rule.tools != "*":
        # Tool-scoped rules need a known tool and valid args.
        if facts.args is None or facts.tool_name not in rule.tools:
            return False
    return all(PREDICATES[name](facts) != negated for name, negated in rule.when)


def _resolve_approver(rule, facts):
    if rule.approver == "group_owner":
        if facts.group is None:
            raise PolicyError("group_owner approver but no group")
        return facts.group["owner_id"]
    return rule.approver


def _blocked(rule_id, reason):
    return PolicyResult(BLOCK, rule_id, (rule_id,), reason)


def evaluate_policy(tool_name, args, requester_id, ticket_id, conn, policy=None):
    """Return the policy verdict for one proposed tool call. Never raises."""
    policy = policy or POLICY
    try:
        facts = Facts(conn, tool_name, args, requester_id, ticket_id, policy.limits)
        facts.requester  # an unknown requester fails closed, even for rules that never look at them

        matched = [r for r in policy.rules if _rule_matches(r, facts)]
        if not matched:
            matched = [policy.default]

        # max() keeps the first rule on ties, so file order breaks ties.
        winner = max(matched, key=lambda r: SEVERITY[r.verdict])
        obligations = {}
        for r in matched:
            obligations.update(r.obligations)

        return PolicyResult(
            verdict=winner.verdict,
            rule_id=winner.id,
            rule_ids=tuple(r.id for r in matched),
            reason=winner.reason,
            approver_id=_resolve_approver(winner, facts) if winner.verdict == REQUIRE_APPROVAL else None,
            obligations=obligations,
            # Communication tools (resolve, escalate) only close the ticket, so they skip the judge.
            needs_judge=bool(facts.spec and facts.spec.write and tool_name not in CLOSING_TOOLS
                             and winner.verdict != BLOCK),
        )
    except Exception as e:  # invariant 4: fail closed
        return _blocked("P999", f"Policy evaluation failed: {type(e).__name__}")
