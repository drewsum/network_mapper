"""Organization rules: which organization a domain suffix or network (ASN) belongs to,
on top of the bundled map (netmap/orgs.py). Changes regroup every domain right away."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from netmap import orgs
from netmap.api.deps import DB
from netmap.collector.categories import assign_categories
from netmap.collector.orgs import assign_organizations, classifier
from netmap.db.models import Domain, OrgRule

router = APIRouter()


class OrgRuleIn(BaseModel):
    kind: Literal[orgs.RULE_KINDS]  # type: ignore[valid-type]
    value: str = Field(max_length=253)  # a domain suffix, or an AS number ("AS15169" works)
    organization: str = Field(max_length=orgs.MAX_NAME * 2)


class OrgRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    value: str
    organization: str
    created_at: datetime


class OrgRuleSaved(OrgRuleOut):
    regrouped: int  # domains whose organization changed


class Organization(BaseModel):
    name: str
    domains: int  # domains grouped under it


@router.get("/api/organizations", response_model=list[Organization])
def organizations(db: DB) -> list[Organization]:
    """Every organization the map and rules know of, with how many domains each has,
    most first."""
    counts = dict(
        db.execute(
            select(Domain.organization, func.count())
            .where(Domain.organization.is_not(None))
            .group_by(Domain.organization)
        ).all()
    )
    names = set(classifier(db).names()) | set(counts)
    return sorted(
        (Organization(name=n, domains=counts.get(n, 0)) for n in names),
        key=lambda o: (-o.domains, o.name.casefold()),
    )


@router.get("/api/org-rules", response_model=list[OrgRuleOut])
def list_rules(db: DB) -> list[OrgRule]:
    return list(db.scalars(select(OrgRule).order_by(OrgRule.kind.desc(), OrgRule.value)))


@router.post("/api/org-rules", response_model=OrgRuleSaved)
def save_rule(rule: OrgRuleIn, db: DB) -> OrgRuleSaved:
    """Add a rule, or replace the one for the same suffix or ASN."""
    try:
        name = orgs.normalize_name(rule.organization)
        if rule.kind == orgs.SUFFIX:
            value = orgs.normalize_suffix(rule.value)
        else:
            value = str(orgs.normalize_asn(rule.value))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    stmt = insert(OrgRule).values(kind=rule.kind, value=value, organization=name)
    saved = db.scalars(
        stmt.on_conflict_do_update(
            index_elements=[OrgRule.kind, OrgRule.value], set_={"organization": name}
        ).returning(OrgRule)
    ).one()
    out = OrgRuleOut.model_validate(saved)
    regrouped = assign_organizations(db)  # commits
    assign_categories(db)  # an organization's category follows it
    return OrgRuleSaved(**out.model_dump(), regrouped=regrouped)


@router.delete("/api/org-rules/{rule_id}", response_model=OrgRuleSaved)
def delete_rule(rule_id: int, db: DB) -> OrgRuleSaved:
    """Remove a rule: its domains fall back to the bundled map, or "Other"."""
    rule = db.get(OrgRule, rule_id)
    if rule is None:
        raise HTTPException(404, "unknown rule")
    out = OrgRuleOut.model_validate(rule)
    db.delete(rule)
    db.flush()
    regrouped = assign_organizations(db)  # commits
    assign_categories(db)
    return OrgRuleSaved(**out.model_dump(), regrouped=regrouped)
