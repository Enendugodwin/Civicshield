"""Pydantic schemas for Asset / Service / Relationship."""

from pydantic import BaseModel


class AssetOut(BaseModel):
    id: int
    name: str
    kind: str
    zone: str
    status: str
    hostname: str = ""
    owner: str = ""
    criticality: str = "low"

    model_config = {"from_attributes": True}


class ServiceOut(BaseModel):
    id: int
    name: str
    zone: str
    population_served: int

    model_config = {"from_attributes": True}


class RelationshipOut(BaseModel):
    id: int
    source_type: str
    source_id: int
    target_type: str
    target_id: int
    rel: str

    model_config = {"from_attributes": True}
