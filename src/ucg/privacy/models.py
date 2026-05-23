from enum import StrEnum

from pydantic import BaseModel, Field


class DataSubjectCategory(StrEnum):
    CUSTOMER = "customer"
    EMPLOYEE = "employee"
    PROSPECT = "prospect"
    PARTNER = "partner"


class ProcessingActivity(BaseModel):
    id: str
    purpose: str
    lawful_basis: str
    retention_period: str
    subject_categories: list[DataSubjectCategory] = Field(default_factory=list)
    obligation_ids: list[str] = Field(default_factory=list)
