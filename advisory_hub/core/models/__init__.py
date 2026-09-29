"""SQLAlchemy models. Import everything here so Alembic autogenerate sees it."""

from .advisory import (
    Advisory,
    AdvisoryAttachment,
    AdvisoryCve,
    AdvisoryFlag,
    AdvisoryIoc,
    AdvisoryProduct,
    AdvisoryTtp,
    Blob,
    Comment,
    CveCpe,
    RelatedAdvisory,
    Source,
    StatusChange,
)
from .base import Base
from .inventory import (
    IntegrationCredential,
    InventoryDevice,
    InventoryDeviceSoftware,
    InventorySnapshot,
    InventorySoftware,
    InventorySource,
    ScanMatch,
    ScanRun,
    VendorAlias,
)
from .system import SystemIntegration
from .user import ApiToken, AuditLog, Session, User

__all__ = [
    "Advisory",
    "AdvisoryAttachment",
    "AdvisoryCve",
    "AdvisoryFlag",
    "AdvisoryIoc",
    "AdvisoryProduct",
    "AdvisoryTtp",
    "ApiToken",
    "AuditLog",
    "Base",
    "Blob",
    "Comment",
    "CveCpe",
    "IntegrationCredential",
    "InventoryDevice",
    "InventoryDeviceSoftware",
    "InventorySnapshot",
    "InventorySoftware",
    "InventorySource",
    "RelatedAdvisory",
    "ScanMatch",
    "ScanRun",
    "Session",
    "Source",
    "StatusChange",
    "SystemIntegration",
    "User",
    "VendorAlias",
]
