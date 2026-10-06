"""Ivanti Neurons for ITSM — the FRSHEATIntegration SOAP service (D-050).

Hand-written SOAP 1.1 over httpx for the handful of operations the ticket
integration needs, shaped exactly as the tenant's WSDL (namespace
``SaaS.Services``). Responses are parsed with defusedxml — this is XML from
another system (CLAUDE.md §2.3). Every request is SSRF-checked, redirects are
off, and the API key only ever goes to the configured tenant host.

One ``IvantiClient`` = one session: it authenticates with the tenant API key
on first use.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse
from xml.etree.ElementTree import Element
from xml.sax.saxutils import escape, quoteattr

import httpx
from defusedxml import ElementTree as SafeET

from ..core.security.ssrf import SsrfBlockedError, validate_outbound_url

NS = "SaaS.Services"
SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SERVICE_PATH = "/ServiceAPI/FRSHEATIntegration.asmx"
TIMEOUT_SECONDS = 60.0
#: Safety stop for paged list searches.
MAX_PAGES = 50


class IvantiError(Exception):
    """A failed call; ``str()`` is safe to show an analyst or admin."""


def _q(tag: str) -> str:
    return f"{{{NS}}}{tag}"


def http_client() -> httpx.Client:
    """Redirects off: a redirect could otherwise bypass the SSRF guard."""
    return httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False)


class IvantiClient:
    def __init__(self, base_url: str, tenant_id: str, api_key: str, client: httpx.Client) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise IvantiError("The tenant URL must start with https://")
        self._host = parsed.hostname
        self._endpoint = f"https://{parsed.netloc}{SERVICE_PATH}"
        self._tenant = tenant_id
        self._api_key = api_key
        self._client = client
        self._session: str | None = None

    # ─── Session ─────────────────────────────────────────────────────────────

    def authenticate(self) -> str:
        if self._session is None:
            body = _el("apiKey", self._api_key) + _el("tenantId", self._tenant)
            result = self._call("AuthenticateTenantAPIKey", body)
            key = (result.text or "").strip()
            if not key or key.lower().startswith(("error", "invalid", "unauthorized")):
                raise IvantiError("Ivanti rejected the API key (or the tenant ID).")
            self._session = key
        return self._session

    def _auth(self) -> str:
        return _el("sessionKey", self.authenticate()) + _el("tenantId", self._tenant)

    # ─── Reading ─────────────────────────────────────────────────────────────

    def schema_fields(self, object_name: str) -> dict[str, bool]:
        """Field name → required?, from ``GetSchemaForObject`` (an XML
        schema). Empty if the schema can't be read."""
        result = self._call(
            "GetSchemaForObject", self._auth() + _el("objectName", object_name.rstrip("#"))
        )
        text = (result.text or "").strip()
        if not text:
            return {}
        try:
            root = SafeET.fromstring(text)
        except Exception:
            return {}
        fields: dict[str, bool] = {}
        for el in root.iter():
            name = el.attrib.get("name") or el.attrib.get("Name")
            if name and el.tag.rsplit("}", 1)[-1].lower() in {"element", "field", "attribute"}:
                min_occurs = el.attrib.get("minOccurs")
                required = el.attrib.get("use") == "required" or (
                    min_occurs is not None and min_occurs != "0"
                )
                fields[name] = required or el.attrib.get("Required", "").lower() == "true"
        return fields

    def search(
        self,
        bo: str,
        fields: Iterable[str],
        where: Iterable[tuple[str, str]] = (),
    ) -> list[dict[str, str]]:
        """Records of ``bo`` (each as field → value) matching every
        ``(field, value)`` in ``where``. Pages through ``PaginationSearch``."""
        select = "".join(f"<Field Name={quoteattr(f)} />" for f in fields)
        rules = "".join(
            f'<Rule Join="AND" Condition="=" ConditionType="ByField" '
            f'Field={quoteattr(field)} Value={quoteattr(value)} Required="false" '
            f'IsClosingBracket="false" BracketLevel="0"><Rules /></Rule>'
            for field, value in where
        )
        query = (
            f"<ObjectQuery><From Object={quoteattr(bo)} />"
            f'<Select All="false"><Fields>{select}</Fields></Select>'
            + (f"<Where>{rules}</Where>" if rules else "")
            + "</ObjectQuery>"
        )
        records: list[dict[str, str]] = []
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            result = self._call(
                "PaginationSearch", self._auth() + query + _el("skip", str(len(records)))
            )
            self._check_status(result)
            page = [_fields(obj) for obj in result.iter(_q("WebServiceBusinessObject"))]
            fresh = [r for r in page if _identity(r) not in seen]
            if not fresh:
                break
            seen.update(_identity(r) for r in fresh)
            records.extend(fresh)
        return records

    def find(self, bo: str, rec_id: str) -> dict[str, str]:
        result = self._call(
            "FindBusinessObject", self._auth() + _el("boType", bo) + _el("recId", rec_id)
        )
        self._check_status(result)
        obj = result.find(_q("obj"))
        return _fields(obj) if obj is not None else {}

    # ─── Writing ─────────────────────────────────────────────────────────────

    def create(self, object_type: str, values: dict[str, str]) -> tuple[str, dict[str, str]]:
        """Create a record; returns ``(RecId, the record's fields)``."""
        fields = "".join(
            "<ObjectCommandDataFieldValue>"
            + _el("Name", name)
            + _el("Value", value)
            + "</ObjectCommandDataFieldValue>"
            for name, value in values.items()
        )
        body = (
            self._auth()
            + "<commandData>"
            + _el("ObjectType", object_type)
            + f"<Fields>{fields}</Fields>"
            + "</commandData>"
        )
        result = self._call("CreateObject", body)
        self._check_status(result)
        rec_id = (result.findtext(_q("recId")) or "").strip()
        if not rec_id:
            raise IvantiError("Ivanti didn't return the new record's ID.")
        obj = result.find(_q("obj"))
        return rec_id, (_fields(obj) if obj is not None else {})

    def add_attachment(self, object_type: str, rec_id: str, file_name: str, data: bytes) -> None:
        body = (
            self._auth()
            + "<commandData>"
            + _el("ObjectId", rec_id)
            + _el("ObjectType", object_type)
            + _el("fileName", file_name)
            + _el("fileData", base64.b64encode(data).decode("ascii"))
            + _el("ForceSaveInDatabase", "true")
            + "</commandData>"
        )
        self._check_status(self._call("AddAttachment", body))

    # ─── SOAP ────────────────────────────────────────────────────────────────

    def _call(self, operation: str, body: str) -> Element:
        envelope = (
            '<?xml version="1.0" encoding="utf-8"?>'
            f'<soap:Envelope xmlns:soap="{SOAP_NS}">'
            f'<soap:Body><{operation} xmlns="{NS}">{body}</{operation}></soap:Body>'
            "</soap:Envelope>"
        )
        if urlparse(self._endpoint).hostname != self._host:  # pragma: no cover - invariant
            raise IvantiError("Refusing to send the API key to another host.")
        try:
            validate_outbound_url(self._endpoint)
        except SsrfBlockedError as exc:
            raise IvantiError(f"{exc.reason}. Add {self._host} to OUTBOUND_ALLOWLIST.") from None
        try:
            response = self._client.post(
                self._endpoint,
                content=envelope.encode("utf-8"),
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": f'"{NS}/{operation}"',
                },
            )
        except httpx.HTTPError as exc:
            raise IvantiError(f"Couldn't reach Ivanti: {exc}") from None
        try:
            root = SafeET.fromstring(response.content)
        except Exception:
            raise IvantiError(
                f"Ivanti returned HTTP {response.status_code} with a body that isn't SOAP."
            ) from None
        fault = root.find(f".//{{{SOAP_NS}}}Fault")
        if fault is not None:
            reason = (fault.findtext("faultstring") or "SOAP fault").strip()
            raise IvantiError(f"Ivanti: {reason[:300]}")
        if response.status_code >= 400:
            raise IvantiError(f"Ivanti returned HTTP {response.status_code}.")
        result = root.find(f".//{_q(operation + 'Result')}")
        if result is None:
            raise IvantiError(f"Unexpected Ivanti response to {operation}.")
        return result

    @staticmethod
    def _check_status(result: Element) -> None:
        status = (result.findtext(_q("status")) or "").strip()
        if status and status.lower() != "success":
            reason = (result.findtext(_q("exceptionReason")) or status).strip()
            raise IvantiError(f"Ivanti: {reason[:300]}")


def _el(tag: str, value: str) -> str:
    return f"<{tag}>{escape(value)}</{tag}>"


def _fields(obj: Element) -> dict[str, str]:
    out: dict[str, str] = {}
    rec_id = obj.findtext(_q("RecID"))
    if rec_id:
        out["RecId"] = rec_id
    for fv in obj.iter(_q("WebServiceFieldValue")):
        name = fv.findtext(_q("Name"))
        if name:
            out[name] = (fv.findtext(_q("Value")) or "").strip()
    return out


def _identity(record: dict[str, Any]) -> str:
    return str(record.get("RecId") or sorted(record.items()))
