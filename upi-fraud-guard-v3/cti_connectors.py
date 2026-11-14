"""External CTI source adapters. No offline/demo IOCs are emitted on failures."""
from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import urlsplit

from cti_database import cti_db
from cti_extraction import intelligence_extractor
from cti_normalization import intelligence_normalizer
from cti_security import fetch_secure_content, get_environment_secret

logger = logging.getLogger("upi_fraud_guard.cti_connectors")

class SourceUnconfigured(Exception):
    """Source requires an API credential which is not configured."""

class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())

def _document_indicators(content: str, source: str, reference: str, category: str) -> List[Dict[str, Any]]:
    parsed = intelligence_extractor.extract_all(content, source)
    rows = []
    for item in parsed["indicators"]:
        rows.append({
            **item, "category": category, "description": f"Extracted from retrieved {source} content",
            "reference": reference, "confidence": 45, "source_verified": False,
            "evidence": [{"source": source, "reference": reference, "excerpt": content[:1000]}],
        })
    return rows

class BaseSourceConnector:
    def __init__(self, source_id: str, name: str, source_type: str, url: str, api_key_env: str = "") -> None:
        self.source_id, self.name, self.source_type, self.url, self.api_key_env = source_id, name, source_type, url, api_key_env
        cti_db.upsert_source(source_id, name, source_type, url, bool(api_key_env))

    def fetch_records(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def _normalize(self, item: Dict[str, Any]) -> Dict[str, Any]:
        value, kind = str(item.get("value", "")).strip(), str(item.get("type", "")).lower()
        if not value:
            raise ValueError("empty indicator")
        if kind == "url":
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError("malformed URL")
            value = intelligence_normalizer.canonicalize_url(value)
        elif kind == "domain":
            value = intelligence_normalizer.normalize_domain(value)
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}", value):
                raise ValueError("malformed domain")
        elif kind == "ip":
            if not intelligence_normalizer.validate_ip(value):
                raise ValueError("malformed IP")
            value = value.lower()
        elif kind == "hash":
            valid, hash_type = intelligence_normalizer.validate_hash(value)
            if not valid:
                raise ValueError("malformed hash")
            value = value.lower()
            item.setdefault("category", f"malware_{hash_type.lower().replace('-', '')}")
        elif kind == "email":
            if not intelligence_normalizer.validate_email(value):
                raise ValueError("malformed email")
            value = value.lower()
        elif kind == "vpa":
            if not intelligence_normalizer.validate_vpa(value):
                raise ValueError("malformed VPA")
            value = value.lower()
        else:
            raise ValueError("unsupported indicator type")
        item["value"] = value
        item["type"] = kind
        return item

    def collect(self) -> Dict[str, Any]:
        started = datetime.now(timezone.utc).isoformat()
        result: Dict[str, Any] = {
            "source_name": self.name, "status": "Success", "records_fetched": 0,
            "extracted_indicators": 0, "inserted_indicators": 0, "duplicate_indicators": 0,
            "rejected_records": 0, "failed_records": 0, "error_details": "",
            "started_at": started, "completed_at": "",
        }
        if self.api_key_env and not get_environment_secret(self.api_key_env):
            result.update(status="Unconfigured", error_details=f"Missing {self.api_key_env}")
            cti_db.update_source_sync(self.name, "Unconfigured", 0, error_msg=result["error_details"])
            cti_db.add_collection_log(self.name, "Unconfigured", 0, 0, 0, result["error_details"])
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result
        try:
            rows = self.fetch_records()
            result["records_fetched"] = len(rows)
            for raw in rows:
                if raw.get("type") == "_non_indicator":
                    continue
                try:
                    item = self._normalize(dict(raw))
                    result["extracted_indicators"] += 1
                    confidence, status, expiry = intelligence_normalizer.calculate_confidence_and_status(
                        item["value"], item["type"], self.name,
                        base_confidence=max(0, min(100, int(item.get("confidence", 45)))),
                        source_count=1, source_verified=bool(item.get("source_verified", False)),
                    )
                    if status == "Allowlisted":
                        result["rejected_records"] += 1
                        continue
                    evidence = item.get("evidence", [])
                    if isinstance(evidence, str):
                        evidence = [{"source": self.name, "excerpt": evidence[:1000]}]
                    evidence = list(evidence) + [{
                        "source": self.name, "reference": item.get("reference", self.url),
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                    }]
                    inserted = cti_db.add_indicator(
                        indicator_value=item["value"], indicator_type=item["type"],
                        threat_category=item.get("category", "unclassified"),
                        source_name=self.name, description=str(item.get("description", ""))[:1000],
                        source_reference=str(item.get("reference", self.url))[:1000],
                        confidence_score=confidence, verification_status=status,
                        evidence=evidence, mitre_tactics=item.get("mitre_tactics", []),
                        expires_at=expiry, source_verified=bool(item.get("source_verified", False)),
                    )
                    result["inserted_indicators" if inserted else "duplicate_indicators"] += 1
                except (ValueError, TypeError, KeyError) as err:
                    result["rejected_records"] += 1
                    logger.info("Rejected malformed record from %s: %s", self.name, err)
            cti_db.update_source_sync(self.name, "Success", result["records_fetched"], checkpoint=result["completed_at"])
        except SourceUnconfigured as err:
            result.update(status="Unconfigured", error_details=str(err))
            cti_db.update_source_sync(self.name, "Unconfigured", 0, error_msg=str(err))
        except Exception as err:
            result.update(status="Failed", error_details=str(err)[:500], failed_records=1)
            cti_db.update_source_sync(self.name, "Failed", 0, error_msg=result["error_details"])
            logger.warning("CTI source %s failed: %s", self.name, err)
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        cti_db.add_collection_log(self.name, result["status"], result["records_fetched"],
                                  result["inserted_indicators"], result["duplicate_indicators"],
                                  result["error_details"])
        return result

class CertInConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-CERTIN","CERT-In Advisories","Government Advisory RSS","https://www.cert-in.org.in/s2cplus/rss.jsp")
    def fetch_records(self):
        content = fetch_secure_content(self.url).decode("utf-8", errors="replace")
        root = ET.fromstring(content)
        rows = []
        for entry in root.findall(".//item"):
            text = " ".join(entry.findtext(k) or "" for k in ("title","description"))
            rows.extend(_document_indicators(text,self.name,entry.findtext("link") or self.url,"advisory_reference"))
        return rows

class NpciConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-NPCI","NPCI Security Circulars","Financial Body Advisory","https://www.npci.org.in/statistics/upi-safety-circulars")
    def fetch_records(self):
        html = fetch_secure_content(self.url).decode("utf-8", errors="replace")
        parser = _TextExtractor(); parser.feed(html)
        return _document_indicators(" ".join(parser.parts),self.name,self.url,"advisory_reference")

class RbiConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-RBI","RBI Fraud Awareness","Regulatory Circular","https://rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx")
    def fetch_records(self):
        html = fetch_secure_content(self.url).decode("utf-8", errors="replace")
        parser = _TextExtractor(); parser.feed(html)
        return _document_indicators(" ".join(parser.parts),self.name,self.url,"advisory_reference")

class PhishTankConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-PHISHTANK","PhishTank Feed","Phishing Feed","https://data.phishtank.com/data/online-valid.json")
    def fetch_records(self):
        data = json.loads(fetch_secure_content(self.url).decode("utf-8"))
        return [{"value": x["url"],"type":"url","category":"phishing",
                 "description":f"PhishTank online-valid record {x.get('phish_id','')}",
                 "reference":x.get("phish_detail_url",self.url),"confidence":90,
                 "source_verified":True,"evidence":[{"phish_id":x.get("phish_id"),"submission_time":x.get("submission_time")} ]}
                for x in data if x.get("url")]

class UrlhausConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-URLHAUS","URLhaus Recent URLs","Malware/Phishing API","https://urlhaus-api.abuse.ch/v1/urls/recent/")
    def fetch_records(self):
        data=json.loads(fetch_secure_content(self.url).decode("utf-8"))
        return [{"value":x["url"],"type":"url","category":"malware",
                 "description":f"URLhaus {x.get('threat','malware')} ({x.get('url_status','unknown')})",
                 "reference":x.get("urlhaus_reference",self.url),"confidence":85,
                 "source_verified":False,"evidence":[{"date_added":x.get("date_added"),"status":x.get("url_status")} ]}
                for x in data.get("urls",[]) if x.get("url")]

class OpenPhishConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-OPENPHISH","OpenPhish Community Feed","Phishing Feed","https://openphish.com/feed.txt")
    def fetch_records(self):
        return [{"value":line.strip(),"type":"url","category":"phishing","description":"URL present in OpenPhish community feed",
                 "reference":self.url,"confidence":75,"source_verified":False}
                for line in fetch_secure_content(self.url).decode("utf-8",errors="replace").splitlines() if line.strip()]

class CisaKevConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-CISAKEV","CISA Known Exploited Vulnerabilities","Vulnerability Feed","https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    def fetch_records(self):
        data=json.loads(fetch_secure_content(self.url).decode("utf-8"))
        # CVE records are vulnerability metadata, not URL/domain/hash IOCs.
        # Fetch them for source health only; never coerce CVEs into fake hashes.
        return [{"type":"_non_indicator","value":x.get("cveID",""),"description":x.get("vulnerabilityName","")}
                for x in data.get("vulnerabilities",[])[:100]]

class MitreAttackConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-MITREATTCK","MITRE ATT&CK Framework","Adversary Tactics JSON","https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    def fetch_records(self):
        data=json.loads(fetch_secure_content(self.url).decode("utf-8"))
        # ATT&CK techniques are knowledge-base records, not IOCs.
        return [{"type":"_non_indicator","value":x.get("id",""),"description":x.get("name","")}
                for x in data.get("objects",[]) if x.get("type")=="attack-pattern"][:100]

class AbuseIpdbConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-ABUSEIPDB","AbuseIPDB Reputation","IP Reputation API","https://api.abuseipdb.com/api/v2/black-list","ABUSEIPDB_API_KEY")
    def fetch_records(self):
        key=get_environment_secret(self.api_key_env)
        if not key: raise SourceUnconfigured(f"Missing {self.api_key_env}")
        data=json.loads(fetch_secure_content(self.url,headers={"Key":key,"Accept":"application/json"}).decode("utf-8"))
        return [{"value":x["ipAddress"],"type":"ip","category":"malicious_ip",
                 "description":f"Abuse confidence {x.get('abuseConfidenceScore')}%",
                 "reference":self.url,"confidence":int(x.get("abuseConfidenceScore",0)),
                 "source_verified":False} for x in data.get("data",[]) if x.get("ipAddress")]

class AlienVaultOtxConnector(BaseSourceConnector):
    def __init__(self): super().__init__("SRC-OTX","AlienVault OTX Pulses","Threat Pulses API","https://otx.alienvault.com/api/v1/pulses/subscribed","OTX_API_KEY")
    def fetch_records(self):
        key=get_environment_secret(self.api_key_env)
        if not key: raise SourceUnconfigured(f"Missing {self.api_key_env}")
        data=json.loads(fetch_secure_content(self.url,headers={"X-OTX-API-KEY":key}).decode("utf-8"))
        rows=[]
        for pulse in data.get("results",[]):
            for ind in pulse.get("indicators",[]):
                kind={"URL":"url","domain":"domain","IPv4":"ip","IPv6":"ip","FileHash-SHA256":"hash","FileHash-SHA1":"hash","FileHash-MD5":"hash","email":"email"}.get(ind.get("type"))
                if kind and ind.get("indicator"):
                    rows.append({"value":ind["indicator"],"type":kind,"category":"threat_pulse",
                                 "description":str(pulse.get("name","OTX pulse"))[:500],
                                 "reference":self.url,"confidence":70,"source_verified":False})
        return rows

ALL_CONNECTORS: List[BaseSourceConnector] = [
    CertInConnector(), NpciConnector(), RbiConnector(), PhishTankConnector(), UrlhausConnector(),
    OpenPhishConnector(), CisaKevConnector(), MitreAttackConnector(), AbuseIpdbConnector(), AlienVaultOtxConnector(),
]
