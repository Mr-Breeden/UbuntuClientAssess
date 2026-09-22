from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
from modules.security_model import MODEL_SCHEMA_VERSION, SecurityModelBuilder, normalize_existing_model_payload


def test_v171_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_correlation_provenance_aggregates_relationships_sources_and_bookmarks():
    b = SecurityModelBuilder()
    app = b.object("application", "demo")
    svc = b.object("service", "demo.service")
    path = b.object("file", "/opt/demo/config")
    b.relationship(app, "owns_or_introduces", svc)
    b.relationship(svc, "consumes", path)
    o1 = b.observation("service_dependency", svc, "service_review", summary="service consumes config", evidence=["service_review.txt::demo.service"])
    o2 = b.observation("filesystem_permission", path, "permissions_review", summary="path writable", evidence=["permissions_review.txt::/opt/demo/config"])
    cid = b.correlation("privileged_service_writable_path", "demo.service:Config:/opt/demo/config", strength="STRONG", title="Writable service path", summary="demo", object_ids=[svc,path], observation_ids=[o1,o2], review_identity="r1", finding_identity="f1")
    corr = b.correlations[cid]
    assert corr["cross_module"] is True
    assert corr["evidence_quality"] == "HIGH"
    assert set(corr["source_modules"]) == {"service_review", "permissions_review"}
    assert len(corr["relationship_ids"]) >= 2
    assert {x["bookmark"] for x in corr["evidence_refs"]} == {"service_review.txt::demo.service", "permissions_review.txt::/opt/demo/config"}
    assert corr["suppressed"] is False
    assert corr["drives_finding"] is True


def test_malformed_finding_correlation_is_suppressed_not_promoted():
    b = SecurityModelBuilder()
    svc = b.object("service", "demo.service")
    cid = b.correlation("privileged_service_writable_path", "broken", strength="STRONG", title="Broken", summary="broken", object_ids=[svc], observation_ids=[], review_identity="r", finding_identity="f")
    corr = b.correlations[cid]
    assert corr["suppressed"] is True
    assert corr["drives_review"] is False
    assert corr["drives_finding"] is False
    assert corr["suppression_reasons"]


def test_schema8_normalization_adds_v171_provenance_fields():
    payload = {
        "schema_version": 8,
        "objects": [{"id":"service:x","kind":"service","identity":"x","attributes":{}}],
        "observations": [{"id":"OBS-x","category":"service_dependency","object_id":"service:x","source_module":"service_review","summary":"x","attributes":{},"evidence_bookmarks":["service_review.txt::x"]}],
        "relationships": [],
        "correlations": [{"id":"COR-x","kind":"privileged_service_writable_path","title":"x","object_ids":["service:x"],"observation_ids":["OBS-x"],"review_identity":"r","finding_identity":"f"}],
    }
    normalized = normalize_existing_model_payload(payload)
    assert normalized["schema_version"] == 10
    obs = normalized["observations"][0]
    assert obs["evidence_refs"][0]["bookmark"] == "service_review.txt::x"
    corr = normalized["correlations"][0]
    assert corr["source_modules"] == ["service_review"]
    assert corr["evidence_quality"] == "MODERATE"
    assert "rationale" in corr
