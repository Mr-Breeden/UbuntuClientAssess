"""Compatibility import for the pre-v1.6.1 test-case module.

UbuntuClientAssess v1.6.1 replaced the duplicative test_cases.txt artifact with
assessment_coverage.txt. New code should import modules.assessment_coverage.
"""
from .assessment_coverage import (  # noqa: F401
    FRAMEWORK_CASE_ID,
    FULL_CATALOG_IDS,
    INSTALLER_ONLY_CATALOG_IDS,
    build_assessment_coverage,
    generate_assessment_coverage,
    generate_test_cases,
    refresh_assessment_coverage,
)
