import unittest
import json
import pathlib
from unittest.mock import patch, MagicMock
from datetime import datetime

# Import the test database configuration
from test_db_config import initialize_test_db, close_test_db

# Mock the logger before importing the target module
mock_logger = MagicMock()
with patch('common.logger.Logger') as mock_logger_class:
    mock_logger_class.return_value = mock_logger
    from apollo.rhworker.poll_rh_activities import (
        create_or_update_advisory_packages,
        create_or_update_advisory_cves,
        create_or_update_advisory_bugzilla_bugs,
        create_or_update_advisory_affected_products,
    )
    # Import DB models directly to use with the test database
    from apollo.db import (
        RedHatAdvisory,
        RedHatAdvisoryPackage,
        RedHatAdvisoryCVE,
        RedHatAdvisoryBugzillaBug,
        RedHatAdvisoryAffectedProduct
    )



class TestRedHatAdvisoryUpdates(unittest.IsolatedAsyncioTestCase):
    @classmethod
    async def asyncSetUpClass(cls):
        await initialize_test_db()

    @classmethod
    async def asyncTearDownClass(cls):
        await close_test_db()

    async def asyncTearDown(self):
        # Clean up all tables after each test
        await RedHatAdvisory.all().delete()
        await RedHatAdvisoryPackage.all().delete()
        await RedHatAdvisoryCVE.all().delete()
        await RedHatAdvisoryBugzillaBug.all().delete()
        await RedHatAdvisoryAffectedProduct.all().delete()

    async def test_create_or_update_advisory_packages_add_and_remove(self):
        advisory = await RedHatAdvisory.create(
            name="RHSA-TEST:0001",
            red_hat_issued_at="2025-01-01T00:00:00+00:00",
            synopsis="syn",
            description="desc",
            kind="Security",
            severity="Important",
            topic="topic",
        )
        await create_or_update_advisory_packages(advisory, {"pkg1", "pkg2"})
        pkgs = await RedHatAdvisoryPackage.filter(red_hat_advisory=advisory)
        self.assertEqual({p.nevra for p in pkgs}, {"pkg1", "pkg2"})

        await create_or_update_advisory_packages(advisory, {"pkg2", "pkg3"}, update_advisory=True)
        pkgs = await RedHatAdvisoryPackage.filter(red_hat_advisory=advisory)
        self.assertEqual({p.nevra for p in pkgs}, {"pkg2", "pkg3"})

    async def test_create_or_update_advisory_cves_add_and_remove(self):
        advisory = await RedHatAdvisory.create(
            name="RHSA-TEST:0002",
            red_hat_issued_at="2025-01-01T00:00:00+00:00",
            synopsis="syn",
            description="desc",
            kind="Security",
            severity="Important",
            topic="topic",
        )
        cve1 = ("CVE-0001", "VEC1", "9.0", "CWE-1")
        cve2 = ("CVE-0002", "VEC2", "8.0", "CWE-2")
        await create_or_update_advisory_cves(advisory, {cve1, cve2})
        cves = await RedHatAdvisoryCVE.filter(red_hat_advisory=advisory)
        self.assertEqual(
            {(c.cve, c.cvss3_scoring_vector, c.cvss3_base_score, c.cwe) for c in cves},
            {cve1, cve2}
        )

        cve3 = ("CVE-0003", "VEC3", "7.0", "CWE-3")
        await create_or_update_advisory_cves(advisory, {cve2, cve3}, update_advisory=True)
        cves = await RedHatAdvisoryCVE.filter(red_hat_advisory=advisory)
        self.assertEqual(
            {(c.cve, c.cvss3_scoring_vector, c.cvss3_base_score, c.cwe) for c in cves},
            {cve2, cve3}
        )

    async def test_create_or_update_advisory_bugzilla_bugs_add_and_remove(self):
        advisory = await RedHatAdvisory.create(
            name="RHSA-TEST:0003",
            red_hat_issued_at="2025-01-01T00:00:00+00:00",
            synopsis="syn",
            description="desc",
            kind="Security",
            severity="Important",
            topic="topic",
        )
        await create_or_update_advisory_bugzilla_bugs(advisory, {"123", "456"})
        bugs = await RedHatAdvisoryBugzillaBug.filter(red_hat_advisory=advisory)
        self.assertEqual({b.bugzilla_bug_id for b in bugs}, {"123", "456"})

        await create_or_update_advisory_bugzilla_bugs(advisory, {"456", "789"}, update_advisory=True)
        bugs = await RedHatAdvisoryBugzillaBug.filter(red_hat_advisory=advisory)
        self.assertEqual({b.bugzilla_bug_id for b in bugs}, {"456", "789"})

    async def test_create_or_update_advisory_affected_products_add_and_remove(self):
        advisory = await RedHatAdvisory.create(
            name="RHSA-TEST:0004",
            red_hat_issued_at="2025-01-01T00:00:00+00:00",
            synopsis="syn",
            description="desc",
            kind="Security",
            severity="Important",
            topic="topic",
        )
        prod1 = ("RHEL", "Dummy1", 9, 0, "x86_64")
        prod2 = ("RHEL", "Dummy2", 9, 1, "aarch64")
        await create_or_update_advisory_affected_products(advisory, {prod1, prod2})
        prods = await RedHatAdvisoryAffectedProduct.filter(red_hat_advisory=advisory)
        self.assertEqual(
            {(p.variant, p.name, p.major_version, p.minor_version, p.arch) for p in prods},
            {prod1, prod2}
        )

        prod3 = ("RHEL", "Dummy3", 9, 2, "ppc64le")
        await create_or_update_advisory_affected_products(advisory, {prod2, prod3}, update_advisory=True)
        prods = await RedHatAdvisoryAffectedProduct.filter(red_hat_advisory=advisory)
        self.assertEqual(
            {(p.variant, p.name, p.major_version, p.minor_version, p.arch) for p in prods},
            {prod2, prod3}
        )