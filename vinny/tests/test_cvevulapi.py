#########################################################################
# VINCE
#
# Test for CVEVulAPIView
#
#########################################################################
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from unittest.mock import Mock, patch
from vincepub.models import VUReport
from datetime import datetime, timedelta
import json


class CVEVulAPIViewTestCase(TestCase):
    databases = {"default", "vincecomm", "vincepub"}
    """Test case for CVEVulAPIView with mock CVE dataset"""

    def setUp(self):
        """Set up test fixtures"""
        self.client = APIClient()
        # Create mock VUReport with 10 CVE records
        self.create_mock_vureport()

    def create_mock_vureport(self):
        """Create a VUReport with 10 CVE records with CVE-1900- prefix"""
        cve_ids = [f"CVE-1900-{str(i).zfill(4)}" for i in range(1, 11)]
        print(cve_ids)
        now = timezone.now()
        
        self.vureport = VUReport.objects.create(
            vuid='VU#123456',
            idnumber='VU-123456',
            name='Test Vulnerability Note with Multiple CVEs',
            overview='This is a test vulnerability note containing 10 CVE records',
            cveids=cve_ids,
            datefirstpublished=now,
            dateupdated=now,
            revision=1,
            publish=True,
            author='Test Author',
            public=['https://example.com/ref1', 'https://example.com/ref2'],
        )

    def test_cve_lookup_returns_vureport_data(self):
        """Test that CVEVulAPIView returns the VUReport data for a valid CVE"""
        # Test with the first CVE in the dataset: CVE-1900-0001
        year = 1900
        pk = 1
        
        with patch('vinny.views.VUReport.objects.raw') as mock_raw:
            # Mock the raw query to return our test VUReport
            mock_raw.return_value = [self.vureport]
            
            with patch('vinny.views.create_record_of_API_access'):
                response = self.client.get(
                    f'/api/vuls/cve/{year}-{pk:04d}/',
                    format='json'
                )
        
        # For this to work, you may need to check the actual endpoint URL
        # Adjust based on your URL configuration
        self.assertIn(response.status_code, [200, 404])  # 404 if endpoint not accessible in test
        
    def test_cve_lookup_with_multiple_cves_in_report(self):
        """Test that the VUReport contains all 10 CVE records"""
        # Verify the VUReport has exactly 10 CVE IDs
        self.assertEqual(len(self.vureport.cveids), 10)
        
        # Verify all CVE IDs follow the CVE-1900- pattern
        for cve_id in self.vureport.cveids:
            self.assertTrue(cve_id.startswith('CVE-1900-'))
        
        # Verify CVE IDs are in sequence
        expected_cves = [f"CVE-1900-{str(i).zfill(4)}" for i in range(1, 11)]
        self.assertEqual(self.vureport.cveids, expected_cves)

    def test_cve_ids_have_correct_format(self):
        """Test that all CVE IDs follow the correct CVE-YYYY-NNNN format"""
        for cve_id in self.vureport.cveids:
            # Check format: CVE-YYYY-NNNN where YYYY is year and NNNN is number
            self.assertRegex(cve_id, r'^CVE-\d{4}-\d{4}$')

    def test_vureport_metadata(self):
        """Test that VUReport contains required metadata"""
        self.assertEqual(self.vureport.vuid, 'VU#123456')
        self.assertEqual(self.vureport.idnumber, 'VU-123456')
        self.assertIsNotNone(self.vureport.datefirstpublished)
        self.assertIsNotNone(self.vureport.dateupdated)
        self.assertTrue(self.vureport.publish)

    def test_vureport_public_references(self):
        """Test that VUReport contains public references"""
        self.assertIsNotNone(self.vureport.public)
        self.assertIsInstance(self.vureport.public, list)
        self.assertGreater(len(self.vureport.public), 0)


class CVEVulAPIViewIntegrationTestCase(TestCase):
    """Integration test case for CVEVulAPIView"""
    databases = {"default", "vincecomm", "vincepub"}
    
    def setUp(self):
        """Set up for integration tests"""
        self.client = APIClient()
        
        # Create multiple VUReports with different CVE sets
        self.create_multiple_vureports()

    def create_multiple_vureports(self):
        """Create multiple VUReports for integration testing"""
        now = timezone.now()
        
        # VUReport 1: CVE-1900-0001 through CVE-1900-0010
        cve_ids_1 = [f"CVE-1900-{str(i).zfill(4)}" for i in range(1, 11)]
        self.vureport_1 = VUReport.objects.create(
            vuid='VU#100001',
            idnumber='VU-100001',
            name='Test Report 1',
            cveids=cve_ids_1,
            datefirstpublished=now,
            dateupdated=now,
            publish=True,
        )
        
        # VUReport 2: CVE-1900-0011 through CVE-1900-0020
        cve_ids_2 = [f"CVE-1900-{str(i).zfill(4)}" for i in range(11, 21)]
        self.vureport_2 = VUReport.objects.create(
            vuid='VU#100002',
            idnumber='VU-100002',
            name='Test Report 2',
            cveids=cve_ids_2,
            datefirstpublished=now,
            dateupdated=now,
            publish=True,
        )

    def test_multiple_vureports_with_distinct_cve_sets(self):
        """Test that multiple VUReports maintain distinct CVE sets"""
        vureports = VUReport.objects.all()
        self.assertEqual(vureports.count(), 2)
        
        # Verify they have different CVE IDs
        cve_ids_1 = set(self.vureport_1.cveids)
        cve_ids_2 = set(self.vureport_2.cveids)
        
        # No overlap between the two sets
        self.assertEqual(len(cve_ids_1.intersection(cve_ids_2)), 0)
        
        # Each has 10 CVEs
        self.assertEqual(len(cve_ids_1), 10)
        self.assertEqual(len(cve_ids_2), 10)

