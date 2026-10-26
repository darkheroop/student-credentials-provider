"""Tests for Student Lookup input validation logic."""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.student_lookup import StudentLookupService
from config import Config


@pytest.fixture
def service():
    config = Config()
    config.STUDENT_LOOKUP_MODE = 'demo'
    return StudentLookupService(config)


class TestStudentLookupValidation:
    
    def test_valid_md5_lookup_input(self, service):
        valid, msg = service.validate_lookup_input('5d41402abc4b2a76b9719d911017c592', 'md5')
        assert valid is True
    
    def test_valid_sha1_lookup_input(self, service):
        valid, msg = service.validate_lookup_input('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'sha1')
        assert valid is True
    
    def test_valid_sha256_lookup_input(self, service):
        valid, msg = service.validate_lookup_input('a' * 64, 'sha256')
        assert valid is True
    
    def test_valid_uppercase_lookup_input(self, service):
        valid, msg = service.validate_lookup_input('5D41402ABC4B2A76B9719D911017C592', 'md5')
        assert valid is True
    
    def test_empty_lookup_input_rejected(self, service):
        valid, msg = service.validate_lookup_input('', 'md5')
        assert valid is False
        assert 'empty' in msg.lower() or 'provide' in msg.lower() or 'enter' in msg.lower()
    
    def test_none_lookup_input_rejected(self, service):
        valid, msg = service.validate_lookup_input(None, 'md5')
        assert valid is False
    
    def test_whitespace_lookup_input_rejected(self, service):
        valid, msg = service.validate_lookup_input('   ', 'md5')
        assert valid is False
    
    def test_unsupported_algorithm_rejected(self, service):
        valid, msg = service.validate_lookup_input('a' * 32, 'rot13')
        assert valid is False
        assert 'support' in msg.lower() or 'algorithm' in msg.lower()
    
    def test_invalid_hex_rejected(self, service):
        valid, msg = service.validate_lookup_input('g' * 32, 'md5')
        assert valid is False
        assert 'hex' in msg.lower() or 'character' in msg.lower() or 'invalid' in msg.lower()
    
    def test_wrong_length_rejected(self, service):
        valid, msg = service.validate_lookup_input('abcdef', 'md5')
        assert valid is False
        assert 'length' in msg.lower() or 'character' in msg.lower()
    
    def test_oversized_input_rejected(self, service):
        valid, msg = service.validate_lookup_input('a' * 300, 'md5')
        assert valid is False
    
    def test_algorithm_case_insensitive(self, service):
        valid, msg = service.validate_lookup_input('5d41402abc4b2a76b9719d911017c592', 'MD5')
        assert valid is True
    
    def test_sha384_length(self, service):
        valid, msg = service.validate_lookup_input('a' * 96, 'sha384')
        assert valid is True
    
    def test_sha512_length(self, service):
        valid, msg = service.validate_lookup_input('a' * 128, 'sha512')
        assert valid is True


class TestDemoStudentLookup:
    
    def test_known_md5_found(self, service):
        result = service.student_lookup('5d41402abc4b2a76b9719d911017c592', 'md5')
        assert result['success'] is True
        assert result['found'] is True
        assert result['plaintext'] == 'hello'
        assert result['mode'] == 'demo'
    
    def test_known_sha256_found(self, service):
        result = service.student_lookup('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'sha256')
        assert result['success'] is True
        assert result['found'] is True
    
    def test_unknown_input_not_found(self, service):
        result = service.student_lookup('a' * 32, 'md5')
        assert result['success'] is True
        assert result['found'] is False
        assert result['plaintext'] is None
    
    def test_demo_mode_label(self, service):
        result = service.student_lookup('5d41402abc4b2a76b9719d911017c592', 'md5')
        assert result['mode'] == 'demo'
