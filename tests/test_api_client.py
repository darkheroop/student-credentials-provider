"""Tests for the MD5Decrypt API client with mocked responses."""
import pytest
from unittest.mock import patch, MagicMock
import requests
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.api_client import Md5DecryptClient


@pytest.fixture
def client():
    return Md5DecryptClient(
        api_url='https://md5decrypt.net/en/Api/api.php',
        api_key='test@example.com:testcode123',
        timeout=10
    )


class TestApiClientSuccess:
    
    @patch('services.api_client.requests.get')
    def test_successful_lookup_found(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'hello'
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        result = client.lookup('5d41402abc4b2a76b9719d911017c592', 'md5')
        assert result['success'] is True
        assert result['found'] is True
        assert result['plaintext'] == 'hello'
        assert 'duration' in result
    
    @patch('services.api_client.requests.get')
    def test_successful_lookup_not_found(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is True
        assert result['found'] is False
        assert result['plaintext'] is None


class TestApiClientErrors:
    
    @patch('services.api_client.requests.get')
    def test_connection_error(self, mock_get, client):
        mock_get.side_effect = requests.exceptions.ConnectionError('Connection refused')
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
        assert result['error'] is not None
        assert 'api_key' not in str(result.get('error', '')).lower()
        assert 'testcode' not in str(result.get('error', '')).lower()
    
    @patch('services.api_client.requests.get')
    def test_timeout_error(self, mock_get, client):
        mock_get.side_effect = requests.exceptions.Timeout('Request timed out')
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
        assert 'timeout' in result.get('error', '').lower() or 'timed' in result.get('error', '').lower()
    
    @patch('services.api_client.requests.get')
    def test_http_401_error(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = 'Unauthorized'
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
        mock_get.return_value = mock_response
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
    
    @patch('services.api_client.requests.get')
    def test_http_429_rate_limit(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = 'Rate limit exceeded'
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
        mock_get.return_value = mock_response
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
    
    @patch('services.api_client.requests.get')
    def test_http_500_server_error(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
        mock_get.return_value = mock_response
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
    
    @patch('services.api_client.requests.get')
    def test_no_credentials_leaked_in_error(self, mock_get, client):
        mock_get.side_effect = Exception('Some error with testcode123')
        
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
        error_str = str(result.get('error', ''))
        assert 'testcode123' not in error_str
        assert 'test@example.com' not in error_str


class TestApiClientConfiguration:
    
    def test_client_creation(self):
        client = Md5DecryptClient(
            api_url='https://md5decrypt.net/en/Api/api.php',
            api_key='user@test.com:key123',
            timeout=5
        )
        assert client is not None
    
    def test_client_with_no_api_key(self):
        client = Md5DecryptClient(
            api_url='https://md5decrypt.net/en/Api/api.php',
            api_key=None,
            timeout=5
        )
        result = client.lookup('a' * 32, 'md5')
        assert result['success'] is False
