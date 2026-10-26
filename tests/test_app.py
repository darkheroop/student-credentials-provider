"""
Tests for the SCP Flask application routes.
Verifies Student Lookup endpoints, demo mode, and security headers.
All external API calls are mocked - no real API key required.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from app import app


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestPageRoutes:
    """Test HTML page routes."""
    
    def test_homepage_returns_200(self, client):
        response = client.get('/')
        assert response.status_code == 200
        assert b'Student Credentials Provider' in response.data
    
    def test_about_returns_200(self, client):
        response = client.get('/about')
        assert response.status_code == 200
        assert b'About' in response.data
    
    def test_documentation_returns_200(self, client):
        response = client.get('/documentation')
        assert response.status_code == 200
    
    def test_learn_returns_200(self, client):
        response = client.get('/learn')
        assert response.status_code == 200
    
    def test_health_endpoint(self, client):
        response = client.get('/api/health')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert data['status'] == 'healthy'
        assert 'mode' in data
        assert 'version' in data
    
    def test_health_does_not_expose_secrets(self, client):
        response = client.get('/api/health')
        data = json.loads(response.data)
        response_text = json.dumps(data)
        assert 'api_key' not in response_text.lower()
        assert 'secret' not in response_text.lower()
        assert 'password' not in response_text.lower()

    def test_404_handler(self, client):
        response = client.get('/nonexistent-page')
        assert response.status_code == 404


class TestStudentLookupEndpoint:
    """Test POST /api/student-lookup and alias /api/lookup."""
    
    def test_student_lookup_requires_json(self, client):
        response = client.post('/api/student-lookup', data='not json')
        assert response.status_code == 400
    
    def test_student_lookup_requires_input_field(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'algorithm_type': 'md5'}),
            content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
    
    def test_student_lookup_requires_algorithm_field(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'lookup_input': 'abc123'}),
            content_type='application/json')
        assert response.status_code == 400
    
    def test_student_lookup_rejects_empty_input(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'lookup_input': '', 'algorithm_type': 'md5'}),
            content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'invalid_input' in data.get('status', '')
    
    def test_student_lookup_rejects_unsupported_algorithm(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'lookup_input': 'a' * 32, 'algorithm_type': 'rot13'}),
            content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
    
    def test_student_lookup_rejects_invalid_hex(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'lookup_input': 'xyz' + 'g' * 29, 'algorithm_type': 'md5'}),
            content_type='application/json')
        assert response.status_code == 400
    
    def test_student_lookup_rejects_wrong_length(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'lookup_input': 'abcdef', 'algorithm_type': 'md5'}),
            content_type='application/json')
        assert response.status_code == 400
    
    def test_student_lookup_rejects_oversized_input(self, client):
        response = client.post('/api/student-lookup',
            data=json.dumps({'lookup_input': 'a' * 300, 'algorithm_type': 'md5'}),
            content_type='application/json')
        assert response.status_code == 400
    
    def test_student_lookup_method_not_allowed(self, client):
        response = client.get('/api/student-lookup')
        assert response.status_code == 405

    def test_backward_compatible_lookup_route(self, client):
        response = client.post('/api/lookup',
            data=json.dumps({'hash': '5d41402abc4b2a76b9719d911017c592', 'algorithm': 'md5'}),
            content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['found'] is True
        assert data['plaintext'] == 'hello'


class TestDemoStudentLookup:
    """Test POST /api/demo-student-lookup and alias /api/demo-lookup."""
    
    def test_demo_lookup_known_record(self, client):
        response = client.post('/api/demo-student-lookup',
            data=json.dumps({
                'lookup_input': '5d41402abc4b2a76b9719d911017c592',
                'algorithm_type': 'md5'
            }),
            content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['mode'] == 'demo'
        assert data['found'] is True
        assert data['plaintext'] == 'hello'
    
    def test_demo_lookup_unknown_record(self, client):
        response = client.post('/api/demo-student-lookup',
            data=json.dumps({
                'lookup_input': 'a' * 32,
                'algorithm_type': 'md5'
            }),
            content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['mode'] == 'demo'
        assert data['found'] is False
    
    def test_demo_lookup_never_claims_live(self, client):
        response = client.post('/api/demo-student-lookup',
            data=json.dumps({
                'lookup_input': '5d41402abc4b2a76b9719d911017c592',
                'algorithm_type': 'md5'
            }),
            content_type='application/json')
        data = json.loads(response.data)
        assert data['mode'] == 'demo'
        assert data['mode'] != 'live'

    def test_backward_compatible_demo_route(self, client):
        response = client.post('/api/demo-lookup',
            data=json.dumps({
                'hash': '5d41402abc4b2a76b9719d911017c592',
                'algorithm': 'md5'
            }),
            content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['mode'] == 'demo'
        assert data['found'] is True


class TestSecurityHeaders:
    """Test security headers are present."""
    
    def test_security_headers_on_page(self, client):
        response = client.get('/')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert response.headers.get('X-Frame-Options') == 'DENY'
    
    def test_no_secrets_in_error(self, client):
        response = client.post('/api/student-lookup',
            data='invalid json{{{',
            content_type='application/json')
        response_text = response.data.decode('utf-8').lower()
        assert 'traceback' not in response_text
        assert 'api_key' not in response_text
