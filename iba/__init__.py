"""
Test Suite for Intent-Bound Authorization (IBA)

Tests cover:
1. Intent declaration and validation
2. Cryptographic binding and verification
3. Drift detection
4. Edge cases and security

Run with: pytest tests/
"""

import sys
sys.path.insert(0, '..')

from iba import (
    IntentDeclaration,
    IntentScope,
    IntentValidator,
    IntentViolationError,
    IntentBinder,
    SimpleIntentBinder
)
from datetime import datetime, timedelta
import pytest


class TestIntentScope:
    """Test IntentScope resource matching."""
    
    def test_exact_match_allowed(self):
        scope = IntentScope(
            allowed_resources=["calendar:read", "calendar:write"]
        )
        assert scope.is_allowed("calendar:read") is True
        assert scope.is_allowed("calendar:write") is True
        assert scope.is_allowed("calendar:delete") is False
    
    def test_wildcard_allowed(self):
        scope = IntentScope(
            allowed_resources=["calendar:*"]
        )
        assert scope.is_allowed("calendar:read") is True
        assert scope.is_allowed("calendar:write") is True
        assert scope.is_allowed("calendar:delete") is True
        assert scope.is_allowed("medical:read") is False
    
    def test_forbidden_overrides_allowed(self):
        scope = IntentScope(
            allowed_resources=["*"],
            forbidden_resources=["medical_records:*"]
        )
        assert scope.is_allowed("calendar:read") is True
        assert scope.is_allowed("medical_records:patient_data") is False
    
    def test_forbidden_wildcard(self):
        scope = IntentScope(
            forbidden_resources=["medical_records:*"]
        )
        assert scope.is_forbidden("medical_records:read") is True
        assert scope.is_forbidden("medical_records:write") is True
        assert scope.is_forbidden("calendar:read") is False


class TestIntentDeclaration:
    """Test IntentDeclaration creation and serialization."""
    
    def test_create_intent(self):
        scope = IntentScope(allowed_resources=["test:read"])
        intent = IntentDeclaration(
            intent_id="test-001",
            declared_purpose="Test purpose",
            authorized_by="user@test.com",
            scope=scope
        )
        assert intent.intent_id == "test-001"
        assert intent.declared_purpose == "Test purpose"
        assert intent.authorized_by == "user@test.com"
        assert isinstance(intent.timestamp, datetime)
        assert isinstance(intent.expiration, datetime)
    
    def test_expiration_defaults(self):
        scope = IntentScope(allowed_resources=["test:read"])
        intent = IntentDeclaration(
            intent_id="test-001",
            declared_purpose="Test",
            authorized_by="user@test.com",
            scope=scope
        )
        # Should expire 1 hour from now
        assert intent.expiration > datetime.utcnow()
        assert intent.expiration < datetime.utcnow() + timedelta(hours=2)
    
    def test_is_expired(self):
        scope = IntentScope(allowed_resources=["test:read"])
        
        # Create expired intent
        past_time = datetime.utcnow() - timedelta(hours=2)
        expired_intent = IntentDeclaration(
            intent_id="test-002",
            declared_purpose="Test",
            authorized_by="user@test.com",
            scope=scope,
            timestamp=past_time - timedelta(hours=1),
            expiration=past_time
        )
        assert expired_intent.is_expired() is True
    
    def test_to_dict_and_back(self):
        scope = IntentScope(
            allowed_resources=["test:read"],
            forbidden_resources=["test:delete"]
        )
        intent1 = IntentDeclaration(
            intent_id="test-003",
            declared_purpose="Test serialization",
            authorized_by="user@test.com",
            scope=scope
        )
        
        # Convert to dict and back
        intent_dict = intent1.to_dict()
        intent2 = IntentDeclaration.from_dict(intent_dict)
        
        assert intent1.intent_id == intent2.intent_id
        assert intent1.declared_purpose == intent2.declared_purpose
        assert intent1.authorized_by == intent2.authorized_by
    
    def test_deterministic_hash(self):
        scope = IntentScope(allowed_resources=["test:read"])
        intent1 = IntentDeclaration(
            intent_id="test-004",
            declared_purpose="Test",
            authorized_by="user@test.com",
            scope=scope
        )
        intent2 = IntentDeclaration(
            intent_id="test-004",
            declared_purpose="Test",
            authorized_by="user@test.com",
            scope=scope,
            timestamp=intent1.timestamp,
            expiration=intent1.expiration
        )
        # Same intent should produce same hash
        assert intent1.get_deterministic_hash() == intent2.get_deterministic_hash()


class TestIntentValidator:
    """Test IntentValidator action validation and drift detection."""
    
    def test_validate_allowed_action(self):
        scope = IntentScope(allowed_resources=["calendar:read"])
        intent = IntentDeclaration(
            intent_id="test-005",
            declared_purpose="Read calendar",
            authorized_by="user@test.com",
            scope=scope
        )
        validator = IntentValidator(intent)
        
        result = validator.validate_action("read", "calendar:read")
        assert result['allowed'] is True
        assert 'Action aligns with declared intent' in result['reason']
    
    def test_validate_forbidden_action(self):
        scope = IntentScope(
            allowed_resources=["calendar:read"],
            forbidden_resources=["medical_records:*"]
        )
        intent = IntentDeclaration(
            intent_id="test-006",
            declared_purpose="Read calendar",
            authorized_by="user@test.com",
            scope=scope
        )
        validator = IntentValidator(intent)
        
        result = validator.validate_action("read", "medical_records:patient_data")
        assert result['allowed'] is False
        assert 'forbidden' in result['reason'].lower()
    
    def test_validate_unauthorized_action(self):
        scope = IntentScope(allowed_resources=["calendar:read"])
        intent = IntentDeclaration(
            intent_id="test-007",
            declared_purpose="Read calendar",
            authorized_by="user@test.com",
            scope=scope
        )
        validator = IntentValidator(intent)
        
        result = validator.validate_action("write", "calendar:write")
        assert result['allowed'] is False
        assert 'not in allowed scope' in result['reason']
    
    def test_api_call_limit(self):
        scope = IntentScope(
            allowed_resources=["test:*"],
            resource_limits={"max_api_calls": 3}
        )
        intent = IntentDeclaration(
            intent_id="test-008",
            declared_purpose="Test limits",
            authorized_by="user@test.com",
            scope=scope
        )
        validator = IntentValidator(intent)
        
        # First 3 calls should succeed
        for i in range(3):
            result = validator.validate_action("test", "test:action")
            assert result['allowed'] is True
        
        # 4th call should fail
        result = validator.validate_action("test", "test:action")
        assert result['allowed'] is False
        assert 'exceeded' in result['reason'].lower()
    
    def test_drift_detection(self):
        scope = IntentScope(
            allowed_resources=["allowed:*"],
            forbidden_resources=["forbidden:*"]
        )
        intent = IntentDeclaration(
            intent_id="test-009",
            declared_purpose="Test drift",
            authorized_by="user@test.com",
            scope=scope
        )
        validator = IntentValidator(intent)
        
        # Generate multiple violations
        for i in range(5):
            validator.validate_action("access", "forbidden:resource")
        
        # Should detect drift
        drift = validator.detect_drift()
        assert drift['drift_detected'] is True
        assert drift['reason'] == 'Repeated violations detected'
    
    def test_statistics(self):
        scope = IntentScope(
            allowed_resources=["allowed:*"],
            forbidden_resources=["forbidden:*"]
        )
        intent = IntentDeclaration(
            intent_id="test-010",
            declared_purpose="Test stats",
            authorized_by="user@test.com",
            scope=scope
        )
        validator = IntentValidator(intent)
        
        # 3 allowed, 2 blocked
        validator.validate_action("read", "allowed:resource")
        validator.validate_action("read", "allowed:resource")
        validator.validate_action("read", "allowed:resource")
        validator.validate_action("read", "forbidden:resource")
        validator.validate_action("read", "forbidden:resource")
        
        stats = validator.get_statistics()
        assert stats['total_actions'] == 5
        assert stats['allowed'] == 3
        assert stats['blocked'] == 2
        assert stats['violation_rate'] == 0.4


class TestSimpleIntentBinder:
    """Test SimpleIntentBinder for environments without cryptography."""
    
    def test_bind_and_verify(self):
        scope = IntentScope(allowed_resources=["test:read"])
        intent = IntentDeclaration(
            intent_id="test-011",
            declared_purpose="Test binding",
            authorized_by="user@test.com",
            scope=scope
        )
        
        binder = SimpleIntentBinder()
        token = binder.bind_intent(intent, "user@test.com")
        
        assert token.intent_hash == intent.get_deterministic_hash()
        assert token.algorithm == "HMAC-SHA256"
        
        # Verify
        is_valid = binder.verify_intent(token, intent)
        assert is_valid is True
    
    def test_detect_tampering(self):
        scope = IntentScope(allowed_resources=["test:read"])
        intent = IntentDeclaration(
            intent_id="test-012",
            declared_purpose="Original purpose",
            authorized_by="user@test.com",
            scope=scope
        )
        
        binder = SimpleIntentBinder()
        token = binder.bind_intent(intent, "user@test.com")
        
        # Tamper with intent
        intent.declared_purpose = "TAMPERED purpose"
        
        # Should fail verification
        is_valid = binder.verify_intent(token, intent)
        assert is_valid is False


# Integration test: Full workflow
class TestFullWorkflow:
    """Test complete IBA workflow."""
    
    def test_healthcare_appointment_scenario(self):
        """
        Simulate the healthcare appointment scheduler from docs.
        This is the core use case from TheArchitecture.html.
        """
        # Define scope (what agent CAN and CANNOT do)
        scope = IntentScope(
            allowed_resources=[
                "calendar:read",
                "calendar:write",
                "healthcare:search",
                "booking:create"
            ],
            forbidden_resources=[
                "medical_records:*",
                "insurance:*",
                "payment:modify"
            ],
            resource_limits={"max_api_calls": 50}
        )
        
        # Create intent
        intent = IntentDeclaration(
            intent_id="healthcare-001",
            declared_purpose="Schedule dentist appointment for next Tuesday",
            authorized_by="user@example.com",
            scope=scope
        )
        
        # Create validator
        validator = IntentValidator(intent)
        
        # TEST 1: Legitimate actions should succeed
        result = validator.validate_action("search", "healthcare:search")
        assert result['allowed'] is True
        
        result = validator.validate_action("read", "calendar:read")
        assert result['allowed'] is True
        
        result = validator.validate_action("create", "booking:create")
        assert result['allowed'] is True
        
        # TEST 2: Malicious actions should be blocked
        result = validator.validate_action("read", "medical_records:patient_history")
        assert result['allowed'] is False
        assert 'forbidden' in result['reason'].lower()
        
        result = validator.validate_action("modify", "insurance:plan")
        assert result['allowed'] is False
        
        result = validator.validate_action("modify", "payment:credit_card")
        assert result['allowed'] is False
        
        # TEST 3: Check statistics
        stats = validator.get_statistics()
        assert stats['allowed'] == 3  # 3 legitimate actions
        assert stats['blocked'] == 3  # 3 malicious actions
        assert stats['violation_rate'] == 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
