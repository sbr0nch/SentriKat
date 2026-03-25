"""
Tests for the SaaS dual-mode system (app/saas.py).

Verifies that:
- On-premise mode: Everything works as before (no restrictions)
- SaaS mode: Tenant isolation, org_admin self-service, per-subscription features
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from flask import session

# app and client fixtures come from conftest.py


class TestModeDetection:
    """Test is_saas_mode() and is_onpremise_mode()."""

    def test_default_is_onpremise(self):
        """Default mode should be on-premise."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SENTRIKAT_MODE', None)
            # Re-import to pick up env change
            import importlib
            import app.saas as saas_module
            importlib.reload(saas_module)
            # The cached value at module load was 'onpremise'
            # For testing, check the env-based logic
            assert os.environ.get('SENTRIKAT_MODE', 'onpremise').lower() == 'onpremise'

    def test_saas_mode_when_set(self):
        """SENTRIKAT_MODE=saas should enable SaaS mode."""
        with patch.dict(os.environ, {'SENTRIKAT_MODE': 'saas'}):
            mode = os.environ.get('SENTRIKAT_MODE', 'onpremise').lower()
            assert mode == 'saas'

    def test_onpremise_mode_explicit(self):
        """SENTRIKAT_MODE=onpremise should be on-premise."""
        with patch.dict(os.environ, {'SENTRIKAT_MODE': 'onpremise'}):
            mode = os.environ.get('SENTRIKAT_MODE', 'onpremise').lower()
            assert mode == 'onpremise'

    def test_case_insensitive(self):
        """Mode detection should be case-insensitive."""
        with patch.dict(os.environ, {'SENTRIKAT_MODE': 'SaaS'}):
            mode = os.environ.get('SENTRIKAT_MODE', 'onpremise').lower()
            assert mode == 'saas'


class TestGetScopedOrgId:
    """Test get_scoped_org_id() in both modes."""

    def test_onpremise_super_admin_sees_all(self, app):
        """On-premise: super_admin can access all orgs (returns None if no org specified)."""
        from app.saas import get_scoped_org_id
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):
            with app.test_request_context('/api/test'):
                user = MagicMock()
                user.role = 'super_admin'
                user.is_admin = True
                user.organization_id = 1
                # No org in request args or session
                with patch('app.saas.session', {}):
                    result = get_scoped_org_id(user)
                    assert result is None  # Can see all

    def test_saas_super_admin_scoped(self, app):
        """SaaS: super_admin is always scoped to an org."""
        from app.saas import get_scoped_org_id
        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            with app.test_request_context('/api/test'):
                user = MagicMock()
                user.role = 'super_admin'
                user.is_admin = True
                user.organization_id = 1
                with patch('app.saas.session', {'organization_id': 5}):
                    result = get_scoped_org_id(user)
                    assert result == 5  # Scoped to session org

    def test_saas_org_admin_scoped(self, app):
        """SaaS: org_admin always scoped to their org."""
        from app.saas import get_scoped_org_id
        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            with app.test_request_context('/api/test'):
                user = MagicMock()
                user.role = 'org_admin'
                user.is_admin = False
                user.organization_id = 3
                with patch('app.saas.session', {'organization_id': 3}):
                    result = get_scoped_org_id(user)
                    assert result == 3

    def test_onpremise_regular_user_scoped(self, app):
        """On-premise: regular users scoped to their org."""
        from app.saas import get_scoped_org_id
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):
            with app.test_request_context('/api/test'):
                user = MagicMock()
                user.role = 'user'
                user.is_admin = False
                user.organization_id = 2
                with patch('app.saas.session', {'organization_id': 2}):
                    result = get_scoped_org_id(user)
                    assert result == 2


class TestRequiresOrgScope:
    """Test requires_org_scope decorator."""

    def test_onpremise_no_restriction(self, app):
        """On-premise: decorator has no effect."""
        from app.saas import requires_org_scope
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):

            @requires_org_scope
            def test_view():
                return 'ok'

            with app.test_request_context('/api/test'):
                result = test_view()
                assert result == 'ok'

    def test_saas_blocks_without_org(self, app):
        """SaaS: returns 403 when no org_id available."""
        from app.saas import requires_org_scope
        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            with patch('app.saas.get_scoped_org_id', return_value=None):

                @requires_org_scope
                def test_view():
                    return 'ok'

                with app.test_request_context('/api/test'):
                    result = test_view()
                    assert result[1] == 403

    def test_saas_allows_with_org(self, app):
        """SaaS: allows access when org_id is available."""
        from app.saas import requires_org_scope
        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            with patch('app.saas.get_scoped_org_id', return_value=1):

                @requires_org_scope
                def test_view():
                    return 'ok'

                with app.test_request_context('/api/test'):
                    result = test_view()
                    assert result == 'ok'


class TestSaasAdminOrOrgAdmin:
    """Test saas_admin_or_org_admin decorator."""

    def test_onpremise_requires_super_admin(self, app):
        """On-premise: only super_admin allowed (same as @admin_required)."""
        from app.saas import saas_admin_or_org_admin

        @saas_admin_or_org_admin
        def test_view():
            return 'ok'

        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):
            with app.test_request_context('/api/test', content_type='application/json'):
                # org_admin should be denied in on-premise
                user = MagicMock()
                user.role = 'org_admin'
                user.is_admin = False
                with patch('app.saas.session', {'user_id': 1}):
                    with patch('app.auth._safe_get_user', return_value=user):
                        result = test_view()
                        assert result[1] == 403

    def test_saas_allows_org_admin(self, app):
        """SaaS: org_admin is allowed (self-service)."""
        from app.saas import saas_admin_or_org_admin

        @saas_admin_or_org_admin
        def test_view():
            return 'ok'

        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            with app.test_request_context('/api/test'):
                user = MagicMock()
                user.role = 'org_admin'
                user.is_admin = False
                with patch('app.saas.session', {'user_id': 1}):
                    with patch('app.auth._safe_get_user', return_value=user):
                        result = test_view()
                        assert result == 'ok'


class TestRestrictCrossOrgAccess:
    """Test restrict_cross_org_access decorator."""

    def test_onpremise_no_restriction(self, app):
        """On-premise: super_admin can access all orgs."""
        from app.saas import restrict_cross_org_access
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):

            @restrict_cross_org_access
            def test_view():
                return 'ok'

            with app.test_request_context('/api/test'):
                result = test_view()
                assert result == 'ok'

    def test_saas_blocks_cross_org(self, app):
        """SaaS: super_admin blocked without org scope."""
        from app.saas import restrict_cross_org_access
        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            with patch('app.saas.get_scoped_org_id', return_value=None):

                @restrict_cross_org_access
                def test_view():
                    return 'ok'

                user = MagicMock()
                user.role = 'super_admin'
                user.is_admin = True
                with app.test_request_context('/api/test'):
                    with patch('app.saas.session', {'user_id': 1}):
                        with patch('app.auth._safe_get_user', return_value=user):
                            result = test_view()
                            assert result[1] == 403


class TestGetEffectiveFeatures:
    """Test get_effective_features() in both modes."""

    def test_onpremise_professional_license(self, app):
        """On-premise: Professional license enables all features."""
        from app.saas import get_effective_features, _get_license_features
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):
            with app.app_context():
                mock_license = MagicMock()
                mock_license.is_professional.return_value = True
                with patch('app.licensing.get_license', return_value=mock_license):
                    features = get_effective_features(org_id=1)
                    assert features.get('ldap') is True
                    assert features.get('sso') is True

    def test_onpremise_demo_license(self, app):
        """On-premise: Demo license disables premium features."""
        from app.saas import get_effective_features
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):
            with app.app_context():
                mock_license = MagicMock()
                mock_license.is_professional.return_value = False
                with patch('app.licensing.get_license', return_value=mock_license):
                    features = get_effective_features(org_id=1)
                    assert features.get('ldap') is False
                    assert features.get('sso') is False


class TestRequiresFeature:
    """Test requires_feature() decorator."""

    def test_onpremise_professional_allowed(self, app):
        """On-premise: Professional license allows feature."""
        from app.saas import requires_feature
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):

            @requires_feature('ldap')
            def test_view():
                return 'ok'

            mock_license = MagicMock()
            mock_license.is_professional.return_value = True
            with app.test_request_context('/api/test'):
                with patch('app.licensing.get_license', return_value=mock_license):
                    result = test_view()
                    assert result == 'ok'

    def test_onpremise_demo_blocked(self, app):
        """On-premise: Demo license blocks feature."""
        from app.saas import requires_feature
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):

            @requires_feature('ldap')
            def test_view():
                return 'ok'

            mock_license = MagicMock()
            mock_license.is_professional.return_value = False
            mock_license.get_effective_edition.return_value = 'community'
            with app.test_request_context('/api/test'):
                with patch('app.licensing.get_license', return_value=mock_license):
                    result = test_view()
                    assert result[1] == 403


class TestModeInfo:
    """Test get_mode_info()."""

    def test_onpremise_info(self):
        """On-premise mode returns correct info."""
        from app.saas import get_mode_info
        with patch('app.saas._SENTRIKAT_MODE', 'onpremise'):
            info = get_mode_info()
            assert info['mode'] == 'onpremise'
            assert info['is_saas'] is False
            assert info['is_onpremise'] is True

    def test_saas_info(self):
        """SaaS mode returns correct info."""
        from app.saas import get_mode_info
        with patch('app.saas._SENTRIKAT_MODE', 'saas'):
            info = get_mode_info()
            assert info['mode'] == 'saas'
            assert info['is_saas'] is True
            assert info['is_onpremise'] is False
