"""
Tests for the admin_users delete route.
Mocks the database and template layers to test authorization behavior.
"""

import asyncio
import sys
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.admin_users import admin_user_delete


def _make_request(current_user_id: int) -> MagicMock:
    request = MagicMock()
    request.state.user = MagicMock()
    request.state.user.id = current_user_id
    return request


def _make_user(user_id: int, role: str = "elevated") -> MagicMock:
    user = MagicMock()
    user.id = user_id
    user.role = role
    user.delete = AsyncMock()
    return user


class TestAdminUserDelete(unittest.TestCase):
    """Authorization and behavior tests for admin_user_delete."""

    def test_delete_user_success_returns_redirect(self):
        """Deleting another user redirects to the users list and calls delete()."""
        target = _make_user(user_id=7, role="elevated")
        request = _make_request(current_user_id=1)

        with patch(
            "apollo.server.routes.admin_users.User.get_or_none",
            new=AsyncMock(return_value=target),
        ):
            response = asyncio.run(admin_user_delete(request, user_id=7))

        target.delete.assert_awaited_once()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/admin/users")

    def test_delete_admin_user_is_allowed(self):
        """Admin users can be deleted (regression: prior guard was removed)."""
        target = _make_user(user_id=7, role="admin")
        request = _make_request(current_user_id=1)

        with patch(
            "apollo.server.routes.admin_users.User.get_or_none",
            new=AsyncMock(return_value=target),
        ):
            response = asyncio.run(admin_user_delete(request, user_id=7))

        target.delete.assert_awaited_once()
        self.assertEqual(response.status_code, 302)

    def test_cannot_delete_yourself(self):
        """Self-deletion is blocked and returns an error response without deleting."""
        target = _make_user(user_id=1, role="admin")
        request = _make_request(current_user_id=1)

        with patch(
            "apollo.server.routes.admin_users.User.get_or_none",
            new=AsyncMock(return_value=target),
        ), patch(
            "apollo.server.routes.admin_users.templates.TemplateResponse"
        ) as mock_template:
            mock_template.return_value = MagicMock()
            asyncio.run(admin_user_delete(request, user_id=1))

        target.delete.assert_not_awaited()
        mock_template.assert_called_once()
        template_name, context = mock_template.call_args.args
        self.assertEqual(template_name, "error.jinja")
        self.assertEqual(context["message"], "Cannot delete yourself")

    def test_delete_nonexistent_user_returns_error(self):
        """Deleting a missing user returns an error response, no delete() call."""
        request = _make_request(current_user_id=1)

        with patch(
            "apollo.server.routes.admin_users.User.get_or_none",
            new=AsyncMock(return_value=None),
        ), patch(
            "apollo.server.routes.admin_users.templates.TemplateResponse"
        ) as mock_template:
            mock_template.return_value = MagicMock()
            asyncio.run(admin_user_delete(request, user_id=999))

        mock_template.assert_called_once()
        template_name, context = mock_template.call_args.args
        self.assertEqual(template_name, "error.jinja")
        self.assertIn("999", context["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
