import os
import tempfile
import unittest
from unittest.mock import patch

from tools import control_servidor


class GameLauncherTests(unittest.TestCase):
    @patch("tools.control_servidor.urllib.request.urlopen")
    def test_shutdown_request_uses_the_local_same_origin(self, urlopen):
        response = urlopen.return_value.__enter__.return_value
        response.status = 200

        self.assertTrue(control_servidor.request_shutdown())
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.get_header("Origin"),
            f"http://127.0.0.1:{control_servidor.PORT}",
        )

    def test_setup_admin_stores_only_a_password_hash(self):
        password = "orbita-admin-password"
        with tempfile.TemporaryDirectory() as profile:
            with patch.dict(os.environ, {"LOCALAPPDATA": profile}), patch(
                "tools.control_servidor.getpass.getpass", side_effect=[password, password]
            ), patch("builtins.print"):
                result = control_servidor.setup_admin_password()
                credential_path = control_servidor.admin_credential_path()

            self.assertEqual(result, 0)
            self.assertNotIn(password, credential_path.read_text(encoding="utf-8"))
            with patch.dict(os.environ, {"LOCALAPPDATA": profile}), patch(
                "tools.control_servidor.getpass.getpass", side_effect=["incorrecta", password]
            ), patch("builtins.print"):
                self.assertFalse(control_servidor.verify_admin_password())
                self.assertTrue(control_servidor.verify_admin_password())

    @patch("tools.control_servidor.wait_for_server_shutdown", return_value=True)
    @patch("tools.control_servidor.request_shutdown", return_value=True)
    @patch("tools.control_servidor.verify_admin_password", return_value=True)
    @patch("builtins.input", return_value="s")
    def test_stop_server_requires_password_and_confirmation(
        self, _input, verify_password, request_shutdown, wait_for_server_shutdown
    ):
        with patch("builtins.print"):
            result = control_servidor.stop_server_command()

        self.assertEqual(result, 0)
        verify_password.assert_called_once_with()
        request_shutdown.assert_called_once_with()
        wait_for_server_shutdown.assert_called_once_with()

    @patch("tools.control_servidor.request_shutdown")
    @patch("tools.control_servidor.verify_admin_password", return_value=True)
    @patch("builtins.input", return_value="n")
    def test_stop_server_can_be_cancelled(self, _input, _verify_password, request_shutdown):
        with patch("builtins.print"):
            result = control_servidor.stop_server_command()

        self.assertEqual(result, 0)
        request_shutdown.assert_not_called()

    @patch("tools.control_servidor.request_shutdown", return_value=False)
    @patch("tools.control_servidor.verify_admin_password", return_value=True)
    @patch("builtins.input", return_value="s")
    def test_stop_server_reports_when_no_local_server_is_available(
        self, _input, _verify_password, request_shutdown
    ):
        with patch("builtins.print"):
            result = control_servidor.stop_server_command()

        self.assertEqual(result, 1)
        request_shutdown.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
