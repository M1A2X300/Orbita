import subprocess
import unittest
from unittest.mock import MagicMock, patch

import iniciar_juego


class LauncherDiagnosticsTests(unittest.TestCase):
    def test_diagnostic_mode_shows_commands_and_inherits_process_output(self):
        server = MagicMock()
        server.pid = 101
        server.poll.return_value = 0
        browser = MagicMock()
        browser.pid = 202
        browser.poll.return_value = 0

        with (
            patch("iniciar_juego.find_server_python", return_value="python.exe"),
            patch("iniciar_juego.find_browser", return_value="browser.exe"),
            patch("iniciar_juego.wait_for_server"),
            patch("iniciar_juego.subprocess.Popen", side_effect=[server, browser]) as popen,
            patch("builtins.print") as print_message,
        ):
            result = iniciar_juego.main(["--diagnostico"])

        self.assertEqual(result, 0)
        self.assertEqual(popen.call_count, 2)
        for call in popen.call_args_list:
            self.assertIsNone(call.kwargs["stdout"])
            self.assertIsNone(call.kwargs["stderr"])
            self.assertEqual(call.kwargs["creationflags"], 0)
        messages = [call.args[0] for call in print_message.call_args_list]
        self.assertTrue(any(message.startswith("Comando del servidor:") for message in messages))
        self.assertTrue(any(message.startswith("Comando del navegador:") for message in messages))

    def test_normal_mode_keeps_process_output_hidden(self):
        server = MagicMock()
        server.poll.return_value = 0
        browser = MagicMock()
        browser.poll.return_value = 0

        with (
            patch("iniciar_juego.find_server_python", return_value="python.exe"),
            patch("iniciar_juego.find_browser", return_value="browser.exe"),
            patch("iniciar_juego.wait_for_server"),
            patch("iniciar_juego.subprocess.Popen", side_effect=[server, browser]) as popen,
            patch("builtins.print"),
        ):
            result = iniciar_juego.main([])

        self.assertEqual(result, 0)
        for call in popen.call_args_list:
            self.assertEqual(call.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
