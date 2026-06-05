import io
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lxperun.cli import main


class CliHelpTest(unittest.TestCase):
    def test_help_topic_mentions_command(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "hardware"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("LxPerun", output)
        self.assertIn("hardware", output)
        self.assertIn("--raw", output)


if __name__ == "__main__":
    unittest.main()
