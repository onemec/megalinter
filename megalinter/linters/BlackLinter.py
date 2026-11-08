#!/usr/bin/env python3
"""
Use Black to format python files
https://github.com/psf/black
"""

from megalinter import Linter, config


class BlackLinter(Linter):
    def pre_test(self, test_name):
        config.set_value(self.request_id, "PYTHON_DEFAULT_STYLE", "black")
