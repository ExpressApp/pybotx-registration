from __future__ import annotations

import inspect

from pybotx import Bot


def test_pybotx_077_has_no_dynamic_account_provider_extension_point() -> None:
    """A passing compatibility gate, not a reason to use private monkey patches."""
    parameters = inspect.signature(Bot).parameters
    assert "bot_accounts" in parameters
    assert "account_provider" not in parameters
