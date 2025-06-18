import importlib
import os


def test_environment_overrides(monkeypatch):
    monkeypatch.setenv('EMAIL_PORT', '2525')
    monkeypatch.setenv('APP_BASE_URL', 'http://example.com')
    config = importlib.reload(importlib.import_module('scripts.config'))
    assert config.EMAIL_PORT == 2525
    assert config.APP_BASE_URL == 'http://example.com'
