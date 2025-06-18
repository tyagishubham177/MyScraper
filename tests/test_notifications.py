import smtplib
from scripts import notifications


def test_format_messages():
    long_html = notifications.format_long_message("Prod", "http://x")
    assert "Prod" in long_html and "http://x" in long_html
    short_msg = notifications.format_short_message("Prod")
    assert "Prod" in short_msg


def test_send_email_notification(monkeypatch):
    sent = {}

    class DummySMTP:
        def __init__(self, host, port):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def starttls(self):
            sent["starttls"] = True

        def login(self, user, pwd):
            sent["login"] = (user, pwd)

        def sendmail(self, sender, recipients, msg):
            sent["message"] = msg
            sent["recipients"] = recipients
            sent["sender"] = sender

    monkeypatch.setattr(smtplib, "SMTP", DummySMTP)
    notifications.send_email_notification(
        subject="sub",
        body="body",
        sender="s@example.com",
        recipients=["r@example.com"],
        host="smtp.example.com",
        port=587,
        username="u",
        password="p",
    )
    assert sent["host"] == "smtp.example.com"
    assert sent["recipients"] == ["r@example.com"]


def test_send_email_missing_config(monkeypatch):
    called = False

    def dummy(*a, **k):
        nonlocal called
        called = True
        return DummySMTP(*a, **k)

    class DummySMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def sendmail(self, *a, **k):
            pass

    monkeypatch.setattr(smtplib, "SMTP", dummy)
    notifications.send_email_notification(
        subject="sub",
        body="body",
        sender="",
        recipients=["r@example.com"],
        host="smtp.example.com",
        port=587,
    )
    assert not called


def test_format_summary_email_body():
    data = [
        {
            "product_name": "Prod",
            "product_url": "http://x",
            "subscriptions": [{"user_email": "u@example.com", "status": "Sent"}],
        }
    ]
    html = notifications.format_summary_email_body("run", data, 1)
    assert "Prod" in html
    assert "http://x" in html
    assert "Notification sent" in html
