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
    assert sent["starttls"] is True # Ensure login path was taken
    assert sent["login"] == ("u", "p")


def test_send_email_no_auth(monkeypatch):
    """Test send_email_notification without username/password (no auth)."""
    sent_args = {}

    class MockSMTPNoAuth:
        def __init__(self, host, port):
            sent_args["host"] = host
            sent_args["port"] = port
            sent_args["login_called"] = False
            sent_args["starttls_called"] = False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

        def starttls(self):
            sent_args["starttls_called"] = True # Should not be called if no user/pass

        def login(self, user, pwd):
            sent_args["login_called"] = True # Should not be called

        def sendmail(self, sender, recipients, msg):
            sent_args["sendmail_called"] = True
            sent_args["sender"] = sender
            sent_args["recipients"] = recipients

    monkeypatch.setattr(smtplib, "SMTP", MockSMTPNoAuth)
    notifications.send_email_notification(
        subject="sub_no_auth",
        body="body_no_auth",
        sender="s_noauth@example.com",
        recipients=["r_noauth@example.com"],
        host="smtp.noauth.com",
        port=25,
        username=None,  # No username
        password=None   # No password
    )
    assert sent_args["host"] == "smtp.noauth.com"
    assert not sent_args["login_called"]
    assert not sent_args["starttls_called"] # starttls should only be called if login is attempted
    assert sent_args["sendmail_called"]
    assert sent_args["recipients"] == ["r_noauth@example.com"]


def test_send_email_smtp_connect_exception(monkeypatch, capsys):
    """Test send_email_notification when smtplib.SMTP() raises an exception."""
    def mock_smtp_connect_fails(host, port):
        raise smtplib.SMTPException("Connection failed")

    monkeypatch.setattr(smtplib, "SMTP", mock_smtp_connect_fails)

    notifications.send_email_notification(
        subject="sub_fail",
        body="body_fail",
        sender="s@example.com",
        recipients=["r@example.com"],
        host="smtp.fail.com",
        port=587
    )
    captured = capsys.readouterr()
    assert "SMTP error occurred: Connection failed" in captured.out


def test_send_email_smtp_sendmail_exception(monkeypatch, capsys):
    """Test send_email_notification when server.sendmail() raises an exception."""
    sendmail_args = {}
    class MockSMTPSendFail:
        def __init__(self, host, port):
            pass
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            pass
        def starttls(self): # Assume auth happens for this test
            pass
        def login(self, user, pwd):
            pass
        def sendmail(self, sender, recipients, msg):
            raise smtplib.SMTPException("Sendmail failed")

    monkeypatch.setattr(smtplib, "SMTP", MockSMTPSendFail)
    notifications.send_email_notification(
        subject="sub_sendfail",
        body="body_sendfail",
        sender="s@example.com",
        recipients=["r@example.com"],
        host="smtp.sendfail.com",
        port=587,
        username="u", # Provide credentials to go through login path
        password="p"
    )
    captured = capsys.readouterr()
    assert "SMTP error occurred: Sendmail failed" in captured.out


def test_send_email_missing_config(monkeypatch, capsys):
    smtp_called = False

    class DummySMTPNoCall: # Renamed to avoid confusion
        def __init__(self, *a, **k):
            nonlocal smtp_called
            smtp_called = True # This constructor itself being called means an attempt was made
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): pass
        def starttls(self): pass
        def login(self, u, p): pass
        def sendmail(self, *a, **k): pass

    monkeypatch.setattr(smtplib, "SMTP", DummySMTPNoCall)

    test_cases = [
        {"sender": "", "recipients": ["r@example.com"], "host": "h", "port": 587, "desc": "Empty sender"},
        {"sender": "s", "recipients": [], "host": "h", "port": 587, "desc": "Empty recipients list"},
        {"sender": "s", "recipients": None, "host": "h", "port": 587, "desc": "None recipients"},
        {"sender": "s", "recipients": [""], "host": "h", "port": 587, "desc": "Recipients list with empty string"},
        {"sender": "s", "recipients": ["r@example.com"], "host": "", "port": 587, "desc": "Empty host"},
        {"sender": "s", "recipients": ["r@example.com"], "host": None, "port": 587, "desc": "None host"},
    ]

    for case in test_cases:
        smtp_called = False # Reset for each case
        notifications.send_email_notification(
            subject="sub", body="body", sender=case["sender"], recipients=case["recipients"],
            host=case["host"], port=case["port"]
        )
        assert not smtp_called, f"SMTP should not be called for: {case['desc']}"
        captured = capsys.readouterr()
        assert "Essential email configuration or recipient list is missing or invalid." in captured.out


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


def test_format_summary_email_body_scenarios(capsys):
    """Test format_summary_email_body with various scenarios."""

    # 1. Empty summary_data_list
    html_empty = notifications.format_summary_email_body("run_empty", [], 0)
    assert "<h1>Stock Check Run Summary</h1>" in html_empty
    assert "Total User Notifications Sent:</strong> 0</p>" in html_empty
    # Check for empty tbody by removing all whitespace
    assert "<tbody></tbody>" in html_empty.replace(" ", "").replace("\n", "")

    # 2. Various subscription statuses
    summary_data_various_statuses = [
        {
            "product_name": "Prod A", "product_url": "http://a",
            "subscriptions": [{"user_email": "a@ex.com", "status": "Sent"}]
        },
        {
            "product_name": "Prod B", "product_url": "http://b",
            "subscriptions": [{"user_email": "b@ex.com", "status": "Not Sent - Out of Stock"}]
        },
        {
            "product_name": "Prod C", "product_url": "http://c",
            "subscriptions": [{"user_email": "c@ex.com", "status": "Skipped - Subscription Not Due"}]
        },
        {
            "product_name": "Prod D", "product_url": "http://d",
            "subscriptions": [{"user_email": "d@ex.com", "status": "Skipped - Invalid Subscription Object"}]
        },
        {
            "product_name": "Prod E", "product_url": "http://e",
            "subscriptions": [{"user_email": "e@ex.com", "status": "Error fetching subscriptions"}]
        },
        {
            "product_name": "Prod F", "product_url": "http://f",
            "subscriptions": [{"user_email": "f@ex.com", "status": "Not Sent - Delayed"}]
        },
        {
            "product_name": "Prod G", "product_url": "http://g",
            "subscriptions": [{"user_email": "g@ex.com", "status": "Not Sent - Scraping Error"}]
        },
        {
            "product_name": "Prod H", "product_url": "http://h",
            "subscriptions": [{"user_email": "h@ex.com", "status": "Skipped - Status Unknown"}]
        },
        {
            "product_name": "Prod I", "product_url": "http://i",
            "subscriptions": [{"user_email": "i@ex.com", "status": "Not Sent - Email Send Error"}]
        },
        {
            "product_name": "Prod J", "product_url": "http://j",
            "subscriptions": [{"user_email": "j@ex.com", "status": "Not Sent - Recipient Email Missing"}]
        },
        {
            "product_name": "Prod K", "product_url": "http://k",
            "subscriptions": [{"user_email": "k@ex.com", "status": "Not Sent - Email Config Missing"}]
        },
        {
            "product_name": "Prod L - Mixed", "product_url": "http://l",
            "subscriptions": [
                {"user_email": "l1@ex.com", "status": "Sent"},
                {"user_email": "l2@ex.com", "status": "Not Sent - Out of Stock"} # This state isn't realistic for same product but tests summary
            ]
        },
    ]
    html_various = notifications.format_summary_email_body("run_various", summary_data_various_statuses, 1)
    assert "Prod A" in html_various and "Notification sent" in html_various
    assert "Prod B" in html_various and "Out of stock" in html_various # summarize_subscriptions logic
    assert "Prod C" in html_various and "Status inconclusive" in html_various # Ignorable
    assert "Prod D" in html_various and "Status inconclusive" in html_various # Ignorable
    assert "Prod E" in html_various and "Status inconclusive" in html_various # Ignorable
    assert "Prod F" in html_various and "Status inconclusive" in html_various # Ignorable
    assert "Prod G" in html_various and "Status inconclusive" in html_various # Ignorable
    assert "Prod H" in html_various and "Status inconclusive" in html_various # Ignorable
    assert "Prod I" in html_various and "Failed to notify: i@ex.com" in html_various
    assert "Prod J" in html_various and "Failed to notify: j@ex.com" in html_various
    assert "Prod K" in html_various and "Failed to notify: k@ex.com" in html_various
    assert "Prod L - Mixed" in html_various and "Notification sent" in html_various # Sent takes precedence for overall status if one user got it

    # 3. Missing keys in product items
    summary_data_missing_keys = [
        {"product_url": "http://m_no_name", "subscriptions": []},
        {"product_name": "Prod N No URL", "subscriptions": []},
        {"product_name": "Prod O No Subs", "product_url": "http://o"},
    ]
    html_missing_keys = notifications.format_summary_email_body("run_missing", summary_data_missing_keys, 0)
    assert "<td>N/A</td>" in html_missing_keys # For Prod M
    assert "<td><a href=\"#\">#</a></td>" in html_missing_keys # For Prod N
    assert "Prod O No Subs" in html_missing_keys and "No subscriptions for this product." in html_missing_keys

    # 4. Product with no subscriptions (already covered by Prod O in missing keys)
    # and product with subscriptions, but all are in ignorable statuses (Prod C-H, F already cover this)

    # 5. Product in stock, but notification failed for some users
    summary_data_failed_notify = [
        {
            "product_name": "Prod P - Partial Fail", "product_url": "http://p",
            "subscriptions": [
                {"user_email": "p1_sent@ex.com", "status": "Sent"},
                {"user_email": "p2_failed@ex.com", "status": "Not Sent - Email Send Error"},
                {"user_email": "p3_nomail@ex.com", "status": "Not Sent - Recipient Email Missing"},
            ]
        }
    ]
    html_failed_notify = notifications.format_summary_email_body("run_partial_fail", summary_data_failed_notify, 1)
    assert "Prod P - Partial Fail" in html_failed_notify
    # Check that both p1_sent is listed as sent, and overall status reflects partial failure
    assert "p1_sent@ex.com" in html_failed_notify
    assert "Failed to notify: p2_failed@ex.com, p3_nomail@ex.com" in html_failed_notify
    assert "<td>p1_sent@ex.com</td>" in html_failed_notify # Check if sent email is listed
