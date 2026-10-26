import smtplib
import asyncio
import pytest
from scripts import notifications


def test_format_messages():
    long_html = notifications.format_long_message("Prod", "http://x")
    assert "Prod" in long_html and "http://x" in long_html
    short_msg = notifications.format_short_message("Prod")
    assert "Prod" in short_msg

def test_format_auto_pause_message():
    html = notifications.format_auto_pause_message("Prod")
    assert "Prod" in html
    assert "Auto-Paused" in html


@pytest.fixture
def smtp_transport(monkeypatch):
    events = {}
    class SMTP:
        def __init__(self, host, port, **kwargs):
            events.update(host=host, port=port, **kwargs)
        def __enter__(self): return self
        def __exit__(self, *args): events['closed'] = True
        def starttls(self, **kwargs): events['tls'] = kwargs['context']
        def login(self, user, password): events['login'] = (user, password)
        def sendmail(self, sender, recipients, message):
            events['sent'] = (sender, recipients, message)
            return events.get('refused', {})
    monkeypatch.setattr(smtplib, 'SMTP', SMTP)
    monkeypatch.setattr(smtplib, 'SMTP_SSL', SMTP)
    return events


def send(**overrides):
    args = dict(subject='Stock', body='Body', sender='sender@example.invalid',
                recipients=['a@example.invalid', 'b@example.invalid'],
                host='smtp.example.invalid', port=587, username='user', password='password')
    args.update(overrides)
    return asyncio.run(notifications.send_email_notification(**args))


@pytest.mark.parametrize('port', [25, 465, 587])
def test_send_email_notification(smtp_transport, port):
    result = send(port=port)
    assert result == {'a@example.invalid': True, 'b@example.invalid': True}
    assert smtp_transport['timeout'] == 20
    assert smtp_transport['closed']
    assert smtp_transport['login'] == ('user', 'password')
    assert (('context' in smtp_transport) if port == 465 else ('tls' in smtp_transport))
    assert smtp_transport.get('tls', smtp_transport.get('context')).check_hostname


def test_send_email_no_auth_still_encrypts(smtp_transport):
    send(username=None, password=None)
    assert 'tls' in smtp_transport and 'login' not in smtp_transport


@pytest.mark.parametrize('error', [smtplib.SMTPConnectError(421, 'unavailable'), TimeoutError('deadline')])
def test_send_email_connect_failure_propagates(monkeypatch, error):
    def fail(*args, **kwargs): raise error
    monkeypatch.setattr(smtplib, 'SMTP', fail)
    with pytest.raises(type(error)):
        send()


def test_send_email_partial_refusal(smtp_transport):
    smtp_transport['refused'] = {'b@example.invalid': (550, 'rejected')}
    assert send() == {'a@example.invalid': True, 'b@example.invalid': False}


def test_send_email_sendmail_exception(monkeypatch, smtp_transport):
    class FailingSMTP:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def starttls(self, **kwargs): pass
        def login(self, *args): pass
        def sendmail(self, *args): raise smtplib.SMTPRecipientsRefused({'a': (550, 'rejected')})
    monkeypatch.setattr(smtplib, 'SMTP', lambda *args, **kwargs: FailingSMTP())
    with pytest.raises(smtplib.SMTPRecipientsRefused): send()


@pytest.mark.parametrize('override', [{'sender':''}, {'recipients':[]}, {'recipients':None},
                                     {'recipients':['']}, {'host':''}, {'host':None}])
def test_send_email_missing_config(monkeypatch, override):
    def unexpected(*args, **kwargs): pytest.fail('Invalid configuration opened a connection')
    monkeypatch.setattr(smtplib, 'SMTP', unexpected)
    with pytest.raises(ValueError, match='Missing email configuration'): send(**override)


def test_format_summary_email_body():
    data = [
        {
            "product_name": "Prod",
            "product_url": "http://x",
            "consecutive_in_stock": 2,
            "subscriptions": [
                {"user_email": "u@example.com", "status": "Sent", "pincode": "111111"}
            ],
        }
    ]
    html = notifications.format_summary_email_body("run", data, 1)
    assert "<a href=\"http://x\">Prod</a>" in html
    assert "<td>2</td>" in html
    assert "u@example.com" in html
    assert "<td>111111</td>" in html


def test_format_summary_email_body_multiple_pincodes():
    data = [
        {
            "product_name": "Prod",
            "product_url": "http://x",
            "consecutive_in_stock": 2,
            "pincode": "111",
            "subscriptions": [
                {"user_email": "a@example.com", "status": "Sent", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod",
            "product_url": "http://x",
            "consecutive_in_stock": 1,
            "pincode": "222",
            "subscriptions": [
                {"user_email": "b@example.com", "status": "Sent", "pincode": "222"}
            ],
        },
    ]
    html = notifications.format_summary_email_body("run", data, 2)
    assert "<td>111</td>" in html and "<td>222</td>" in html
    assert "<td>2</td>" in html and "<td>1</td>" in html


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
            "product_name": "Prod A",
            "product_url": "http://a",
            "consecutive_in_stock": 1,
            "subscriptions": [
                {"user_email": "a@ex.com", "status": "Sent", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod B", "product_url": "http://b",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "b@ex.com", "status": "Not Sent - Out of Stock", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod C", "product_url": "http://c",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "c@ex.com", "status": "Skipped - Subscription Not Due", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod D", "product_url": "http://d",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "d@ex.com", "status": "Skipped - Invalid Subscription Object", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod E", "product_url": "http://e",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "e@ex.com", "status": "Error fetching subscriptions", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod F", "product_url": "http://f",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "f@ex.com", "status": "Not Sent - Delayed", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod G", "product_url": "http://g",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "g@ex.com", "status": "Not Sent - Scraping Error", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod H", "product_url": "http://h",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "h@ex.com", "status": "Skipped - Status Unknown", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod I", "product_url": "http://i",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "i@ex.com", "status": "Not Sent - Email Send Error", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod J", "product_url": "http://j",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "j@ex.com", "status": "Not Sent - Recipient Email Missing", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod K", "product_url": "http://k",
            "consecutive_in_stock": 0,
            "subscriptions": [
                {"user_email": "k@ex.com", "status": "Not Sent - Email Config Missing", "pincode": "111"}
            ],
        },
        {
            "product_name": "Prod L - Mixed", "product_url": "http://l",
            "consecutive_in_stock": 1,
            "subscriptions": [
                {"user_email": "l1@ex.com", "status": "Sent", "pincode": "111"},
                {"user_email": "l2@ex.com", "status": "Not Sent - Out of Stock", "pincode": "111"}  # This state isn't realistic for same product but tests summary
            ]
        },
    ]
    html_various = notifications.format_summary_email_body("run_various", summary_data_various_statuses, 1)
    assert "In-Stock Streak" in html_various
    # Only products with at least one successful notification should appear
    assert "<a href=\"http://a\">Prod A</a>" in html_various
    assert "<a href=\"http://l\">Prod L - Mixed</a>" in html_various
    # Products without sent notifications should be omitted
    for prod_letter in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]:
        assert f"http://{prod_letter}" not in html_various

    # 3. Missing keys in product items
    summary_data_missing_keys = [
        {"product_url": "http://m_no_name", "subscriptions": []},
        {"product_name": "Prod N No URL", "subscriptions": []},
        {"product_name": "Prod O No Subs", "product_url": "http://o"},
    ]
    html_missing_keys = notifications.format_summary_email_body("run_missing", summary_data_missing_keys, 0)
    assert "http://m_no_name" not in html_missing_keys  # Skip products missing name
    # Products with no valid subscriptions should be omitted
    assert "Prod N No URL" not in html_missing_keys
    assert "Prod O No Subs" not in html_missing_keys

    # 4. Product with no subscriptions (already covered by Prod O in missing keys)
    # and product with subscriptions, but all are in ignorable statuses (Prod C-H, F already cover this)

    # 5. Product in stock, but notification failed for some users
    summary_data_failed_notify = [
        {
            "product_name": "Prod P - Partial Fail",
            "product_url": "http://p",
            "consecutive_in_stock": 1,
            "subscriptions": [
                {"user_email": "p1_sent@ex.com", "status": "Sent", "pincode": "111"},
                {"user_email": "p2_failed@ex.com", "status": "Not Sent - Email Send Error", "pincode": "111"},
                {"user_email": "p3_nomail@ex.com", "status": "Not Sent - Recipient Email Missing", "pincode": "111"},
            ],
        }
    ]
    html_failed_notify = notifications.format_summary_email_body("run_partial_fail", summary_data_failed_notify, 1)
    assert "<a href=\"http://p\">Prod P - Partial Fail</a>" in html_failed_notify
    assert "p1_sent@ex.com" in html_failed_notify
    assert "<td>111</td>" in html_failed_notify
