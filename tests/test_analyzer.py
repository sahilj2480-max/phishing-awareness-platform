from phishguard.detection import analyzer


def test_analyze_clean_url():
    result = analyzer.analyze_url("https://www.google.com/search")
    assert result.score < 40
    assert result.verdict == "Likely Safe"


def test_analyze_ip_address_url():
    result = analyzer.analyze_url("http://192.168.1.50/login")
    assert result.score >= 70
    assert result.verdict == "Likely Phishing"


def test_analyze_shortener():
    result = analyzer.analyze_url("https://bit.ly/3xyzabc")
    assert result.score >= 40


def test_analyze_brand_impersonation():
    result = analyzer.analyze_url("https://paypal.secure-login.com/verify")
    assert result.verdict == "Likely Phishing"
    assert any("paypal" in f.message.lower() for f in result.findings)


def test_analyze_suspicious_email():
    headers = {
        "From": '"PayPal Support" <support@paypa1-security.example>',
        "Reply-To": "support@paypa1-security.example",
        "Subject": "Action required: verify your account now",
    }
    body = "Dear customer, your account will be suspended within 24 hours. Click here to verify."
    result = analyzer.analyze_email(headers, body, ["http://paypal.secure-login.com"])
    assert result.verdict == "Likely Phishing"
    assert result.score >= 70


def test_analyze_clean_email():
    headers = {"From": "Alice <alice@example.com>", "Subject": "Weekly report"}
    result = analyzer.analyze_email(headers, "Hi team, here is the weekly report.")
    assert result.verdict == "Likely Safe"


def test_analyze_failed_auth():
    headers = {
        "From": "billing@example.com",
        "Subject": "Invoice due",
        "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
    }
    result = analyzer.analyze_email(headers, "Please pay your invoice.")
    assert result.score >= 70
