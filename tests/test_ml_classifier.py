from phishguard.detection import ml_classifier


def _indexes():
    return {name: i for i, name in enumerate(ml_classifier.FEATURE_NAMES)}


def test_extract_features_ip_url():
    idx = _indexes()
    f = ml_classifier.extract_features("http://192.168.1.50/login")
    assert f[idx["has_ip"]] == 1.0
    assert f[idx["uses_https"]] == 0.0


def test_extract_features_brand_impersonation():
    idx = _indexes()
    f = ml_classifier.extract_features("https://paypal.secure-login.com/verify")
    assert f[idx["brand_impersonation"]] == 1.0


def test_extract_features_benign_url():
    idx = _indexes()
    f = ml_classifier.extract_features("https://www.google.com")
    assert f[idx["brand_impersonation"]] == 0.0
    assert f[idx["uses_https"]] == 1.0
    assert f[idx["has_ip"]] == 0.0


def test_extract_features_feature_length():
    assert len(ml_classifier.extract_features("https://example.com")) == len(
        ml_classifier.FEATURE_NAMES
    )


def test_train_and_predict(tmp_path):
    data = tmp_path / "data.csv"
    data.write_text(
        "url,label\n"
        "http://192.168.1.50/login,1\n"
        "http://104.20.1.1/verify,1\n"
        "http://paypal.secure-login.com,1\n"
        "http://secure-login.ml,1\n"
        "http://bit.ly/abc,1\n"
        "http://free-gift.top,1\n"
        "http://xn--pypl-6qa.com,1\n"
        "http://google.com@evil.org,1\n"
        "http://45.76.11.23/update,1\n"
        "http://tinyurl.com/x,1\n"
        "https://www.google.com,0\n"
        "https://www.amazon.com,0\n"
        "https://github.com,0\n"
        "https://www.microsoft.com,0\n"
        "https://www.apple.com,0\n"
        "https://www.paypal.com,0\n"
        "https://www.netflix.com,0\n"
        "https://en.wikipedia.org,0\n"
        "https://www.reddit.com,0\n"
        "https://www.linkedin.com,0\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.joblib"
    metrics = ml_classifier.train(str(data), str(model))
    assert metrics["accuracy"] >= 0.8
    assert model.exists()

    assert ml_classifier.predict("http://192.168.1.50/login", str(model))["label"] == 1
    assert ml_classifier.predict("https://www.google.com", str(model))["label"] == 0


def test_predict_missing_model(tmp_path):
    try:
        ml_classifier.predict("https://example.com", str(tmp_path / "nope.joblib"))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError for missing model")
