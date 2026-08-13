from threat_triage.security.models import (
    LanguageFeatures,
    SecurityFeatures,
    SenderFeatures,
    URLFeatures,
)


def test_security_features_model_creation():
    url_features = URLFeatures(
        has_url=True,
        url_count=1,
        uses_ip_address_url=False,
        uses_url_shortener=False,
        suspicious_tld=False,
        punycode_domain=False,
        excessive_subdomains=False,
        domain_contains_digits=True,
        domain_contains_hyphen=True,
        credential_path_keyword=True,
        extracted_urls=[
            "https://paypa1-security.example/login"
        ],
        matched_credential_terms=[
            "login"
        ],
    )

    sender_features = SenderFeatures(
        sender_present=True,
        sender_address="support@paypa1-security.example",
        sender_domain="paypa1-security.example",
        sender_domain_has_digits=True,
        sender_domain_has_hyphen=True,
    )

    language_features = LanguageFeatures(
        urgency_language=True,
        credential_request=True,
        financial_request=False,
        verification_request=True,
        account_suspension_language=True,
        password_reset_language=False,
        matched_urgency_terms=[
            "urgent",
            "immediately",
        ],
        matched_credential_terms=[
            "verify your password",
        ],
        matched_verification_terms=[
            "verify",
        ],
        matched_suspension_terms=[
            "account will be suspended",
        ],
    )

    security_features = SecurityFeatures(
        message_id="example-message-id",
        url=url_features,
        sender=sender_features,
        language=language_features,
    )

    assert security_features.message_id == "example-message-id"

    assert security_features.url.has_url is True
    assert security_features.url.url_count == 1
    assert security_features.url.credential_path_keyword is True

    assert security_features.sender.sender_present is True
    assert (
        security_features.sender.sender_domain
        == "paypa1-security.example"
    )

    assert security_features.language.urgency_language is True
    assert security_features.language.credential_request is True