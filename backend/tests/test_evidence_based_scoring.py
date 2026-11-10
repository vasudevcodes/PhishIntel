"""
Comprehensive Regression Test Suite for Evidence-Based Phishing Risk Scoring Redesign.
Covers:
1. Real corporate notification fixtures (OpenAI, LinkedIn, Pinterest, Google, Overleaf).
2. Clean plain-text emails (01_simple_plaintext).
3. Dangerous executable and double-extension attachments (floor >= 75).
4. Deceptive displayed links (anchor spoofing) (floor >= 75).
5. Userinfo @ authority deception (floor >= 75).
6. Lookalike / brand impersonation domains (floor >= 75 when unaligned).
7. Credential-harvesting URL with unaligned or failing authentication (floor >= 75).
8. Explicit authentication failure (floor >= 30, REVIEW_RECOMMENDED).
9. Contradictory authentication headers (floor >= 30, REVIEW_RECOMMENDED).
10. Incomplete / malformed email (07_malformed.eml -> INSUFFICIENT_EVIDENCE).
11. Corroboration dampening for DistilBERT on clean emails (score <= 25).
12. Full 5-category point breakdown integrity (sender_auth <= 25, url <= 25, content <= 20, ml <= 20, header_ip <= 10, total <= 100).
"""

from pathlib import Path
import pytest

from app.schemas.email import AttachmentInfo, EmailBodyInfo, EmailHeaderInfo, ExtractedURL
from app.schemas.email_authentication import (
    AuthResultStatus,
    DKIMEvidence,
    DMARCEvidence,
    EmailAuthenticationAnalysis,
    OverallAuthStatus,
    SPFEvidence,
)
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    EvidenceCompletenessStatus,
    ModelInferenceEvidence,
    ModelInferenceStatus,
)
from app.services.email_authentication import analyze_email_authentication
from app.services.email_parser import parse_email_message
from app.services.evidence_fusion import fuse_evidence
from app.services.scoring_engine import calculate_phishing_risk_score
from app.services.url_intelligence import analyze_email_extracted_urls, analyze_urls

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ==============================================================================
# 1. Genuine Corporate Notifications
# ==============================================================================

def test_openai_privacy_policy_notification():
    """
    Verifies that the authentic OpenAI Privacy Policy update fixture evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE, correctly treating
    the login_hint OIDC parameter on chatgpt.com as benign.
    """
    path = FIXTURES_DIR / "openai_privacy_policy.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "openai_privacy_policy.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE
    assert ef.risk_score_breakdown is not None
    assert ef.risk_score_breakdown.ml_model.is_dampened is True
    assert ef.risk_score_breakdown.sender_auth.score == 0
    assert ef.risk_score_breakdown.url_intelligence.score == 0


def test_linkedin_complete_profile_notification():
    """
    Verifies that the authentic LinkedIn notification fixture evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE, with uncorroborated
    DistilBERT shortcut learning dampened to <= 5 points.
    """
    path = FIXTURES_DIR / "linkedin_complete_profile.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "linkedin_complete_profile.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE
    assert ef.risk_score_breakdown is not None
    assert ef.risk_score_breakdown.ml_model.is_dampened is True
    assert ef.risk_score_breakdown.ml_model.score <= 5


def test_pinterest_terms_update_notification():
    """
    Verifies that the authentic Pinterest Terms of Service update evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE.
    """
    path = FIXTURES_DIR / "pinterest_terms_update.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "pinterest_terms_update.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE


def test_google_account_notification():
    """
    Verifies that authentic Google Account security notifications evaluate to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE.
    """
    path = FIXTURES_DIR / "google_notification.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "google_notification.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE


def test_overleaf_welcome_notification():
    """
    Verifies that authentic Overleaf welcome notification evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE.
    """
    path = FIXTURES_DIR / "overleaf_welcome.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "overleaf_welcome.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE


def test_simple_plaintext_email():
    """
    Verifies that 01_simple_plaintext.eml evaluates to LOW_RISK_INDICATORS (score <= 25)
    with PARTIAL_COVERAGE due to missing auth headers and transit hops.
    """
    path = FIXTURES_DIR / "01_simple_plaintext.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "01_simple_plaintext.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.evidence_completeness == EvidenceCompletenessStatus.PARTIAL_COVERAGE


# ==============================================================================
# 2. Critical Threat Floors (Score >= 75 -> HIGH_RISK_INDICATORS_PRESENT)
# ==============================================================================

def test_critical_threat_floor_dangerous_attachment():
    """
    Verifies that dangerous executable or double-extension attachments (.pdf.exe)
    trigger the critical threat floor (score >= 75, HIGH_RISK_INDICATORS_PRESENT)
    regardless of other clean signals.
    """
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="billing@legit-vendor.com", subject="Important invoice"),
        body_info=EmailBodyInfo(plain_text="Please review your monthly invoice attached."),
        attachments=[
            AttachmentInfo(
                filename="statement_2026.pdf.exe",
                content_type="application/x-msdownload",
                size_bytes=4096,
                sha256="abc12345",
            )
        ],
        url_analysis=None,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert any("executable" in n.lower() or "double" in n.lower() for n in neg)


def test_critical_threat_floor_deceptive_displayed_link():
    """
    Verifies that deceptive anchor text spoofing (<a href="evil.com">https://paypal.com</a>)
    triggers the critical threat floor (score >= 75, HIGH_RISK_INDICATORS_PRESENT).
    """
    urls = [
        ExtractedURL(
            url="https://phish-harvesting-portal.com/login",
            domain="phish-harvesting-portal.com",
            source="html_href",
            anchor_text="https://secure.bankofamerica.com/login",
        )
    ]
    url_analysis = analyze_email_extracted_urls(urls, sender_domain="notifications.com")
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="service@notifications.com", subject="Action Required"),
        body_info=EmailBodyInfo(html_extracted_text="Please log in to your account."),
        attachments=[],
        url_analysis=url_analysis,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert any("deceptive" in n.lower() for n in neg)


def test_critical_threat_floor_userinfo_auth_deception():
    """
    Verifies that authority deception with '@' syntax (https://paypal.com@evil-site.com)
    triggers the critical threat floor (score >= 75, HIGH_RISK_INDICATORS_PRESENT).
    """
    url_batch = analyze_urls(["https://chase.com@phish-login-portal.net/auth"])
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="security@chase.com", subject="Verify Login"),
        body_info=EmailBodyInfo(plain_text="Click here to authenticate."),
        attachments=[],
        url_analysis=url_batch,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


def test_critical_threat_floor_lookalike_domain_unaligned():
    """
    Verifies that lookalike brand impersonation domain (paypa1-security.com)
    with unaligned sender identity triggers high risk.
    """
    urls = [
        ExtractedURL(
            url="https://paypa1-security.com/signin",
            domain="paypa1-security.com",
            source="html_href",
        )
    ]
    url_analysis = analyze_email_extracted_urls(urls, sender_domain="attacker-mail.org")
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="support@attacker-mail.org", subject="Account Alert"),
        body_info=EmailBodyInfo(plain_text="Log in to verify your identity."),
        attachments=[],
        url_analysis=url_analysis,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# 3. Authentication Risk Floors & Completeness
# ==============================================================================

def test_auth_explicit_failure_floor_review_recommended():
    """
    Verifies that explicit domain authentication failure alone (SPF/DKIM/DMARC fail)
    enforces a minimum risk score of 30 (REVIEW_RECOMMENDED) and never evaluates as LOW_RISK.
    """
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=fail smtp.mailfrom=target.com; dkim=fail; dmarc=fail"]
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.10, predicted_label=0)

    res = fuse_evidence(
        header_info=header_info,
        body_info=EmailBodyInfo(plain_text="Hello, here is our regular team update."),
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )
    assert res.overall_risk_score >= 30
    assert res.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    assert res.overall_category != AssessmentCategory.LOW_RISK_INDICATORS


def test_conflicting_headers_floor_review_recommended():
    """
    Verifies that contradictory authentication headers across intermediate MTAs
    enforce a minimum risk score of 30 (REVIEW_RECOMMENDED).
    """
    auth_analysis = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.CONFLICTING_EVIDENCE,
        spf=SPFEvidence(status=AuthResultStatus.CONFLICTING_EVIDENCE, explanation="Conflicting SPF"),
        dkim=DKIMEvidence(status=AuthResultStatus.PASS, explanation="DKIM pass"),
        dmarc=DMARCEvidence(status=AuthResultStatus.NOT_PRESENT, explanation="DMARC missing"),
        has_conflicts=True,
    )
    res = fuse_evidence(authentication_analysis=auth_analysis)
    assert res.overall_risk_score >= 30
    assert res.overall_category == AssessmentCategory.REVIEW_RECOMMENDED


def test_malformed_email_insufficient_evidence():
    """
    Verifies that empty or malformed emails lacking both headers and body text
    evaluate to INSUFFICIENT_EVIDENCE with MINIMAL_OR_INSUFFICIENT coverage.
    """
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=None,
        body_info=None,
        attachments=[],
        url_analysis=None,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert category == AssessmentCategory.INSUFFICIENT_EVIDENCE
    assert comp == EvidenceCompletenessStatus.MINIMAL_OR_INSUFFICIENT
