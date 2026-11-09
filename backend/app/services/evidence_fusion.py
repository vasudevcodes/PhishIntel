"""
Standalone Evidence Fusion Engine for PhishIntel (Phase 7A).
Synthesizes findings from DistilBERT text classification, URL intelligence,
email authentication (SPF/DKIM/DMARC), and IP transit intelligence.

Transparent, deterministic, explainable.
Preserves uncertainty, avoids double-counting correlated signals, and
strictly refrains from outputting uncalibrated overall probabilities.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.schemas.evidence_fusion import (
    AssessmentCategory,
    AuthEvidenceSummary,
    EvidenceFusionResult,
    IPEvidenceSummary,
    ModelEvidenceInterpretation,
    ModelInferenceEvidence,
    ModelInferenceStatus,
    URLEvidenceSummary,
)
from app.schemas.email_authentication import EmailAuthenticationAnalysis
from app.schemas.ip_intelligence import IPIntelligenceResult
from app.schemas.url_intelligence import URLBatchAnalysisResult


def _extract_url_evidence(
    url_analysis: Optional[URLBatchAnalysisResult],
) -> Tuple[URLEvidenceSummary, List[str], List[str]]:
    """
    Consolidates URL intelligence evidence and collapses duplicates by hostname
    to prevent double-counting multiple links pointing to the same destination.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if not url_analysis or url_analysis.total_urls == 0:
        missing_or_inconclusive.append("No extracted URLs present to evaluate for structural link risks.")
        summary = URLEvidenceSummary(
            total_urls=0,
            unique_domains=0,
            highest_heuristic_risk="NONE",
            suspicious_indicators=[],
            deduplication_applied=False,
            explanation="No URLs were detected in the email body.",
        )
        return summary, contributing, missing_or_inconclusive

    total_urls = url_analysis.total_urls
    unique_domains_set: Set[str] = set()
    indicators_set: Set[str] = set()
    highest_risk = url_analysis.highest_risk_category.value if hasattr(url_analysis.highest_risk_category, "value") else str(url_analysis.highest_risk_category)

    # Track observations by destination hostname to prevent double counting
    for res in url_analysis.url_results:
        host = res.normalized_hostname or res.features.hostname or "unknown-host"
        unique_domains_set.add(host)

        for obs in res.observations:
            if obs.severity.value in ["MEDIUM", "HIGH"]:
                name = getattr(obs, "rule_name", getattr(obs, "title", "Indicator"))
                indicators_set.add(f"{name} ({obs.rule_id})")

    unique_domains = len(unique_domains_set)
    indicators = sorted(list(indicators_set))

    if highest_risk == "HIGH":
        contributing.append(
            f"High-risk URL heuristics detected across {unique_domains} unique destination host(s): "
            + (", ".join(indicators[:3]) if indicators else "Elevated structural risk")
        )
    elif highest_risk == "MEDIUM":
        contributing.append(
            f"Moderate URL heuristic risk detected across {unique_domains} unique destination host(s): "
            + (", ".join(indicators[:2]) if indicators else "Moderate structural indicators")
        )
    else:
        missing_or_inconclusive.append(f"Extracted {total_urls} URL(s) across {unique_domains} domain(s) with negligible heuristic risk.")

    explanation = (
        f"Analyzed {total_urls} URL(s) pointing to {unique_domains} distinct host(s). "
        f"Highest heuristic risk: {highest_risk}. Deduplication applied across repeated link occurrences."
    )

    summary = URLEvidenceSummary(
        total_urls=total_urls,
        unique_domains=unique_domains,
        highest_heuristic_risk=highest_risk,
        suspicious_indicators=indicators,
        deduplication_applied=True,
        explanation=explanation,
    )
    return summary, contributing, missing_or_inconclusive


def _extract_auth_evidence(
    auth_analysis: Optional[EmailAuthenticationAnalysis],
) -> Tuple[AuthEvidenceSummary, List[str], List[str]]:
    """
    Consolidates email authentication evidence (SPF, DKIM, DMARC),
    handling correlated failures (e.g. SPF failure causing downstream DMARC failure),
    and distinguishing reported assertions from independently established evidence.

    Stage A.2: has_valid_authentication now reflects provenance_status.
    For offline .eml uploads, all authentication is REPORTED — even SPF/DKIM/DMARC PASS
    cannot be considered independently verified evidence. has_valid_authentication
    represents "all protocols passed AND provenance is independently established",
    which is never True for offline uploads.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if not auth_analysis or auth_analysis.status.value == "NO_EVIDENCE":
        missing_or_inconclusive.append("No SPF, DKIM, or DMARC authentication headers were recorded by receiving MTAs.")
        summary = AuthEvidenceSummary(
            spf_status="NOT_PRESENT",
            dkim_status="NOT_PRESENT",
            dmarc_status="NOT_PRESENT",
            has_conflicts=False,
            has_valid_authentication=False,
            has_explicit_failure=False,
            correlated_failure_noted=False,
            boundary_authserv_trust="MISSING",
            is_boundary_trusted=False,
            explanation="No authentication results were available in the message headers.",
        )
        return summary, contributing, missing_or_inconclusive

    spf_st = auth_analysis.spf.status.value if hasattr(auth_analysis.spf.status, "value") else str(auth_analysis.spf.status)
    dkim_st = auth_analysis.dkim.status.value if hasattr(auth_analysis.dkim.status, "value") else str(auth_analysis.dkim.status)
    dmarc_st = auth_analysis.dmarc.status.value if hasattr(auth_analysis.dmarc.status, "value") else str(auth_analysis.dmarc.status)
    has_conflicts = auth_analysis.has_conflicts
    is_boundary_trusted = getattr(auth_analysis, "is_boundary_trusted", False)
    boundary_authserv = getattr(auth_analysis, "boundary_authserv_id", None)
    boundary_trust = getattr(auth_analysis, "boundary_authserv_trust", "UNTRUSTED")
    boundary_trust_str = boundary_trust.value if hasattr(boundary_trust, "value") else str(boundary_trust)

    # Stage A.2: Read provenance_status to distinguish reported vs verified authentication.
    provenance_status = getattr(auth_analysis, "provenance_status", None)
    provenance_str = provenance_status.value if hasattr(provenance_status, "value") else str(provenance_status) if provenance_status else "REPORTED_AUTHENTICATION"

    has_pass = any(s == "PASS" for s in [spf_st, dkim_st, dmarc_st])
    has_fail = any(s == "FAIL" for s in [spf_st, dkim_st, dmarc_st])

    # Correlate failures: In RFC 7489, DMARC failure often directly results from SPF/DKIM failure
    correlated_failure = False
    if dmarc_st == "FAIL" and (spf_st == "FAIL" or dkim_st in ["FAIL", "NOT_PRESENT"]):
        correlated_failure = True

    all_auth_findings = (
        auth_analysis.spf.findings
        + auth_analysis.dkim.findings
        + auth_analysis.dmarc.findings
    )
    has_any_pass_finding = any(
        (f.result.value if hasattr(f.result, "value") else str(f.result)) == "PASS"
        for f in all_auth_findings
    )

    # Stage A.2: has_valid_authentication = True only when provenance is independently established.
    # For offline .eml uploads provenance_status is REPORTED_AUTHENTICATION or weaker,
    # so has_valid_authentication is always False in that context.
    # This prevents the evidence fusion engine from treating reported PASS as a trust signal.
    if provenance_str == "TRUSTED_RECEIVER_EVIDENCE" and has_pass and is_boundary_trusted:
        has_valid_auth = True
    else:
        has_valid_auth = False

    if has_any_pass_finding and not has_valid_auth:
        if boundary_trust_str in ("UNTRUSTED", "SUSPICIOUS"):
            contributing.append(
                f"Authentication results were recorded by an untrusted or unrecognized authserv-id ('{boundary_authserv}')."
            )
        elif boundary_trust_str == "REPORTED":
            # Stage A.2: authserv-id matched a known gateway name but provenance is unverified.
            contributing.append(
                f"Authentication results claim '{boundary_authserv}' as the recording MTA, but this is an offline .eml upload — "
                "the authserv-id string cannot be independently verified as genuine. "
                "Authentication assertions are REPORTED (unverified provenance)."
            )
        else:
            contributing.append(
                "Authentication results were recorded only on upstream or untrusted hops, not at the recipient boundary MTA."
            )

    if has_conflicts:
        contributing.append("Contradictory authentication evidence detected across multiple intermediate receiving MTAs.")
    elif has_fail:
        if correlated_failure:
            contributing.append(f"Explicit authentication failure observed: SPF={spf_st}, DKIM={dkim_st}, with correlated downstream DMARC={dmarc_st}.")
        else:
            contributing.append(f"Explicit authentication failure observed: SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}.")
    elif has_pass and not has_fail:
        authserv_info = f" via reported MTA ({boundary_authserv})" if boundary_authserv else ""
        missing_or_inconclusive.append(
            f"Receiver-reported domain authentication passed (SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}){authserv_info}. "
            f"Provenance: {provenance_str}. "
            "Note: Reported authentication reflects MTA header assertions (RFC 8601) — "
            "these cannot be independently verified in an offline context and do not guarantee benign intent."
        )

    if any(s in ["SOFTFAIL", "NEUTRAL"] for s in [spf_st, dkim_st]):
        contributing.append(f"Ambiguous or permissive SPF policy outcome observed (SPF={spf_st}).")

    explanation = (
        f"Authentication evaluation: SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}. "
        f"Provenance: {provenance_str}. "
        f"Conflicting headers: {has_conflicts}. Correlated failures accounted for: {correlated_failure}. "
        f"Boundary MTA trusted: {is_boundary_trusted} ({boundary_trust_str})."
    )

    summary = AuthEvidenceSummary(
        spf_status=spf_st,
        dkim_status=dkim_st,
        dmarc_status=dmarc_st,
        has_conflicts=has_conflicts,
        has_valid_authentication=has_valid_auth,
        has_explicit_failure=has_fail,
        correlated_failure_noted=correlated_failure,
        boundary_authserv_trust=boundary_trust_str,
        is_boundary_trusted=is_boundary_trusted,
        explanation=explanation,
    )
    return summary, contributing, missing_or_inconclusive


def _extract_ip_evidence(
    ip_analysis: Optional[IPIntelligenceResult],
) -> Tuple[IPEvidenceSummary, List[str], List[str]]:
    """
    Consolidates IP intelligence transit findings and provenance.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if not ip_analysis or ip_analysis.total_candidates == 0:
        missing_or_inconclusive.append("No candidate IP addresses were available from Received headers.")
        summary = IPEvidenceSummary(
            apparent_origin_ip=None,
            origin_classification="Unavailable",
            is_routable=False,
            hop_count=0,
            explanation="No Received headers containing IP addresses were detected.",
        )
        return summary, contributing, missing_or_inconclusive

    origin = ip_analysis.origin_candidate
    origin_ip = origin.ip if origin else None
    origin_cls = origin.classification.value if origin and hasattr(origin.classification, "value") else (origin.classification if origin else "Unavailable")
    is_routable = origin.is_routable if origin else False
    hop_count = ip_analysis.total_candidates

    if origin:
        if is_routable:
            missing_or_inconclusive.append(f"Apparent origin relay is a globally routable public IP ({origin_ip}).")
        else:
            missing_or_inconclusive.append(f"Apparent origin relay is classified as non-routable {origin_cls} ({origin_ip}).")

    explanation = f"Analyzed {hop_count} transit hop candidate(s). Apparent origin: {origin_ip or 'None'} ({origin_cls})."

    summary = IPEvidenceSummary(
        apparent_origin_ip=origin_ip,
        origin_classification=origin_cls,
        is_routable=is_routable,
        hop_count=hop_count,
        explanation=explanation,
    )
    return summary, contributing, missing_or_inconclusive


def _extract_model_evidence(
    model_inference: Optional[Union[ModelInferenceEvidence, Dict[str, Any]]],
) -> Tuple[ModelEvidenceInterpretation, List[str], List[str]]:
    """
    Interprets DistilBERT model inference output with explicit calibration caveats.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if model_inference is None:
        missing_or_inconclusive.append("DistilBERT Transformer NLP model inference was not executed for this request.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.UNAVAILABLE,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation="Model inference was not supplied or executed.",
        )
        return interpretation, contributing, missing_or_inconclusive

    score = getattr(model_inference, "uncalibrated_score", None)
    label = getattr(model_inference, "predicted_label", None)
    status_override = getattr(model_inference, "status", None)
    error_msg = getattr(model_inference, "error_message", None)
    if isinstance(model_inference, dict):
        score = model_inference.get("uncalibrated_score")
        label = model_inference.get("predicted_label")
        status_override = model_inference.get("status")
        error_msg = model_inference.get("error_message")

    if status_override == ModelInferenceStatus.ERROR or (status_override and str(status_override).upper() == "ERROR"):
        missing_or_inconclusive.append(f"DistilBERT model inference encountered an error: {error_msg or 'Execution failed'}.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.ERROR,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation=f"Model inference failed: {error_msg or 'Execution error'}.",
        )
        return interpretation, contributing, missing_or_inconclusive

    if status_override == ModelInferenceStatus.UNAVAILABLE or (status_override and str(status_override).upper() == "UNAVAILABLE"):
        missing_or_inconclusive.append(f"DistilBERT model inference was unavailable: {error_msg or 'Checkpoint not found'}.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.UNAVAILABLE,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation=f"Model inference unavailable: {error_msg or 'Checkpoint not found'}.",
        )
        return interpretation, contributing, missing_or_inconclusive

    if score is None:
        missing_or_inconclusive.append("DistilBERT model output score is missing or null.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.UNAVAILABLE,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation="Model inference output incomplete.",
        )
        return interpretation, contributing, missing_or_inconclusive

    if score >= 0.7:
        contributing.append(f"DistilBERT model indicated elevated textual similarity to phishing lures (uncalibrated score: {score:.3f}).")
        text_interp = f"Model predicts phishing (label {label}) with uncalibrated phishing score {score:.3f}."
    elif score >= 0.4:
        contributing.append(f"DistilBERT model indicated borderline/indeterminate semantic evidence (uncalibrated score: {score:.3f}).")
        text_interp = f"Model indicates borderline text classification (uncalibrated score {score:.3f})."
    else:
        missing_or_inconclusive.append(f"DistilBERT model indicated low textual similarity to phishing lures (uncalibrated score: {score:.3f}).")
        text_interp = f"Model predicts benign text (label {label}) with low phishing similarity ({score:.3f})."

    interpretation = ModelEvidenceInterpretation(
        status=ModelInferenceStatus.EVALUATED,
        uncalibrated_score=score,
        predicted_label=label,
        interpretation=text_interp,
    )
    return interpretation, contributing, missing_or_inconclusive


def _format_forensic_explanation(
    category: AssessmentCategory,
    primary_rationale: str,
    model_summary: ModelEvidenceInterpretation,
    url_summary: URLEvidenceSummary,
    auth_summary: AuthEvidenceSummary,
) -> str:
    """
    Constructs a dynamic, fully evidence-grounded forensic explanation for the assessment.
    Guarantees no invented findings and no hardcoded false conflict statements.
    """
    parts: List[str] = [primary_rationale]

    # Model evidence component
    if model_summary.status == ModelInferenceStatus.EVALUATED and model_summary.uncalibrated_score is not None:
        parts.append(
            f"Model evidence: DistilBERT NLP uncalibrated phishing score {model_summary.uncalibrated_score:.3f} "
            f"(predicted label {model_summary.predicted_label})."
        )
    elif model_summary.status == ModelInferenceStatus.ERROR:
        parts.append("Model evidence: DistilBERT inference encountered an execution error.")
    else:
        parts.append("Model evidence: DistilBERT inference was unavailable or not evaluated.")

    # URL evidence component
    if url_summary.total_urls > 0:
        if url_summary.suspicious_indicators:
            indicators_str = ", ".join(url_summary.suspicious_indicators[:3])
            parts.append(
                f"URL evidence: {url_summary.total_urls} link(s) across {url_summary.unique_domains} domain(s) "
                f"with highest heuristic risk '{url_summary.highest_heuristic_risk}' (indicators: {indicators_str})."
            )
        else:
            parts.append(
                f"URL evidence: {url_summary.total_urls} link(s) across {url_summary.unique_domains} domain(s) "
                f"with negligible structural risk ('{url_summary.highest_heuristic_risk}')."
            )
    else:
        parts.append("URL evidence: No links detected in message body.")

    # Authentication evidence component
    if auth_summary.has_explicit_failure:
        parts.append(
            f"Authentication evidence: Explicit failure recorded (SPF={auth_summary.spf_status}, "
            f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
        )
    elif auth_summary.has_conflicts:
        parts.append(
            f"Authentication evidence: Conflicting authentication assertions recorded across intermediate MTAs "
            f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
        )
    elif auth_summary.has_valid_authentication:
        if auth_summary.is_boundary_trusted:
            parts.append(
                f"Authentication evidence: Receiver-reported domain authentication passed at boundary MTA "
                f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
            )
        else:
            parts.append(
                f"Authentication evidence: Domain authentication pass assertions exist only on upstream hops "
                f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}), not verified by boundary MTA."
            )
    else:
        parts.append("Authentication evidence: No authentication results present in email headers.")

    return " ".join(parts)


def fuse_evidence(
    url_analysis: Optional[URLBatchAnalysisResult] = None,
    authentication_analysis: Optional[EmailAuthenticationAnalysis] = None,
    ip_intelligence: Optional[IPIntelligenceResult] = None,
    model_inference: Optional[Union[ModelInferenceEvidence, Dict[str, Any]]] = None,
) -> EvidenceFusionResult:
    """
    Main entry point for Evidence Fusion Engine (Phase 7A).
    Synthesizes multi-modal observations into a transparent forensic assessment.
    """
    all_contributing: List[str] = []
    all_missing: List[str] = []

    # 1. Extract component evidence
    url_summary, url_contrib, url_missing = _extract_url_evidence(url_analysis)
    auth_summary, auth_contrib, auth_missing = _extract_auth_evidence(authentication_analysis)
    ip_summary, ip_contrib, ip_missing = _extract_ip_evidence(ip_intelligence)
    model_summary, model_contrib, model_missing = _extract_model_evidence(model_inference)

    all_contributing.extend(url_contrib)
    all_contributing.extend(auth_contrib)
    all_contributing.extend(ip_contrib)
    all_contributing.extend(model_contrib)

    all_missing.extend(url_missing)
    all_missing.extend(auth_missing)
    all_missing.extend(ip_missing)
    all_missing.extend(model_missing)

    # 2. Determine Overall Assessment Category
    has_high_url = (url_summary.highest_heuristic_risk == "HIGH")
    has_med_url = (url_summary.highest_heuristic_risk == "MEDIUM")
    has_auth_fail = auth_summary.has_explicit_failure
    has_auth_conflict = auth_summary.has_conflicts
    is_boundary_trusted = auth_summary.is_boundary_trusted
    has_trusted_auth_pass = (
        auth_summary.has_valid_authentication
        and is_boundary_trusted
        and not has_auth_fail
        and not has_auth_conflict
    )

    model_score = model_summary.uncalibrated_score
    has_high_model = (model_score is not None and model_score >= 0.7)
    has_med_model = (model_score is not None and 0.4 <= model_score < 0.7)
    has_low_model = (model_score is not None and model_score < 0.3)
    has_model_error = (model_summary.status == ModelInferenceStatus.ERROR)

    # Condition 1: Severe structural URL deception
    # Strong independent phishing indicators cannot be automatically overridden by domain authentication.
    if has_high_url and (has_auth_fail or has_high_model or len(url_summary.suspicious_indicators) >= 2):
        category = AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
        rationale = (
            "High-risk indicators are present based on corroborated severe evidence: high-risk structural URL deception "
            f"({', '.join(url_summary.suspicious_indicators[:2]) if url_summary.suspicious_indicators else 'severe link deception'}) "
            "coinciding with explicit authentication failure or elevated text model similarity."
        )
    elif has_high_url:
        category = AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
        rationale = (
            "High-risk indicators are present based on severe structural URL heuristics (e.g. IP-literal host, "
            "embedded credentials in authority, or dangerous scheme), even in the absence of corroborated text or auth signals."
        )

    # Condition 2: Explicit authentication failure corroborated by independent evidence
    elif has_auth_fail and (has_med_url or has_high_model):
        category = AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
        corrob = []
        if has_med_url:
            corrob.append(f"moderate URL anomalies ({', '.join(url_summary.suspicious_indicators[:2])})")
        if has_high_model:
            corrob.append(f"elevated text model similarity ({model_score:.3f})")
        rationale = (
            "High-risk indicators are present due to explicit domain authentication failure "
            f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}) "
            f"corroborated by independent evidence: {' and '.join(corrob)}."
        )

    # Condition 3: Elevated text model score corroborated by moderate URL anomalies on UNVERIFIED or UNTRUSTED email
    elif has_high_model and has_med_url and not has_trusted_auth_pass:
        category = AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
        rationale = (
            "High-risk indicators are present based on multiple unmitigated independent signals: "
            f"elevated text model similarity ({model_score:.3f}) corroborated by moderate URL anomalies "
            f"({', '.join(url_summary.suspicious_indicators[:2]) if url_summary.suspicious_indicators else 'suspicious URLs'}) "
            "on an email lacking verified boundary domain authentication."
        )

    # Condition 4: Authenticated email with elevated model score or moderate URL anomalies -> REVIEW_RECOMMENDED
    elif has_trusted_auth_pass and (has_high_model or has_med_url):
        category = AssessmentCategory.REVIEW_RECOMMENDED
        if has_high_model and has_med_url:
            rationale = (
                f"Review recommended: DistilBERT text model flagged elevated phishing similarity ({model_score:.3f}) "
                f"and URL analysis flagged moderate structural indicators ({', '.join(url_summary.suspicious_indicators[:2])}), "
                f"despite domain authentication passing at recipient boundary MTA (SPF={auth_summary.spf_status}, "
                f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}). Because model score is uncalibrated "
                "and authentication does not prove body content safety, manual analyst review is recommended."
            )
        elif has_high_model:
            rationale = (
                f"Review recommended: DistilBERT text model flagged elevated phishing similarity ({model_score:.3f}), "
                f"but receiver-reported domain authentication passed at boundary MTA (SPF={auth_summary.spf_status}, "
                f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}) without corroborating structural URL deception. "
                "Because model score is uncalibrated, analyst review is recommended."
            )
        else:
            rationale = (
                "Review recommended: Domain authentication passed at recipient boundary MTA "
                f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}), "
                f"but moderate structural URL anomalies ({', '.join(url_summary.suspicious_indicators[:2])}) were observed. "
                "Manual analyst review is recommended."
            )

    # Condition 5: Isolated high model score without independent corroboration
    elif has_high_model and not has_high_url and not has_auth_fail:
        category = AssessmentCategory.REVIEW_RECOMMENDED
        rationale = (
            "Review recommended: DistilBERT text model flagged elevated phishing similarity, "
            "but no corroborating structural URL or authentication failure evidence was observed. "
            "Because model score is uncalibrated, analyst review is recommended."
        )

    # Condition 6: Moderate URL anomalies, isolated auth failure, auth conflicts, borderline model, or model errors
    elif has_med_url or has_auth_conflict or has_auth_fail or has_med_model or has_model_error or (not is_boundary_trusted and auth_summary.has_valid_authentication):
        category = AssessmentCategory.REVIEW_RECOMMENDED
        factors = []
        if has_med_url:
            factors.append(f"moderate URL anomalies ({', '.join(url_summary.suspicious_indicators[:2])})")
        if has_auth_conflict:
            factors.append("contradictory authentication results across intermediate headers")
        if has_auth_fail:
            factors.append(f"isolated authentication failure (SPF={auth_summary.spf_status}, DMARC={auth_summary.dmarc_status}) without corroborating URL/text risk")
        if not is_boundary_trusted and auth_summary.has_valid_authentication:
            factors.append("authentication pass assertions recorded only on untrusted upstream hops")
        if has_med_model:
            factors.append(f"borderline text model score ({model_score:.3f})")
        if has_model_error:
            factors.append("text model inference error")
        rationale = (
            f"Review recommended due to anomalous or indeterminate forensic indicators requiring manual inspection: {'; '.join(factors)}."
        )

    # Condition 7: Low risk indicators (Verified boundary auth, clean/low-risk URLs, low or neutral model score)
    elif has_trusted_auth_pass and (url_summary.highest_heuristic_risk in ["INFO", "NONE", "LOW"]) and (has_low_model or (model_score is None and not has_model_error)):
        category = AssessmentCategory.LOW_RISK_INDICATORS
        rationale = (
            "Low risk indicators observed: domain authentication passed at the recipient boundary MTA "
            f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}) "
            "with negligible structural URL anomalies and low textual phishing similarity."
        )

    # Condition 8: Insufficient evidence in all other cases
    else:
        category = AssessmentCategory.INSUFFICIENT_EVIDENCE
        rationale = (
            "Insufficient evidence available to assign an elevated risk category. "
            "Key forensic indicators (such as URLs, authentication headers, or public transit IPs) were absent or neutral."
        )

    reasoning = _format_forensic_explanation(
        category=category,
        primary_rationale=rationale,
        model_summary=model_summary,
        url_summary=url_summary,
        auth_summary=auth_summary,
    )

    return EvidenceFusionResult(
        overall_category=category,
        model_evidence=model_summary,
        url_evidence=url_summary,
        auth_evidence=auth_summary,
        ip_evidence=ip_summary,
        contributing_factors=all_contributing,
        inconclusive_or_missing_factors=all_missing,
        reasoning=reasoning,
    )
