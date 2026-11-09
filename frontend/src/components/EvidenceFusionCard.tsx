import type { FC } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  HelpCircle,
  Cpu,
  Globe,
  Lock,
  Network,
  Info,
  CheckCircle2,
  ArrowRight,
} from 'lucide-react';
import type {
  EvidenceFusionResult,
  AssessmentCategory,
  ModelInferenceStatus,
} from '../types/forensics';

interface EvidenceFusionCardProps {
  fusion?: EvidenceFusionResult | null;
}

export const EvidenceFusionCard: FC<EvidenceFusionCardProps> = ({ fusion }) => {
  if (!fusion) {
    return (
      <div className="rounded-2xl border border-surface-border bg-white p-6 shadow-card">
        <div className="flex items-center space-x-2 text-slate-500">
          <HelpCircle className="w-5 h-5" />
          <h3 className="text-base font-semibold text-navy-900 tracking-tight">
            Multi-Modal Evidence Fusion Assessment
          </h3>
        </div>
        <p className="mt-3 text-xs font-mono text-slate-500">
          Evidence fusion assessment data is not available for this email analysis.
        </p>
      </div>
    );
  }

  const getCategoryConfig = (category: AssessmentCategory) => {
    switch (category) {
      case 'HIGH_RISK_INDICATORS_PRESENT':
        return {
          title: 'High Risk Indicators Present',
          badgeClass: 'bg-red-50 text-red-700 border-red-200',
          icon: <ShieldAlert className="w-6 h-6 text-red-600 flex-shrink-0" />,
          cardBorder: 'border-red-200',
          bgHeader: 'bg-red-50/50',
          subtitle: 'Explicit structural, authentication, or model risk indicators were identified.',
          actionText: 'Quarantine message immediately. Investigate origin relay and block reported destination URLs.',
        };
      case 'REVIEW_RECOMMENDED':
        return {
          title: 'Review Recommended',
          badgeClass: 'bg-amber-50 text-amber-800 border-amber-200',
          icon: <AlertTriangle className="w-6 h-6 text-amber-600 flex-shrink-0" />,
          cardBorder: 'border-amber-200',
          bgHeader: 'bg-amber-50/50',
          subtitle: 'Elevated or ambiguous indicators require manual forensic analyst inspection.',
          actionText: 'Inspect message headers and candidate IP provenance. Do not engage with embedded hyperlinks.',
        };
      case 'LOW_RISK_INDICATORS':
        return {
          title: 'Low Risk Indicators Observed',
          badgeClass: 'bg-emerald-50 text-emerald-800 border-emerald-200',
          icon: <CheckCircle2 className="w-6 h-6 text-emerald-600 flex-shrink-0" />,
          cardBorder: 'border-emerald-200',
          bgHeader: 'bg-emerald-50/50',
          subtitle: 'No prominent structural risk flags observed. (Note: does NOT guarantee safety).',
          actionText: 'Routine delivery permissible. Continue adhering to standard organizational security awareness.',
        };
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return {
          title: 'Insufficient Evidence',
          badgeClass: 'bg-slate-100 text-slate-700 border-slate-200',
          icon: <HelpCircle className="w-6 h-6 text-slate-500 flex-shrink-0" />,
          cardBorder: 'border-surface-border',
          bgHeader: 'bg-slate-50',
          subtitle: 'Key evidence components were missing, unverified, or indeterminate.',
          actionText: 'Gather original raw transit headers or resubmit complete RFC 5322 payload.',
        };
    }
  };

  const catConfig = getCategoryConfig(fusion.overall_category);
  const model = fusion.model_evidence;

  // Compute reassuring factors cleanly at component level
  const reassuringFactors: string[] = [];
  if (fusion.auth_evidence.has_valid_authentication && !fusion.auth_evidence.has_explicit_failure) {
    const passed = [
      fusion.auth_evidence.spf_status === 'PASS' ? 'SPF' : null,
      fusion.auth_evidence.dkim_status === 'PASS' ? 'DKIM' : null,
      fusion.auth_evidence.dmarc_status === 'PASS' ? 'DMARC' : null,
    ].filter(Boolean).join(', ');
    reassuringFactors.push(`Reported cryptographic authentication passed (${passed || 'Valid'})`);
  }
  if (model.status === 'EVALUATED' && model.predicted_label === 0) {
    reassuringFactors.push('DistilBERT model observed benign language patterns');
  }
  if (fusion.url_evidence.total_urls > 0 && (fusion.url_evidence.highest_heuristic_risk === 'LOW' || fusion.url_evidence.highest_heuristic_risk === 'INFO')) {
    reassuringFactors.push('All extracted URLs are within low structural risk thresholds');
  }
  if (fusion.url_evidence.total_urls === 0) {
    reassuringFactors.push('Zero external URLs embedded in message body');
  }

  const renderModelStatusBadge = (status: ModelInferenceStatus) => {
    switch (status) {
      case 'EVALUATED':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            EVALUATED
          </span>
        );
      case 'ERROR':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
            ERROR (Unavailable)
          </span>
        );
      case 'UNAVAILABLE':
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            UNAVAILABLE
          </span>
        );
    }
  };

  return (
    <div className={`rounded-2xl border ${catConfig.cardBorder} bg-white shadow-card overflow-hidden`}>
      {/* Assessment Header Banner */}
      <div className={`p-5 sm:p-6 ${catConfig.bgHeader} border-b border-surface-border`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-xl bg-white border border-surface-border flex items-center justify-center shadow-subtle">
              {catConfig.icon}
            </div>
            <div>
              <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold">
                  Evidence Fusion Synthesis
                </span>
                <span
                  className={`px-3 py-0.5 rounded-full text-xs font-bold border ${catConfig.badgeClass}`}
                >
                  {catConfig.title}
                </span>
              </div>
              <p className="text-xs sm:text-sm text-navy-900 mt-1 leading-relaxed">
                {catConfig.subtitle}
              </p>
            </div>
          </div>

          <div className="text-left md:text-right text-xs">
            <span className="block text-[11px] font-medium text-slate-500 uppercase tracking-wider">
              Assessment Code
            </span>
            <span className="font-mono font-semibold text-navy-900">{fusion.overall_category}</span>
          </div>
        </div>

        {/* Recommended Action Pill */}
        <div className="mt-4 pt-3.5 border-t border-slate-200/60 flex items-start sm:items-center space-x-2 text-xs">
          <span className="font-semibold text-navy-900 flex-shrink-0 flex items-center gap-1">
            <span>Recommended Action:</span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
          </span>
          <span className="text-slate-700">{catConfig.actionText}</span>
        </div>
      </div>

      <div className="p-5 sm:p-6 space-y-6">
        {/* Synthesized Forensic Reasoning */}
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
            Forensic Reasoning &amp; Context
          </h4>
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border text-xs sm:text-sm text-navy-900 leading-relaxed font-sans">
            {fusion.reasoning}
          </div>
        </div>

        {/* DistilBERT Model Evidence Section */}
        <div className="rounded-xl border border-surface-border bg-white p-5 shadow-subtle">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3.5 border-b border-surface-border">
            <div className="flex items-center space-x-2 text-navy-900">
              <Cpu className="w-4 h-4 text-brand-600" />
              <h4 className="text-sm font-semibold tracking-tight">
                DistilBERT Transformer Text Inference
              </h4>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs text-slate-500">Inference Status:</span>
              {renderModelStatusBadge(model.status)}
            </div>
          </div>

          {model.status === 'EVALUATED' ? (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border">
                  <div className="text-slate-500 text-[11px] font-medium uppercase tracking-wider">
                    Classification Output
                  </div>
                  <div className="text-base font-bold mt-1">
                    {model.predicted_label === 1 ? (
                      <span className="text-red-700 flex items-center gap-1.5">
                        <AlertCircle className="w-4 h-4 text-red-600" />
                        1 (Phishing Indicator)
                      </span>
                    ) : (
                      <span className="text-emerald-700 flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        0 (Benign / Non-Phishing Pattern)
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1 font-mono">
                    Binary decision threshold: 0.5000
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border">
                  <div className="text-slate-500 text-[11px] font-medium uppercase tracking-wider">
                    Model Confidence Indicator
                  </div>
                  <div className="text-base font-bold font-mono text-navy-900 mt-1">
                    {model.uncalibrated_score !== null
                      ? model.uncalibrated_score.toFixed(4)
                      : 'N/A'}
                  </div>
                  <div className="text-[11px] text-amber-700 mt-1">
                    * Raw heuristic model score (not a calibrated real-world probability)
                  </div>
                </div>
              </div>

              <div className="text-xs text-slate-700 leading-relaxed">
                <strong className="text-navy-900">Interpretation: </strong>
                {model.interpretation}
              </div>

              {/* Calibration Caveat Banner */}
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start space-x-2.5">
                <Info className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-amber-800">Model Limitation &amp; Caveat: </span>
                  <span className="text-amber-800 leading-relaxed">{model.caveat}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-4 p-4 rounded-xl bg-amber-50 border border-amber-200 text-xs space-y-2">
              <div className="flex items-center space-x-2 text-amber-800 font-semibold">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                <span>
                  Model Inference {model.status === 'ERROR' ? 'Failed with Error' : 'Unavailable'}
                </span>
              </div>
              <p className="text-amber-800 leading-relaxed">
                {model.interpretation ||
                  'The DistilBERT model was not executed or encountered an inference fault. The system does not fall back to a default benign assumption.'}
              </p>
              <div className="p-2 rounded bg-white border border-amber-200 font-mono text-slate-600 text-[11px]">
                Predicted Label: <span className="text-red-700 font-semibold">N/A ({model.status})</span> | Model Score:{' '}
                <span className="text-red-700 font-semibold">N/A</span>
              </div>
            </div>
          )}
        </div>

        {/* Key Findings: Suspicious, Reassuring & Inconclusive Groups */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Key Findings &amp; Forensic Indicators
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* 1. Suspicious / Contributing Factors */}
            <div className="rounded-xl border border-red-200 bg-red-50/20 p-4">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-red-800 mb-2.5 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
                <span>Suspicious Indicators ({fusion.contributing_factors.length})</span>
              </h5>
              {fusion.contributing_factors.length === 0 ? (
                <p className="text-xs text-slate-500 italic">
                  No explicit suspicious factors flagged.
                </p>
              ) : (
                <ul className="space-y-2 text-xs text-navy-900">
                  {fusion.contributing_factors.map((factor, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-red-500 font-bold mt-0.5">•</span>
                      <span className="leading-relaxed">{factor}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* 2. Reassuring Indicators */}
            <div className="rounded-xl border border-emerald-200 bg-emerald-50/20 p-4">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-emerald-800 mb-2.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
                <span>Reassuring Indicators</span>
              </h5>
              {reassuringFactors.length === 0 ? (
                <p className="text-xs text-slate-500 italic">
                  No positive authentication or benign signals observed.
                </p>
              ) : (
                <ul className="space-y-2 text-xs text-navy-900">
                  {reassuringFactors.map((r, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-emerald-500 font-bold mt-0.5">•</span>
                      <span className="leading-relaxed">{r}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* 3. Inconclusive or Missing Factors */}
            <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-4">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-2.5 flex items-center gap-1.5">
                <HelpCircle className="w-4 h-4 text-slate-500 flex-shrink-0" />
                <span>Inconclusive Signals ({fusion.inconclusive_or_missing_factors.length})</span>
              </h5>
              {fusion.inconclusive_or_missing_factors.length === 0 ? (
                <p className="text-xs text-slate-500 italic">
                  All expected forensic signals were present and evaluable.
                </p>
              ) : (
                <ul className="space-y-2 text-xs text-slate-700">
                  {fusion.inconclusive_or_missing_factors.map((factor, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-slate-400 font-bold mt-0.5">•</span>
                      <span className="leading-relaxed">{factor}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Modality Summaries Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {/* URL Intelligence Summary */}
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-2 shadow-subtle">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-blue-700 font-semibold">
                <Globe className="w-4 h-4" />
                <span>URL Intelligence</span>
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  fusion.url_evidence.highest_heuristic_risk === 'HIGH'
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : fusion.url_evidence.highest_heuristic_risk === 'MEDIUM'
                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                    : 'bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {fusion.url_evidence.highest_heuristic_risk} RISK
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              {fusion.url_evidence.explanation}
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1.5 border-t border-slate-200">
              URLs: {fusion.url_evidence.total_urls} | Domains: {fusion.url_evidence.unique_domains}
            </div>
          </div>

          {/* Authentication Summary */}
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-2 shadow-subtle">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-brand-700 font-semibold">
                <Lock className="w-4 h-4" />
                <span>Authentication</span>
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  fusion.auth_evidence.has_explicit_failure
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : fusion.auth_evidence.has_valid_authentication
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {fusion.auth_evidence.has_explicit_failure
                  ? 'FAIL DETECTED'
                  : fusion.auth_evidence.has_valid_authentication
                  ? 'VALID AUTH'
                  : 'INDETERMINATE'}
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              {fusion.auth_evidence.explanation}
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1.5 border-t border-slate-200 flex justify-between">
              <span>SPF: {fusion.auth_evidence.spf_status}</span>
              <span>DKIM: {fusion.auth_evidence.dkim_status}</span>
              <span>DMARC: {fusion.auth_evidence.dmarc_status}</span>
            </div>
          </div>

          {/* IP Transit Summary */}
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-2 shadow-subtle">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-purple-700 font-semibold">
                <Network className="w-4 h-4" />
                <span>IP Transit</span>
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200 font-mono">
                {fusion.ip_evidence.hop_count} HOPS
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              {fusion.ip_evidence.explanation}
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1.5 border-t border-slate-200 truncate">
              Origin: {fusion.ip_evidence.apparent_origin_ip || '(Undetermined)'} (
              {fusion.ip_evidence.origin_classification})
            </div>
          </div>
        </div>

        {/* Mandatory Research / Analyst Disclaimer */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
          <div className="flex items-center space-x-1.5 text-navy-900 font-semibold">
            <Info className="w-4 h-4 text-brand-600 flex-shrink-0" />
            <span>Forensic Synthesis Disclaimer</span>
          </div>
          <p className="leading-relaxed">
            {fusion.disclaimer}
          </p>
        </div>
      </div>
    </div>
  );
};
