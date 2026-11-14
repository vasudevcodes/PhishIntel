import { useState } from 'react';
import {
  Shield,
  Globe,
  Paperclip,
  AlignLeft,
  Mail,
  Network,
  Layers,
  Lock,
  Cpu,
  ShieldCheck,
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { UploadZone } from './components/UploadZone';
import { EmailOverviewBanner } from './components/EmailOverviewBanner';
import { EvidenceFusionCard } from './components/EvidenceFusionCard';
import { AuthenticationCard } from './components/AuthenticationCard';
import { HeaderForensics } from './components/HeaderForensics';
import { IPCandidatesCard } from './components/IPCandidatesCard';
import { ExtractedURLsCard } from './components/ExtractedURLsCard';
import { AttachmentForensicsCard } from './components/AttachmentForensicsCard';
import { BodyForensicsCard } from './components/BodyForensicsCard';
import type { EmailAnalysisResponse } from './types/forensics';

export function App() {
  const [analysisData, setAnalysisData] = useState<EmailAnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    'all' | 'fusion' | 'auth' | 'headers' | 'ips' | 'urls' | 'attachments' | 'body'
  >('all');

  const handleReset = () => {
    setAnalysisData(null);
    setErrorMessage(null);
    setActiveTab('all');
  };

  return (
    <div className="min-h-screen bg-surface-bg text-navy-900 flex flex-col font-sans">
      <Navbar onBrandClick={analysisData ? handleReset : undefined} />

      <main className="flex-1 py-8 sm:py-10">
        {!analysisData ? (
          <div className="max-w-5xl mx-auto px-4 sm:px-6">
            {/* Hero Section */}
            <div className="text-center space-y-4 mb-8 sm:mb-10">
              <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-brand-50 border border-brand-200 text-brand-800 text-xs font-medium shadow-subtle">
                <Shield className="w-3.5 h-3.5 text-brand-600" />
                <span>Transformer &amp; NLP-Based Email Phishing Detection and IP Intelligence</span>
              </div>

              <h1 className="text-4xl sm:text-5xl font-extrabold text-navy-900 tracking-tight leading-tight">
                Understand. Investigate. Detect.
              </h1>

              <p className="text-sm sm:text-base text-slate-600 max-w-2xl mx-auto leading-relaxed">
                A professional digital forensics platform for email investigation. Ingest RFC 5322{' '}
                <code className="text-navy-900 font-semibold font-mono text-xs px-1.5 py-0.5 rounded bg-slate-200/70">.eml</code> files to evaluate fine-tuned DistilBERT transformer text inference, cryptographic SPF/DKIM/DMARC headers, IP intelligence, and static zero-touch URL heuristics in an isolated local environment.
              </p>
            </div>

            {/* Upload Section */}
            <UploadZone
              onAnalysisComplete={setAnalysisData}
              isLoading={isLoading}
              setIsLoading={setIsLoading}
              errorMessage={errorMessage}
              setErrorMessage={setErrorMessage}
            />

            {/* Feature Cards Grid */}
            <div className="mt-12 sm:mt-16">
              <div className="text-center mb-6">
                <h3 className="text-xs uppercase font-semibold text-slate-500 tracking-wider">
                  Core Forensic Capabilities
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-left">
                {/* Feature 1: Transformer */}
                <div className="p-5 rounded-2xl bg-white border border-surface-border shadow-card hover:shadow-card-hover transition-all space-y-3">
                  <div className="w-10 h-10 rounded-xl bg-teal-50 border border-teal-100 flex items-center justify-center text-brand-600">
                    <Cpu className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-navy-900 mb-1">
                      Transformer-Based Detection
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      Evaluates email subject and body text through a fine-tuned DistilBERT model, emitting uncalibrated text heuristic scores with explicit limitations.
                    </p>
                  </div>
                </div>

                {/* Feature 2: Authentication */}
                <div className="p-5 rounded-2xl bg-white border border-surface-border shadow-card hover:shadow-card-hover transition-all space-y-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
                    <Lock className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-navy-900 mb-1">
                      Email Authentication
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      Parses reported SPF sender policy, DKIM cryptographic signatures, and DMARC alignment records across downstream mail transfer agent assertions.
                    </p>
                  </div>
                </div>

                {/* Feature 3: IP Intelligence */}
                <div className="p-5 rounded-2xl bg-white border border-surface-border shadow-card hover:shadow-card-hover transition-all space-y-3">
                  <div className="w-10 h-10 rounded-xl bg-purple-50 border border-purple-100 flex items-center justify-center text-purple-600">
                    <Network className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-navy-900 mb-1">
                      IP Intelligence &amp; Provenance
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      Reconstructs chronological Received transit hops, extracts candidate IPs, validates routability, and identifies earliest origin relay candidates.
                    </p>
                  </div>
                </div>

                {/* Feature 4: Static URLs */}
                <div className="p-5 rounded-2xl bg-white border border-surface-border shadow-card hover:shadow-card-hover transition-all space-y-3">
                  <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-navy-900 mb-1">
                      Static URL Intelligence
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      Extracts hyperlinks and scores structural heuristics (IP literals, suspicious TLDs, hex encodings) with zero network requests or DNS resolutions.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Top Analysis Overview Banner */}
            <EmailOverviewBanner data={analysisData} onReset={handleReset} />

            {/* Navigation Tabs Bar */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex items-center space-x-1.5 border-b border-surface-border pb-3 overflow-x-auto text-xs sm:text-sm font-medium">
                <button
                  onClick={() => setActiveTab('all')}
                  className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                    activeTab === 'all'
                      ? 'bg-brand-500 text-white font-semibold shadow'
                      : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                  }`}
                >
                  <Layers className="w-4 h-4" />
                  <span>All Forensics</span>
                </button>

                {analysisData.evidence_fusion && (
                  <button
                    onClick={() => setActiveTab('fusion')}
                    className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                      activeTab === 'fusion'
                        ? 'bg-brand-500 text-white font-semibold shadow'
                        : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                    }`}
                  >
                    <Shield className="w-4 h-4" />
                    <span>Evidence Fusion</span>
                  </button>
                )}

                {analysisData.authentication_analysis && (
                  <button
                    onClick={() => setActiveTab('auth')}
                    className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                      activeTab === 'auth'
                        ? 'bg-brand-500 text-white font-semibold shadow'
                        : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                    }`}
                  >
                    <Lock className="w-4 h-4" />
                    <span>Authentication</span>
                  </button>
                )}

                <button
                  onClick={() => setActiveTab('ips')}
                  className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                    activeTab === 'ips'
                      ? 'bg-brand-500 text-white font-semibold shadow'
                      : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                  }`}
                >
                  <Network className="w-4 h-4" />
                  <span>IP Candidates ({analysisData.ip_candidates.length})</span>
                </button>

                <button
                  onClick={() => setActiveTab('urls')}
                  className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                    activeTab === 'urls'
                      ? 'bg-brand-500 text-white font-semibold shadow'
                      : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                  }`}
                >
                  <Globe className="w-4 h-4" />
                  <span>URLs ({analysisData.urls.length})</span>
                </button>

                <button
                  onClick={() => setActiveTab('headers')}
                  className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                    activeTab === 'headers'
                      ? 'bg-brand-500 text-white font-semibold shadow'
                      : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                  }`}
                >
                  <Mail className="w-4 h-4" />
                  <span>Headers &amp; Transit</span>
                </button>

                <button
                  onClick={() => setActiveTab('attachments')}
                  className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                    activeTab === 'attachments'
                      ? 'bg-brand-500 text-white font-semibold shadow'
                      : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                  }`}
                >
                  <Paperclip className="w-4 h-4" />
                  <span>Attachments ({analysisData.attachments.length})</span>
                </button>

                <button
                  onClick={() => setActiveTab('body')}
                  className={`px-3.5 py-2 rounded-xl transition-all flex items-center space-x-2 whitespace-nowrap shadow-subtle ${
                    activeTab === 'body'
                      ? 'bg-brand-500 text-white font-semibold shadow'
                      : 'bg-white text-slate-600 hover:text-navy-900 hover:bg-slate-50 border border-surface-border'
                  }`}
                >
                  <AlignLeft className="w-4 h-4" />
                  <span>Body Forensics</span>
                </button>
              </div>
            </div>

            {/* Content Display based on Active Tab */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
              {/* Evidence Fusion Card: in 'all' or 'fusion' tab */}
              {(activeTab === 'all' || activeTab === 'fusion') && analysisData.evidence_fusion && (
                <EvidenceFusionCard fusion={analysisData.evidence_fusion} />
              )}

              {/* Authentication Card: in 'all' or 'auth' tab */}
              {(activeTab === 'all' || activeTab === 'auth') && analysisData.authentication_analysis && (
                <AuthenticationCard auth={analysisData.authentication_analysis} />
              )}

              {/* IP Candidates Card: in 'all' or 'ips' tab */}
              {(activeTab === 'all' || activeTab === 'ips') && (
                <IPCandidatesCard
                  candidates={analysisData.ip_candidates}
                  ipIntelligence={analysisData.ip_intelligence}
                />
              )}

              {/* Extracted URLs Card: in 'all' or 'urls' tab */}
              {(activeTab === 'all' || activeTab === 'urls') && (
                <ExtractedURLsCard
                  key={`urls-${analysisData.filename}-${analysisData.parsed_at}`}
                  urls={analysisData.urls}
                  urlAnalysis={analysisData.url_analysis}
                />
              )}

              {/* RFC 5322 Standard Headers & Transit: in 'all' or 'headers' tab */}
              {(activeTab === 'all' || activeTab === 'headers') && (
                <HeaderForensics headers={analysisData.headers} />
              )}

              {/* Attachment Forensics Card: in 'all' or 'attachments' tab */}
              {(activeTab === 'all' || activeTab === 'attachments') && (
                <AttachmentForensicsCard attachments={analysisData.attachments} />
              )}

              {/* Body Forensics Card: in 'all' or 'body' tab */}
              {(activeTab === 'all' || activeTab === 'body') && (
                <BodyForensicsCard body={analysisData.body} />
              )}
            </div>
          </div>
        )}
      </main>

      {/* Professional Footer */}
      <footer className="border-t border-surface-border bg-white py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-1.5">
          <p className="font-semibold text-navy-900">
            PhishIntel — Transformer &amp; NLP-Based Email Phishing Detection and IP Intelligence
          </p>
          <p className="text-slate-500">
            Deterministic offline analysis • Zero external network lookups • Single-file RFC 5322 processing • Zero retention
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
