import type { FC } from 'react';
import { Shield, Cpu } from 'lucide-react';

export interface NavbarProps {
  onBrandClick?: () => void;
}

export const Navbar: FC<NavbarProps> = ({ onBrandClick }) => {
  return (
    <header className="border-b border-surface-border bg-white sticky top-0 z-50 shadow-subtle">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand & Subtitle */}
        <div
          onClick={onBrandClick}
          className={`flex items-center space-x-3.5 ${onBrandClick ? 'cursor-pointer select-none' : ''}`}
        >
          <div className="w-9 h-9 rounded-lg bg-brand-50 border border-brand-200 flex items-center justify-center text-brand-500 shadow-sm">
            <Shield className="w-5 h-5 text-brand-500" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold tracking-tight text-navy-900">
                Phish<span className="text-brand-500">Intel</span>
              </span>
              <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                Forensics
              </span>
            </div>
            <p className="text-xs text-slate-500 hidden md:block">
              Transformer &amp; NLP-Based Email Phishing Detection and IP Intelligence
            </p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 text-xs font-medium px-3 py-1.5 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span className="hidden sm:inline text-emerald-700">Engine:</span>
            <span className="font-semibold">Local Offline</span>
          </div>

          <div className="hidden sm:flex items-center space-x-1.5 text-xs text-slate-500 px-3 py-1.5 rounded-md bg-slate-50 border border-surface-border">
            <Cpu className="w-3.5 h-3.5 text-slate-400" />
            <span className="font-mono text-[11px]">DistilBERT + Heuristics</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
