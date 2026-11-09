import { useState, useRef } from 'react';
import type { FC, ChangeEvent, DragEvent } from 'react';
import { UploadCloud, FileText, AlertCircle, Loader2, Shield } from 'lucide-react';
import type { EmailAnalysisResponse } from '../types/forensics';

interface UploadZoneProps {
  onAnalysisComplete: (data: EmailAnalysisResponse) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  errorMessage: string | null;
  setErrorMessage: (msg: string | null) => void;
}

export const UploadZone: FC<UploadZoneProps> = ({
  onAnalysisComplete,
  isLoading,
  setIsLoading,
  errorMessage,
  setErrorMessage,
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadFileName, setUploadFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = async (file: File) => {
    setErrorMessage(null);
    setUploadFileName(file.name);

    // 1. Client-side extension validation
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setErrorMessage(`Invalid file format "${file.name}". Only RFC 5322 .eml files are accepted for forensic parsing.`);
      setUploadFileName(null);
      return;
    }

    // 2. Client-side size check (10 MB limit)
    const MAX_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
      setErrorMessage(`File exceeds 10 MB limit (${sizeMB} MB). Please select an email file under 10 MB.`);
      setUploadFileName(null);
      return;
    }

    if (file.size === 0) {
      setErrorMessage('The selected email file is empty (0 bytes).');
      setUploadFileName(null);
      return;
    }

    setIsLoading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/v1/email/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errorDetail = `Analysis failed with status ${response.status}`;
        try {
          const errData = await response.json();
          if (errData && errData.detail) {
            errorDetail = errData.detail;
          }
        } catch {
          // Keep default message
        }
        setErrorMessage(errorDetail);
        return;
      }

      const data: EmailAnalysisResponse = await response.json();
      onAnalysisComplete(data);
    } catch (err: unknown) {
      setErrorMessage(
        err instanceof Error
          ? `Network error: ${err.message}. Ensure the PhishIntel backend is running on port 8000.`
          : 'An unexpected connection error occurred during analysis.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
      e.target.value = '';
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto my-4">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !isLoading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-8 sm:p-12 text-center transition-all cursor-pointer bg-white shadow-card ${
          isDragOver
            ? 'border-brand-500 bg-brand-50/40 ring-4 ring-brand-100 scale-[1.005]'
            : 'border-slate-300 hover:border-brand-400 hover:bg-slate-50/60'
        } ${isLoading ? 'pointer-events-none opacity-80 cursor-wait' : ''}`}
      >
        <input
          id="email-file-input"
          ref={fileInputRef}
          type="file"
          accept=".eml"
          onChange={handleFileSelect}
          className="hidden"
          disabled={isLoading}
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div
            className={`w-14 h-14 rounded-2xl flex items-center justify-center transition-transform ${
              isDragOver
                ? 'scale-110 bg-brand-100 text-brand-700'
                : 'bg-slate-100 text-brand-600'
            }`}
          >
            {isLoading ? (
              <Loader2 className="w-7 h-7 text-brand-600 animate-spin" />
            ) : (
              <UploadCloud className="w-7 h-7 text-brand-600" />
            )}
          </div>

          <div className="space-y-1.5 max-w-md mx-auto">
            <h3 className="text-base sm:text-lg font-semibold text-navy-900">
              {isLoading
                ? `Analyzing ${uploadFileName || 'email'}...`
                : 'Upload email file for investigation'}
            </h3>
            <p className="text-xs sm:text-sm text-slate-500 leading-relaxed">
              Drag and drop your <code className="font-mono text-xs px-1.5 py-0.5 rounded bg-slate-100 text-navy-900 font-semibold">.eml</code> file here, or{' '}
              <span className="text-brand-600 font-medium underline underline-offset-2 hover:text-brand-700">
                browse from your computer
              </span>
            </p>
          </div>

          {/* Validation Constraints Pills */}
          <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-xs text-slate-500">
            <span className="inline-flex items-center px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
              <FileText className="w-3.5 h-3.5 mr-1.5 text-slate-500" />
              RFC 5322 (.eml)
            </span>
            <span className="inline-flex items-center px-2.5 py-1 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
              Max size: 10 MB
            </span>
            <span className="inline-flex items-center px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-800 border border-emerald-200">
              <Shield className="w-3.5 h-3.5 mr-1.5 text-emerald-600" />
              100% Offline &amp; Isolated
            </span>
          </div>

          {isLoading && (
            <div className="w-full max-w-xs pt-2">
              <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                <div className="h-full bg-brand-500 rounded-full animate-pulse w-3/4" />
              </div>
              <p className="text-[11px] text-slate-400 mt-2 font-mono">
                Extracting transit hops, evaluating DistilBERT inference, and verifying signatures...
              </p>
            </div>
          )}
        </div>
      </div>

      {errorMessage && (
        <div className="mt-4 p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 flex items-start space-x-3 text-sm shadow-subtle">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold text-red-800">Ingestion notice: </span>
            <span className="text-red-700">{errorMessage}</span>
          </div>
        </div>
      )}
    </div>
  );
};
