"use client";

import React, { useState } from "react";
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";

export default function TestMultipleUpload() {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      // Convert FileList to Array
      setSelectedFiles(Array.from(e.target.files));
      setUploadResult(null);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (selectedFiles.length === 0) return;

    setIsUploading(true);
    setError(null);
    setUploadResult(null);

    const formData = new FormData();
    // The key "files" MUST match the FastAPI parameter name exactly
    selectedFiles.forEach((file) => {
      formData.append("files", file);
    });

    try {
      const response = await fetch("http://127.0.0.1:8000/api/v1/upload-multiple", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok || data.status === "error") {
        throw new Error(data.message || "Upload failed from server.");
      }

      setUploadResult(data);
    } catch (err: any) {
      setError(err.message || "Network error occurred during upload.");
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6 font-sans">
      <div className="bg-white max-w-2xl w-full rounded-xl shadow-sm border border-slate-200/60 p-8 space-y-6">
        
        {/* Header */}
        <div className="text-center">
          <h1 className="text-2xl font-bold text-slate-900 flex items-center justify-center gap-2">
            <UploadCloud className="text-indigo-600" />
            Multiple File Upload Test
          </h1>
          <p className="text-sm text-slate-500 mt-2">
            Select multiple files to test the streaming backend endpoint.
          </p>
        </div>

        {/* Dropzone / Input Area */}
        <div className="border-2 border-dashed border-slate-300 rounded-xl p-8 text-center hover:bg-slate-50 transition-colors bg-slate-50/50 relative">
          <input
            type="file"
            id="multiple-file-upload"
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            multiple
            onChange={handleFileChange}
          />
          <div className="flex flex-col items-center justify-center pointer-events-none">
            <div className="h-12 w-12 bg-white border border-slate-200 shadow-sm rounded-full flex items-center justify-center mb-3">
              <FileText className="h-6 w-6 text-indigo-600" />
            </div>
            <span className="text-base font-semibold text-slate-700">
              Click or Drag files here
            </span>
            <span className="text-sm text-slate-500 mt-1">
              Any file type supported
            </span>
          </div>
        </div>

        {/* Selected Files Preview */}
        {selectedFiles.length > 0 && (
          <div className="bg-slate-50 rounded-lg border border-slate-200 p-4">
            <h3 className="text-sm font-semibold text-slate-700 mb-3">
              Selected Files ({selectedFiles.length})
            </h3>
            <ul className="space-y-2 max-h-40 overflow-y-auto">
              {selectedFiles.map((file, idx) => (
                <li key={idx} className="flex justify-between text-sm bg-white p-2 rounded border border-slate-100 shadow-sm">
                  <span className="text-slate-800 truncate pr-4">{file.name}</span>
                  <span className="text-slate-400 shrink-0">
                    {(file.size / 1024).toFixed(1)} KB
                  </span>
                </li>
              ))}
            </ul>

            <button
              onClick={handleUpload}
              disabled={isUploading}
              className="mt-4 w-full flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2.5 rounded-md font-medium transition-all shadow-sm disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {isUploading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Uploading Streams...
                </>
              ) : (
                "Execute Multiple Upload"
              )}
            </button>
          </div>
        )}

        {/* Success State */}
        {uploadResult && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4 flex items-start gap-3 text-emerald-800">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-semibold text-emerald-900 text-sm">Upload Successful</h4>
              <p className="text-xs mt-1 opacity-90">
                Successfully saved {uploadResult.saved_files?.length} files to: <br/>
                <code className="bg-emerald-100 px-1 py-0.5 rounded text-emerald-900 font-mono mt-1 inline-block">
                  {uploadResult.folder}
                </code>
              </p>
            </div>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3 text-red-800">
            <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-semibold text-red-900 text-sm">Upload Failed</h4>
              <p className="text-xs mt-1 opacity-90">{error}</p>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}