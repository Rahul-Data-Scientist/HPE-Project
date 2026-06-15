'use client';

import React, { useRef } from 'react';
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { UploadCloud, FileSpreadsheet, Loader2, CheckCircle2 } from 'lucide-react';
import { motion } from 'framer-motion';

interface UploadZoneProps {
  file: File | null;
  setFile: (file: File | null) => void;
  onProcess: () => void;
  isProcessing: boolean;
  isComplete: boolean;
  filename?: string;
}

export default function UploadZone({ file, setFile, onProcess, isProcessing, isComplete, filename }: UploadZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  return (
    <Card className={`border-dashed border-2 transition-all ${
      isComplete ? 'border-[#01A982]/50 bg-[#01A982]/5' : 
      file ? 'border-[#0F172A] bg-slate-50' : 'border-slate-300 hover:bg-slate-50 cursor-pointer'
    }`}>
      <CardContent className="flex flex-col items-center justify-center p-8 text-center min-h-[160px] relative">
        <input 
          type="file" ref={inputRef} className="hidden" 
          accept=".csv,.xlsx" onChange={handleFileChange} disabled={isProcessing || isComplete}
        />

        {isComplete ? (
          <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="flex flex-col items-center">
            <CheckCircle2 className="h-10 w-10 text-[#01A982] mb-2" />
            <p className="font-semibold text-[#0F172A]">Payload Active</p>
            <p className="text-xs text-slate-500 font-mono mt-1">{filename || 'data.csv'}</p>
          </motion.div>
        ) : file ? (
          <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="flex flex-col items-center w-full">
            <FileSpreadsheet className="h-10 w-10 text-[#0F172A] mb-3" />
            <p className="font-semibold text-[#0F172A] truncate max-w-[200px]">{file.name}</p>
            
            <Button 
              onClick={onProcess} disabled={isProcessing}
              className="bg-[#01A982] hover:bg-[#01A982]/90 w-full text-white font-semibold mt-4"
            >
              {isProcessing ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Uploading...</> : 'Process Payload'}
            </Button>
          </motion.div>
        ) : (
          <div onClick={() => inputRef.current?.click()} className="flex flex-col items-center w-full">
            <UploadCloud className="h-10 w-10 mb-3 text-[#01A982]" />
            <p className="font-semibold text-[#0F172A]">Drag & Drop Scan Results</p>
            <p className="text-sm text-slate-500 mt-1">Supports .csv or .xlsx</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}