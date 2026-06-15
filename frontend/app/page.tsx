"use client";

import { useState } from "react";
import AgentTerminal from "@/components/AgentTerminal";
import ActiveTargetSidebar from "@/components/ActiveTargetSidebar"; 
import UploadZone from "@/components/UploadZone"; // Your new component
import { ShieldCheck } from 'lucide-react';
import type { LogEntry } from "@/types";

export default function Dashboard() {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activePayload, setActivePayload] = useState<any>(null);
  const [agentState, setAgentState] = useState<'rca' | 'patch' | 'pr_ci' | 'waiting' | 'resolved' | null>(null);
  
  // UploadZone state
  const [file, setFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const parseCSVRow = (text: string) => {
    const regex = /(?:"([^"]*(?:""[^"]*)*)"|([^,]*))(?:,|$)/g;
    const result: string[] = [];
    let match;
    while ((match = regex.exec(text)) && match[0] !== '') {
      result.push(match[1] ? match[1].replace(/""/g, '"') : match[2]);
    }
    return result;
  };

  // Mapped to HPE Colors
  const getColorForLog = (text: string): string => {
    if (text.includes('[ERROR]') || text.includes('[CRITICAL]')) return 'text-[#ef4444]'; // Destructive Red
    if (text.includes('[WARNING]')) return 'text-[#f59e0b]'; // Warning Amber
    if (text.includes('[SYSTEM]') || text.includes('[CI/CD]')) return 'text-[#3b82f6]'; // Info Blue
    if (text.includes('[AGENT]')) return 'text-[#01A982]'; // HPE Green
    if (text.includes('[GIT]')) return 'text-[#8b5cf6]'; // Purple
    if (text.includes('[STANDBY]')) return 'text-slate-400'; 
    return 'text-slate-300';
  };

  const addLog = (message: string) => {
    const newLog: LogEntry = {
      id: crypto.randomUUID(),
      time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      color: getColorForLog(message),
      message: message
    };
    setLogs(prev => [...prev, newLog]);
  };

  const handleProcessFile = async () => {
    if (!file) return;
    setIsProcessing(true);

    try {
      const text = await file.text();
      const lines = text.split('\n').filter(line => line.trim() !== '');
      
      if (lines.length < 2) {
        addLog("[ERROR] Payload must contain at least a header row and one data row.");
        setIsProcessing(false);
        return;
      }

      const headers = parseCSVRow(lines[0]).map(h => h.trim());
      const data = parseCSVRow(lines[1]).map(d => d.trim());

      const payload: Record<string, string> = {};
      headers.forEach((header, index) => {
        payload[header] = data[index] || "";
      });

      if (!payload.issue_description || !payload.repo_owner || !payload.repo_name || !payload.target_file) {
        addLog("[ERROR] Missing required CSV columns.");
        setIsProcessing(false);
        return;
      }

      setActivePayload(payload);
      startPipeline(payload);

    } catch (error) {
      addLog("[ERROR] Failed to read or parse the CSV file.");
      setIsProcessing(false);
    }
  };

  const startPipeline = async (payload: any) => {
    setLogs([]); 
    setAgentState(null); 
    addLog("[SYSTEM] Initiating vulnerability ingest from CSV...");
    setCurrentStep(1); 

    try {
      const response = await fetch("http://localhost:8000/start-agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.body) {
         setIsProcessing(false);
         return;
      }
      
      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          setIsProcessing(false);
          break;
        }
        
        const chunk = decoder.decode(value);
        const lines = chunk.split("\n\n");
        
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.replace("data: ", ""));
              if (data.step) setCurrentStep(data.step);
              if (data.log) {
                addLog(data.log);
                
                const logText = data.log.toLowerCase();
                if (logText.includes('parsing vulnerability') || logText.includes('normalizing')) {
                  setAgentState('rca');
                } else if (logText.includes('generating bash') || logText.includes('generating automated')) {
                  setAgentState('patch');
                } else if (logText.includes('formulating git') || logText.includes('pipeline status') || logText.includes('pushing code')) {
                  setAgentState('pr_ci');
                } else if (logText.includes('standby') || logText.includes('sleep mode') || logText.includes('awaiting human')) {
                  setAgentState('waiting');
                } else if (logText.includes('resolved') || logText.includes('merged')) {
                  setAgentState('resolved');
                }
              }
            } catch (e) {
              console.error("Failed to parse chunk", line);
            }
          }
        }
      }
    } catch (error) {
       addLog("[CRITICAL ERROR] Failed to connect to backend engine.");
       setIsProcessing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#f8fafc] text-[#0f172a] p-8 font-sans">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* Header matched to new design */}
        <div className="flex justify-between items-center bg-white p-5 rounded-xl shadow-sm border border-slate-200">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#0F172A] flex items-center justify-center shadow-inner">
              <ShieldCheck className="text-[#01A982] w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-[#0F172A]">Zero Touch Vulnerability Remediator</h1>
              <p className="text-xs text-slate-500 font-medium">Automated Security Operations</p>
            </div>
          </div>
        </div>

        {/* Top Grid: Upload Zone */}
        <div className="grid grid-cols-1">
          <UploadZone 
            file={file} 
            setFile={setFile} 
            onProcess={handleProcessFile} 
            isProcessing={isProcessing} 
            isComplete={currentStep > 0} 
            filename={file?.name}
          />
        </div>

        {/* Main Content Grid: Sidebar + Terminal */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <ActiveTargetSidebar 
              currentStep={currentStep} 
              agentState={agentState} 
              payload={activePayload} 
            />
          </div>
          <div className="lg:col-span-2">
            <AgentTerminal logs={logs} />
          </div>
        </div>

      </div>
    </div>
  );
}