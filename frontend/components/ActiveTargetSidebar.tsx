'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Loader2, ShieldCheck, GitPullRequest, Target, Database, AlertTriangle, Cpu, Clock, TerminalSquare } from 'lucide-react';

interface SidebarProps {
  currentStep: number;
  agentState?: 'rca' | 'patch' | 'pr_ci' | 'waiting' | 'resolved' | null;
  payload: any | null;
}

const STEPS_CONFIG = [
  { step: 1, label: 'Parsing & Extraction', icon: Database },
  { step: 2, label: 'Data Normalization', icon: Target },
  { step: 3, label: 'Risk Prioritization', icon: AlertTriangle },
  { step: 4, label: 'Agent Remediation & PR', icon: Cpu },
  { step: 5, label: 'Vulnerability Resolved', icon: ShieldCheck }
];

const AGENT_SUB_STEPS = [
  { id: 'rca', label: 'Root Cause Analysis' },
  { id: 'patch', label: 'Patch Script Generation' },
  { id: 'pr_ci', label: 'PR & CI/CD Validation' },
  { id: 'waiting', label: 'Waiting for Human Approval' }
];

export default function ActiveTargetSidebar({ currentStep, agentState = null, payload }: SidebarProps) {
  const isWaiting = !payload;
  const extractedCve = payload?.issue_description?.match(/(CVE-\d{4}-\d{4,7})/i)?.[0] || "CVE-UNKNOWN";
  const riskScore = payload ? "8.5" : "--";
  const severity = payload ? "HIGH" : "--";

  return (
    <Card className="bg-white border-slate-200 shadow-lg flex flex-col h-[600px] overflow-hidden relative">
      <div className="p-5 border-b bg-slate-50 flex-shrink-0 relative overflow-hidden">
        {/* HPE Green ambient glow */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-[#01A982]/10 rounded-full blur-3xl -mr-10 -mt-10 pointer-events-none" />
        
        <div className="flex justify-between items-start mb-4">
          <div>
            <h2 className="font-extrabold text-[#0F172A] text-lg tracking-tight flex items-center gap-2">
              <TerminalSquare className="w-5 h-5 text-[#01A982]" />
              Active Target
            </h2>
            <p className="text-xs text-slate-500 font-medium mt-0.5">Zero-Touch Pipeline</p>
          </div>
          <Badge className={currentStep === 5 ? "bg-[#01A982] text-white" : isWaiting ? "bg-slate-100 text-slate-500 border-slate-200" : "bg-[#0F172A] text-white shadow-md animate-pulse"}>
            {currentStep === 5 ? "Secured" : isWaiting ? "Standby" : "Processing"}
          </Badge>
        </div>

        <div className="grid grid-cols-2 gap-3 mt-2 bg-white p-3 rounded-lg border border-slate-100 shadow-sm">
          <div className="flex flex-col">
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-0.5">CVE ID</span>
            <span className={`text-sm font-mono font-semibold ${payload ? 'text-[#ef4444]' : 'text-slate-400'}`}>
              {payload ? extractedCve : "--"}
            </span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-0.5">Risk Score</span>
            <span className={`text-sm font-bold ${payload ? 'text-[#f59e0b]' : 'text-slate-400'}`}>
              {riskScore} <span className="text-xs font-normal">({severity})</span>
            </span>
          </div>
          <div className="flex flex-col col-span-2 pt-2 border-t border-slate-50 mt-1">
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-0.5">Repository target</span>
            <span className="text-sm font-mono text-[#0F172A] truncate">
              {payload ? `${payload.repo_owner}/${payload.repo_name}` : "--"}
            </span>
            <span className="text-xs font-mono text-[#01A982] truncate mt-0.5">
              ↳ {payload ? payload.target_file : "--"}
            </span>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto bg-white p-6 scrollbar-thin scrollbar-thumb-slate-200">
        {isWaiting ? (
          <div className="h-full flex flex-col items-center justify-center text-center opacity-50">
            <ShieldCheck className="w-12 h-12 text-slate-300 mb-3" />
            <p className="text-sm text-slate-500 font-medium">Upload a payload to initialize remediation.</p>
          </div>
        ) : (
          <div className="pl-5 ml-2 border-l-2 border-slate-100 space-y-7 py-2 relative">
            {STEPS_CONFIG.map((config) => {
              const isPast = currentStep > config.step;
              const isCurrent = currentStep === config.step;
              
              return (
                <div key={config.step} className="relative">
                  <div className="absolute -left-[31px] bg-white py-1">
                    {/* Replaced blue with HPE Green and Deep Slate matching PipelineTracker */}
                    {isPast || (config.step === 5 && isCurrent) ? (
                      <CheckCircle2 className="h-5 w-5 text-[#01A982] bg-white rounded-full shadow-sm" />
                    ) : isCurrent ? (
                      <div className="relative">
                        <Loader2 className="h-5 w-5 text-[#0F172A] bg-white rounded-full animate-spin relative z-10" />
                        <div className="absolute inset-0 bg-[#0F172A] blur-sm rounded-full animate-pulse opacity-30" />
                      </div>
                    ) : (
                      <div className="h-3 w-3 ml-1 rounded-full border-2 border-slate-200 bg-white" />
                    )}
                  </div>
                  
                  <div className="pl-4 flex flex-col pt-0.5">
                    <span className={`text-sm font-bold flex items-center gap-2 transition-colors duration-300 ${isPast || (config.step === 5 && isCurrent) ? 'text-[#01A982]' : isCurrent ? 'text-[#0F172A]' : 'text-slate-400'}`}>
                      {config.label}
                    </span>

                    <AnimatePresence>
                      {isCurrent && config.step === 4 && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="mt-3 overflow-hidden">
                          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg">
                            <div className="text-xs font-bold text-[#0F172A] mb-3 flex items-center gap-2">
                              <Cpu className="w-3.5 h-3.5 text-[#01A982]" />
                              Agent Graph Execution
                            </div>
                            
                            <div className="space-y-3 pl-1.5 border-l-2 border-slate-200 ml-1.5">
                              {AGENT_SUB_STEPS.map((subStep) => {
                                const agentStatesList = ['rca', 'patch', 'pr_ci', 'waiting', 'resolved'];
                                const currentIndex = agentStatesList.indexOf(agentState || 'rca');
                                const subStepIndex = agentStatesList.indexOf(subStep.id);
                                
                                const isSubPast = currentIndex > subStepIndex;
                                const isSubCurrent = currentIndex === subStepIndex;
                                
                                return (
                                  <div key={subStep.id} className="relative pl-4">
                                    <div className="absolute -left-[5px] top-1 h-2 w-2 rounded-full bg-white border border-slate-300">
                                      {isSubPast && <div className="absolute inset-0 bg-[#01A982] rounded-full" />}
                                      {isSubCurrent && subStep.id !== 'waiting' && <div className="absolute inset-0 bg-[#0F172A] rounded-full animate-ping opacity-75" />}
                                      {isSubCurrent && subStep.id === 'waiting' && <div className="absolute inset-0 bg-[#f59e0b] rounded-full animate-pulse" />}
                                      {isSubCurrent && <div className="absolute inset-0 bg-[#0F172A] rounded-full scale-75" />}
                                    </div>
                                    <div className={`text-xs ${isSubPast ? 'text-[#01A982]' : isSubCurrent ? 'font-bold text-[#0F172A]' : 'text-slate-400'}`}>
                                      {subStep.label}
                                    </div>
                                    {isSubCurrent && subStep.id === 'waiting' && (
                                      <div className="text-[10px] text-[#b45309] mt-1 font-medium flex items-center gap-1.5 bg-[#fef3c7] p-1.5 rounded border border-[#fde68a] w-fit">
                                        <Clock className="w-3 h-3" /> Awaiting PR review...
                                      </div>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}