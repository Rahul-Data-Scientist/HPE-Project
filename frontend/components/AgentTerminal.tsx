'use client';

import React, { useEffect, useRef } from 'react';
import { Card } from "@/components/ui/card";
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal } from 'lucide-react';
import type { LogEntry } from '@/types'; 

export default function AgentTerminal({ logs = [] }: { logs?: LogEntry[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <Card className="bg-[#0d1117] text-slate-300 font-mono text-sm border-slate-800 shadow-2xl overflow-hidden flex flex-col h-[600px] relative selection:bg-[#01A982]/20 selection:text-[#01A982]">
      {/* HPE Green Ambient Glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-3/4 h-20 bg-[#01A982]/10 blur-[50px] pointer-events-none" />

      {/* Mac-style Window Header matches dark popover theme */}
      <div className="bg-[#161b22] p-3 flex items-center justify-between border-b border-slate-800/80 shrink-0 z-10 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="flex gap-2.5">
            <div className="w-3 h-3 rounded-full bg-[#ef4444] border border-[#dc2626] shadow-inner"></div>
            <div className="w-3 h-3 rounded-full bg-[#f59e0b] border border-[#d97706] shadow-inner"></div>
            <div className="w-3 h-3 rounded-full bg-[#01a982] border border-[#018868] shadow-inner"></div>
          </div>
          <div className="flex items-center text-xs font-medium text-slate-400 tracking-wider">
            <Terminal className="w-3.5 h-3.5 mr-2 text-[#01A982]" />
            Agent Console
          </div>
        </div>
      </div>

      <div ref={scrollRef} className="p-5 overflow-y-auto flex-1 leading-relaxed z-10 scrollbar-thin scrollbar-thumb-slate-700">
        <div className="space-y-2">
          <AnimatePresence initial={false}>
            {Array.isArray(logs) && logs.map((log) => (
              <motion.div 
                key={log.id} 
                initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                className="flex gap-4 hover:bg-white/5 px-2 py-0.5 rounded transition-colors -mx-2"
              >
                <span className="text-slate-500/60 select-none shrink-0">{log.time}</span>
                <span className={`${log.color} font-medium`}>{log.message}</span>
              </motion.div>
            ))}
          </AnimatePresence>
          
          <div className="flex mt-6 px-2 -mx-2">
            <span className="text-[#01A982] font-bold mr-3 select-none">agent $</span>
            <span className="w-2.5 h-5 bg-slate-400 animate-pulse block shadow-[0_0_8px_rgba(1,169,130,0.4)]"></span>
          </div>
        </div>
      </div>
    </Card>
  );
}