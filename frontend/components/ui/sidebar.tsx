'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, ShieldAlert } from 'lucide-react';

export default function Sidebar() {
  const pathname = usePathname();

  // Helper function to determine if a link is active
  const isActive = (path: string) => pathname === path;

  return (
    <aside className="w-64 bg-[#0F172A] text-slate-300 flex flex-col justify-between shadow-2xl z-20 shrink-0">
      <div>
        {/* Brand Header */}
        <div className="h-20 flex items-center px-6 border-b border-slate-800 bg-[#0B1120]">
          <div className="w-8 h-8 bg-[#01A982] rounded-md mr-3 flex items-center justify-center shadow-[0_0_15px_rgba(1,169,130,0.5)]">
            <ShieldAlert className="text-white h-5 w-5" />
          </div>
          <span className="text-lg font-bold text-white tracking-wide">
            <span className="text-[#01A982]">Monitering</span>
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="p-4 space-y-2 mt-4">
          <Link 
            href="/" 
            className={`flex items-center px-4 py-3 text-sm font-medium rounded-lg border transition-colors ${
              isActive('/') 
                ? 'bg-[#01A982]/10 text-[#01A982] border-[#01A982]/20' 
                : 'border-transparent text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <LayoutDashboard className="h-5 w-5 mr-3" />
            Executive Dashboard
          </Link>

          <Link 
            href="/remediation" 
            className={`flex items-center px-4 py-3 text-sm font-medium rounded-lg border transition-colors ${
              isActive('/remediation') 
                ? 'bg-[#01A982]/10 text-[#01A982] border-[#01A982]/20' 
                : 'border-transparent text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <ShieldAlert className="h-5 w-5 mr-3" />
            Remediation Center
          </Link>
        </nav>
      </div>

      {/* Bottom Settings */}
      {/* <div className="p-4 border-t border-slate-800 space-y-2">
        <button className="flex w-full items-center px-4 py-2 text-sm font-medium text-slate-300 border border-transparent rounded-lg hover:bg-slate-800 transition-colors">
          <Settings className="h-5 w-5 mr-3 text-slate-500" />
          System Settings
        </button>
        <button className="flex w-full items-center px-4 py-2 text-sm font-medium text-slate-300 border border-transparent rounded-lg hover:bg-red-500/10 hover:text-red-400 transition-colors">
          <LogOut className="h-5 w-5 mr-3 text-slate-500 group-hover:text-red-400 transition-colors" />
          Sign Out
        </button>
      </div> */}
    </aside>
  );
}