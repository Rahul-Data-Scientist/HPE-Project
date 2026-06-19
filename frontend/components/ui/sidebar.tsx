'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, Activity, Hexagon, Shield, PanelLeftClose, PanelLeftOpen, CircleDot } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function Sidebar() {
  const pathname = usePathname();
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Keyboard shortcut (Cmd/Ctrl + B) to toggle sidebar
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'b') {
        e.preventDefault();
        setIsCollapsed((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const navItems = [
    { 
      name: 'Dashboard', 
      href: '/', 
      icon: LayoutDashboard,
    },
    { 
      name: 'Remediation Center', 
      href: '/remediation', 
      icon: Activity,
    },
  ];

  return (
    <motion.div 
      initial={false}
      animate={{ width: isCollapsed ? 80 : 260 }}
      transition={{ type: "spring", stiffness: 300, damping: 30 }}
      className="bg-[#0F172A] flex flex-col h-full border-r border-slate-800 z-20 font-sans shadow-xl relative"
    >
      
      {/* --- Toggle Button (Edge Floating) --- */}
      <button 
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="absolute -right-3 top-8 bg-[#0F172A] border border-slate-700 text-slate-400 hover:text-white rounded-full p-1 z-50 shadow-md transition-colors"
        title={`Toggle Sidebar (⌘B)`}
      >
        {isCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
      </button>

      {/* --- Header & Logo --- */}
      <div className="h-24 flex items-center px-6 border-b border-slate-800/60 overflow-hidden shrink-0">
        <div className="flex items-center gap-3 cursor-pointer">
          {/* Logo Mark */}
          <div className="relative flex items-center justify-center w-8 h-8 shrink-0">
            <Hexagon className="absolute w-8 h-8 text-[#01A982] opacity-80" strokeWidth={2} />
            <Shield className="w-3.5 h-3.5 text-white fill-white z-10" />
          </div>
          
          {/* Brand Name (Hidden when collapsed) */}
          <AnimatePresence>
            {!isCollapsed && (
              <motion.div 
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10, transition: { duration: 0.1 } }}
                className="flex flex-col whitespace-nowrap"
              >
                <span className="text-xl font-black text-white tracking-tight">
                  HPE <span className="text-[#01A982]">Project</span>
                </span>
                <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-0.5">
                  Zero-Touch Remediation
                </span>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* --- Navigation Links --- */}
      <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-hidden">
        <AnimatePresence>
          {!isCollapsed && (
            <motion.p 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-4 whitespace-nowrap"
            >
              Core Modules
            </motion.p>
          )}
        </AnimatePresence>
        
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          
          return (
            <Link key={item.name} href={item.href} title={isCollapsed ? item.name : undefined}>
              <div 
                className={`relative flex items-center ${isCollapsed ? 'justify-center px-0' : 'justify-between px-3'} py-2.5 rounded-lg transition-colors duration-200 group
                  ${isActive 
                    ? 'bg-[#01A982]/10 text-white' 
                    : 'hover:bg-slate-800/50 text-slate-400 hover:text-slate-200'
                  }
                `}
              >
                {/* Active Indicator Line */}
                {isActive && (
                  <motion.div 
                    layoutId="active-nav"
                    className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-[#01A982] rounded-r-md"
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                  />
                )}
                
                <div className="flex items-center justify-center">
                  <item.icon 
                    className={`w-4 h-4 ${!isCollapsed && 'mr-3'} ${isActive ? 'text-[#01A982]' : 'text-slate-500 group-hover:text-slate-300'}`} 
                    strokeWidth={isActive ? 2.5 : 2} 
                  />
                  
                  <AnimatePresence>
                    {!isCollapsed && (
                      <motion.span 
                        initial={{ opacity: 0, width: 0 }}
                        animate={{ opacity: 1, width: "auto" }}
                        exit={{ opacity: 0, width: 0, transition: { duration: 0.1 } }}
                        className={`text-sm whitespace-nowrap ${isActive ? 'font-bold' : 'font-medium'}`}
                      >
                        {item.name}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </div>

                
              </div>
            </Link>
          );
        })}
      </nav>

      

    </motion.div>
  );
}