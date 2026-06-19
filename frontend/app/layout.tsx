import React from 'react';
import type { Metadata } from 'next';
import { Inter, Geist_Mono } from 'next/font/google';
import './globals.css';

// Import your newly created Sidebar component
import Sidebar from '@/components/ui/sidebar';

// Configure Inter (Main Sans-Serif Font for UI/Headers)
const inter = Inter({
  variable: "--font-sans",
  subsets: ["latin"],
  display: "swap",
});

// Configure Geist Mono (For Terminal Logs/Code Blocks)
const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

// Global Metadata for browser tabs and SEO
export const metadata: Metadata = {
  title: 'NovaGuard | Zero-Touch Remediation',
  description: 'Enterprise Zero-Touch Vulnerability Remediation Dashboard',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="antialiased">
      <body 
        className={`${inter.variable} ${geistMono.variable} font-sans bg-[#F8FAFC] text-[#0F172A] flex h-screen overflow-hidden`}
      >
        {/* Fixed Navigation Sidebar */}
        <Sidebar />

        {/* Main Scrollable Content Area */}
        <main className="flex-1 overflow-y-auto relative w-full">
          {children}
        </main>
        
      </body>
    </html>
  );
}