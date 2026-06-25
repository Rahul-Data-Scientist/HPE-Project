'use client';

import React, { useEffect, useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { AreaChart, Area, PieChart, Pie, Cell, ResponsiveContainer, Tooltip, XAxis, CartesianGrid, Legend } from 'recharts';
import { ShieldAlert, Clock, DollarSign, Cpu, Activity, AlertCircle, CheckCircle2, Layers } from 'lucide-react';

type DashboardData = {
  kpis: { avg_cost: number; avg_mttr: string; total_vulns: number; total_solved: number; total_tokens: number; success_rate: number; pending_vulns: number };
  tokens: { time: string; tokens: number }[];
  severities: { name: string; value: number; color: string }[];
  recent_activity: { id: string; name: string; severity: string; status: string; time: string }[];
};

// Helper for formatting large numbers
const formatCompactNumber = (num: number) => {
  return new Intl.NumberFormat('en', { notation: "compact", maximumFractionDigits: 1 }).format(num);
};

// Lookup maps for cleaner classNames
const severityStyles: Record<string, string> = {
  Critical: 'bg-red-50 border-red-200 text-red-700',
  High: 'bg-orange-50 border-orange-200 text-orange-700',
  Medium: 'bg-yellow-50 border-yellow-200 text-yellow-700',
  Low: 'bg-blue-50 border-blue-200 text-blue-700',
};

export default function ExecutiveDashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchDashboardData = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/v1/dashboard');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const liveData = await response.json();
        
        if (isMounted) {
          if (liveData.error) {
            setErrorMessage(`Backend Error: ${liveData.error}`);
            setIsConnected(false);
          } else {
            setData(liveData);
            setIsConnected(true);
            setErrorMessage(null);
            setLastUpdated(new Date());
          }
        }
      } catch (err: any) {
        if (isMounted) { 
          setErrorMessage(`Connection Error: ${err.message}`); 
          setIsConnected(false); 
        }
      }
    };

    fetchDashboardData();
    const intervalId = setInterval(fetchDashboardData, 10000);
    return () => { isMounted = false; clearInterval(intervalId); };
  }, []);

  // KPI Configuration array to keep render logic clean
  const kpiCards = useMemo(() => {
    if (!data) return [];
    return [
      { title: "Avg Cost / Vuln", icon: DollarSign, value: `$${data.kpis.avg_cost.toFixed(2)}`, accent: 'text-[#01A982]', border: 'border-t-[#01A982]' },
      { title: "Avg MTTR / Vuln", icon: Clock, value: data.kpis.avg_mttr, accent: 'text-[#01A982]', border: 'border-t-[#01A982]' },
      { title: "Total Vulns", icon: Layers, value: data.kpis.total_vulns.toLocaleString(), accent: 'text-slate-700', border: 'border-t-slate-700' },
      { title: "Total Solved", icon: ShieldAlert, value: data.kpis.total_solved.toLocaleString(), accent: 'text-[#01A982]', border: 'border-t-[#01A982]' },
      { title: "Tokens Used", icon: Cpu, value: formatCompactNumber(data.kpis.total_tokens), subValue: data.kpis.total_tokens.toLocaleString(), accent: 'text-blue-500', border: 'border-t-blue-500' },
    ];
  }, [data]);

  // Initial Load Error (Only show full screen if we never got data)
  if (errorMessage && !data) return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4">
      <div className="max-w-md w-full p-8 bg-red-50 border border-red-200 rounded-xl text-center">
        <AlertCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <h2 className="text-xl font-bold text-red-700 mb-2">Dashboard Unavailable</h2>
        <p className="text-red-600 font-medium text-sm">{errorMessage}</p>
      </div>
    </div>
  );

  // Loading State
  if (!data) return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-6 min-h-[calc(100vh-4rem)]">
      <div className="flex justify-between items-end mb-4">
        <div className="space-y-2">
          <Skeleton className=" h-8 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Skeleton className="h-8 w-40" />
      </div>
      {/* Updated to 6 columns for the skeletons to match the new layout */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-28 w-full rounded-xl" />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-4">
        <Skeleton className="h-[360px] w-full rounded-xl" />
        <Skeleton className="h-[360px] w-full rounded-xl" />
      </div>
      <Skeleton className="h-96 w-full rounded-xl mt-4" />
    </div>
  );

  return (
    <div className="p-4 md:p-8 max-w-[1600px] mx-auto space-y-6 min-h-[calc(100vh-4rem)] flex flex-col font-sans">
      
      {/* Header Section */}
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4 mb-6">
        <div>
          <h1 className="text-2xl md:text-3xl font-extrabold text-slate-900 tracking-tight">Executive Telemetry</h1>
          <p className="text-slate-500 mt-1 font-medium text-sm md:text-base">
            Global fleet vulnerability and AI agent performance.
            {lastUpdated && <span className="ml-2 text-xs text-slate-400 hidden md:inline">Last updated: {lastUpdated.toLocaleTimeString()}</span>}
          </p>
        </div>
        <Badge variant="outline" className={`px-4 py-2 shadow-sm font-semibold text-sm flex items-center w-fit ${isConnected ? 'bg-white border-slate-200 text-slate-600' : 'bg-red-50 border-red-500 text-red-600'}`}>
          <span className={`w-2 h-2 rounded-full mr-2 inline-block ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}}`} />
          {isConnected ? 'Live Sync Active' : 'Connection Lost'}
        </Badge>
      </div>

      {/* Transient Error Banner (Shows if connection drops but we still have old data) */}
      {!isConnected && errorMessage && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center gap-3 text-sm font-medium">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <span>Real-time sync paused. Displaying last known data. {errorMessage}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpiCards.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <Card key={kpi.title} className={`shadow-sm border-t-4 ${kpi.border} hover:shadow-md transition-shadow`}>
              <CardHeader className="pb-2 pt-4 px-4 flex flex-row items-center justify-between">
                <CardTitle className="text-xs font-bold text-slate-500 uppercase tracking-wider">{kpi.title}</CardTitle>
                <Icon className={`h-4 w-4 ${kpi.accent}`} />
              </CardHeader>
              <CardContent className="px-4 pb-4" title={kpi.subValue || ""}>
                <div className="text-2xl font-black text-slate-900">{kpi.value}</div>
              </CardContent>
            </Card>
          );
        })}

        {/* Special Success Rate Card - Updated with Real DB Pending Stats */}
        <Card className="shadow-sm border-t-4 border-t-slate-900 hover:shadow-md transition-shadow">
          <CardHeader className="pb-2 pt-4 px-4 flex flex-row items-center justify-between">
            <CardTitle className="text-xs font-bold text-slate-500 uppercase tracking-wider">Success Rate</CardTitle>
            <Activity className="h-4 w-4 text-slate-900" />
          </CardHeader>
          <CardContent className="px-4 pb-4 flex flex-col justify-between">
            <div className="text-2xl font-black text-slate-900">{data.kpis.success_rate}%</div>
            <div className="text-[11px] font-bold text-slate-400 mt-1 flex items-center">
              <span className="text-emerald-600 flex items-center gap-1" title="Solved"><CheckCircle2 className="h-3 w-3" /> {data.kpis.total_solved}</span>
              <span className="mx-2 text-slate-300">·</span>
              <span className="text-amber-500 flex items-center gap-1" title="Pending"><AlertCircle className="h-3 w-3" /> {data.kpis.pending_vulns}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <Card className="shadow-sm lg:col-span-3">
          <CardHeader className="border-b border-slate-100 pb-4">
            <CardTitle className="text-base font-bold text-slate-900">Historical Token Consumption</CardTitle>
            <CardDescription className="text-xs text-slate-500">Tokens processed over the last 24 hours</CardDescription>
          </CardHeader>
          <CardContent className="h-[320px] pt-6 pl-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.tokens} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTokens" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#01A982" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#01A982" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#E2E8F0" />
                <XAxis dataKey="time" stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} dy={10} minTickGap={40} />
                <Tooltip 
                  contentStyle={{ borderRadius: '8px', border: '1px solid #E2E8F0', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} 
                  itemStyle={{ color: '#01A982', fontWeight: 'bold' }}
                  formatter={(value: number) => [value.toLocaleString(), 'Tokens']}
                />
                <Area type="monotone" dataKey="tokens" stroke="#01A982" strokeWidth={3} fillOpacity={1} fill="url(#colorTokens)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="shadow-sm lg:col-span-2 flex flex-col">
          <CardHeader className="border-b border-slate-100 pb-4">
            <CardTitle className="text-base font-bold text-slate-900">Vulnerabilities by Severity</CardTitle>
            <CardDescription className="text-xs text-slate-500">All-time fleet distribution</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 flex items-center justify-center pt-6">
            <div className="w-full h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={data.severities} cx="40%" cy="50%" innerRadius={70} outerRadius={100} paddingAngle={5} cornerRadius={4} dataKey="value" stroke="none">
                    {data.severities.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ borderRadius: '8px', border: '1px solid #E2E8F0', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                    formatter={(value: number, name: string) => [value.toLocaleString(), name]}
                  />
                  <Legend verticalAlign="middle" align="right" layout="vertical" iconType="circle" wrapperStyle={{ paddingLeft: '20px', fontSize: '13px', color: '#475569' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Activity Table */}
      <Card className="shadow-sm flex-1 mt-2 border border-slate-200 flex flex-col">
        <CardHeader className="bg-slate-50 border-b border-slate-200 py-4">
          <CardTitle className="text-base font-bold text-slate-900">Live Global Remediation Log</CardTitle>
        </CardHeader>
        <CardContent className="p-0 flex-1 overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 bg-white">
              <TableRow className="hover:bg-transparent border-slate-200">
                <TableHead className="font-bold text-slate-500 pl-6 uppercase text-xs">Identifier</TableHead>
                <TableHead className="font-bold text-slate-500 uppercase text-xs">Asset Target</TableHead>
                <TableHead className="font-bold text-slate-500 uppercase text-xs">Severity</TableHead>
                <TableHead className="font-bold text-slate-500 uppercase text-xs">Status</TableHead>
                <TableHead className="text-right font-bold text-slate-500 pr-6 uppercase text-xs">Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.recent_activity.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-slate-500 py-8">No recent activity.</TableCell>
                </TableRow>
              ) : (
                data.recent_activity.map((row) => (
                  <TableRow key={row.id} className="group hover:bg-slate-50 transition-colors border-slate-100">
                    <TableCell className="font-bold text-slate-900 pl-6 font-mono text-xs">{row.id}</TableCell>
                    <TableCell className="font-medium text-slate-700">{row.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`px-2 py-0.5 shadow-none text-xs font-bold border ${severityStyles[row.severity] || 'bg-slate-50 border-slate-200 text-slate-600'}`}>
                        {row.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={`px-2 py-0.5 shadow-none text-xs font-medium ${row.status === 'Resolved' ? 'bg-emerald-500 text-white hover:bg-emerald-600' : 'bg-slate-200 text-slate-700 hover:bg-slate-300'}`}>
                        {row.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right text-slate-400 font-medium pr-6 text-xs">{row.time}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}