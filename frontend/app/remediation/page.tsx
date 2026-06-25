"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  UploadCloud,
  CheckCircle2,
  Circle,
  Loader2,
  Check,
  ExternalLink,
  ShieldAlert,
  RotateCcw,
} from "lucide-react";

// --- TYPES ---
interface LogMessage {
  time: string;
  text: string;
}

interface Vulnerability {
  thread_id: string;
  asset_id?: string; // The unique backend tracking ID (e.g., VULN-xyz123)
  vuln_id: string; // The human-readable display ID (e.g., CVE-2026-3592)
  score: number;
  severity?: string;
  status: string; // PENDING, IN_PROGRESS, WAITING_FOR_APPROVAL, RESOLVED
  active_step?: string;
}

const PIPELINE_STEPS = [
  "Parsing",
  "Normalization",
  "Prioritization",
  "Remediation",
  "Resolved",
];

const REMEDIATION_STEPS = [
  { id: "generate_remediation_script", label: "Root Cause Analysis (RCA)" },
  { id: "create_prompt", label: "Patch Script Generation" },
  { id: "github_workflow", label: "Automated PR Deployment" },
  { id: "check_ci_status", label: "Security Validation" },
  { id: "wait_for_human_approval", label: "Waiting for Human Approval" },
  { id: "calculate_tokens_and_cost_consumption", label: "Resolved" },
];

export default function RemediationCommandCenter() {
  const [fileUploaded, setFileUploaded] = useState(false);
  const [pipelineStep, setPipelineStep] = useState<number>(0);
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [expandedVulnId, setExpandedVulnId] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Add this right below your other state declarations (around line 45)
  const [pendingFiles, setPendingFiles] = useState<File[]>([]);

  // Auto-advance to final pipeline step when everything is resolved
  useEffect(() => {
    if (
      vulnerabilities.length > 0 &&
      vulnerabilities.every((v) => v.status === "RESOLVED")
    ) {
      setPipelineStep(4);
    }
  }, [vulnerabilities]);

  // --- NEW: PERSISTENCE SYNC ON LOAD ---
  useEffect(() => {
    const syncState = async () => {
      try {
        const response = await fetch(
          "http://127.0.0.1:8000/api/v1/system-state",
        );
        const data = await response.json();

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
          setFileUploaded(true);

          const formattedVulns = data.vulnerabilities.map((v: any) => {
            const score = v.score || 0;
            return {
              ...v,
              severity:
                v.severity ||
                (score >= 9
                  ? "Critical"
                  : score >= 7
                    ? "High"
                    : score >= 4
                      ? "Medium"
                      : "Low"),
            };
          });

          // 👇 UPDATE THIS LINE to use formattedVulns instead of data.vulnerabilities
          setVulnerabilities(formattedVulns);
          // If an active task is found, expand it automatically
          if (data.active_task) {
            setExpandedVulnId(data.active_task.thread_id);
          }
        }
      } catch (err) {
        console.warn("Could not sync with backend. Is the server running?");
      }
    };
    syncState();
  }, []);

  // --- WEBSOCKET CONNECTION ---
  useEffect(() => {
    let ws: WebSocket | null = null;
    let isComponentMounted = true;
    let reconnectTimer: NodeJS.Timeout;

    const connectWebSocket = () => {
      if (ws && ws.readyState !== WebSocket.CLOSED) return;

      ws = new WebSocket("ws://127.0.0.1:8000/api/v1/ws/updates");
      socketRef.current = ws;

      ws.onopen = () => {
        setLogs((prev) =>
          prev.some((l) => l.text.includes("Terminal Linked"))
            ? prev
            : [
                ...prev,
                {
                  time: new Date().toLocaleTimeString(),
                  text: "[SYSTEM] Terminal Linked to Backend Orchestrator.",
                },
              ],
        );
      };

      ws.onmessage = (event) => {
        try {
          // const data = JSON.parse(event.data);
          const safeData = event.data.replace(/:\s*NaN/g, ": null");
          const data = JSON.parse(safeData);

          // 1. Pipeline General Updates
          if (data.step && PIPELINE_STEPS.includes(data.step)) {
            setPipelineStep(PIPELINE_STEPS.indexOf(data.step));
          }

          // 2. Console Logs
          if (data.log) {
            setLogs((prev) => [
              ...prev,
              { time: new Date().toLocaleTimeString(), text: data.log },
            ]);
          }

          // 3. Queue Initialization
          if (data.type === "BATCH_READY" || data.type === "NEW_BATCH") {
            const incomingVulns = data.top_vulnerabilities || data.tasks || [];
            const formattedVulns = incomingVulns.map((v: any) => {
              const score = v.score || v.priority_score || 0;
              return {
                ...v,
                thread_id: v.thread_id,
                asset_id: v.asset_id, // Use for tracking
                vuln_id: v.vuln_id || v.cve_id || v.asset_id, // Use for UI display (fallback to asset_id if CVE missing)
                score: score,
                severity:
                  v.severity ||
                  (score >= 9
                    ? "Critical"
                    : score >= 7
                      ? "High"
                      : score >= 4
                        ? "Medium"
                        : "Low"),
                status: v.status || "PENDING",
              };
            });
            setVulnerabilities(formattedVulns);
            setPipelineStep(3);
          }

          // 4. Unified Vulnerability State Updates (tracked by asset_id)
          const currentId = data.thread_id;

          if (currentId) {
            setVulnerabilities((prev) => {
              const exists = prev.find((v) => v.thread_id === currentId);

              // Determine active step mapping
              let updatedStep =
                exists?.active_step || "generate_remediation_script";
              if (
                data.node &&
                REMEDIATION_STEPS.some((step) => step.id === data.node)
              ) {
                updatedStep = data.node;
              }

              // Determine exact status
              let updatedStatus =
                data.status || exists?.status || "IN_PROGRESS";

              // Handle specific backend overrides seamlessly
              if (
                data.type === "ACTION_REQUIRED" ||
                data.node === "wait_for_human_approval"
              ) {
                updatedStatus = "WAITING_FOR_APPROVAL";
                updatedStep = "wait_for_human_approval";
              } else if (
                data.status === "COMPLETED" ||
                data.node === "calculate_tokens_and_cost_consumption"
              ) {
                updatedStatus = "RESOLVED";
                updatedStep = "calculate_tokens_and_cost_consumption";
              }

              if (exists) {
                return prev.map((v) =>
                  v.thread_id === currentId
                    ? { ...v, status: updatedStatus, active_step: updatedStep }
                    : v,
                );
              } else {
                const incomingScore = data.score || 0;
                const dynamicSeverity =
                  incomingScore >= 9
                    ? "Critical"
                    : incomingScore >= 7
                      ? "High"
                      : incomingScore >= 4
                        ? "Medium"
                        : "Low";

                return [
                  ...prev,
                  {
                    thread_id: currentId,
                    asset_id: data.asset_id || "Unknown",
                    vuln_id: data.vuln_id || currentId,
                    score: incomingScore,
                    severity: dynamicSeverity,
                    status: updatedStatus,
                    active_step: updatedStep,
                  },
                ];
              }
            });

            // Keep accordion focused on the active task
            if (
              data.status === "IN_PROGRESS" ||
              data.type === "ACTION_REQUIRED"
            ) {
              setExpandedVulnId(currentId);
            }
          }

          // 5. System Reset
          if (data.type === "QUEUE_CLEARED") {
            setPipelineStep(0);
            setVulnerabilities([]);
            setLogs([]);
          }
        } catch (e) {
          console.error("Failed to parse WS payload:", e);
        }
      };

      ws.onclose = () => {
        if (isComponentMounted) {
          reconnectTimer = setTimeout(connectWebSocket, 3000);
        }
      };

      ws.onerror = () => {};
    };

    connectWebSocket();

    return () => {
      isComponentMounted = false;
      clearTimeout(reconnectTimer);
      if (ws) {
        ws.close();
      }
    };
  }, []);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Triggered when the user selects files via the file dialog
  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setPendingFiles(Array.from(event.target.files));
    }
  };

  // Clears the selected files
  const handleClearFiles = () => {
    setPendingFiles([]);
    // Reset the actual input value so the same file can be selected again if needed
    const fileInput = document.getElementById(
      "file-upload",
    ) as HTMLInputElement;
    if (fileInput) fileInput.value = "";
  };

  // Triggers the actual backend pipeline upload
  const handleSubmitFiles = async () => {
    if (pendingFiles.length === 0) return;

    setFileUploaded(true);
    setLogs([
      {
        time: new Date().toLocaleTimeString(),
        text: `[SYSTEM] Initiating upload for ${pendingFiles.length} file(s)...`,
      },
    ]);
    setPipelineStep(0);

    const formData = new FormData();
    pendingFiles.forEach((file) => {
      formData.append("files", file);
    });

    try {
      await fetch("http://127.0.0.1:8000/api/v1/upload", {
        method: "POST",
        body: formData,
      });
      setPendingFiles([]); // Clear pending state after successful dispatch
    } catch (error) {
      console.error("Upload failed", error);
      setLogs((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          text: "[CRITICAL ERROR] Failed to connect to backend upload endpoint.",
        },
      ]);
      setFileUploaded(false); // Revert UI so they can try again
    }
  };

  const handleProcessNewData = () => {
    setFileUploaded(false);
    setPipelineStep(0);
    setLogs([
      {
        time: new Date().toLocaleTimeString(),
        text: "[SYSTEM] Ready for new payload.",
      },
    ]);
    setVulnerabilities([]);
    setExpandedVulnId(null);
  };

  // --- HELPERS ---
  const getStepStatus = (
    vuln: Vulnerability,
    stepId: string,
    index: number,
  ) => {
    if (vuln.status === "RESOLVED") return "completed";

    const currentIndex = REMEDIATION_STEPS.findIndex(
      (s) => s.id === vuln.active_step,
    );

    if (currentIndex > index) return "completed";
    if (currentIndex === index && vuln.status === "WAITING_FOR_APPROVAL")
      return "waiting";
    if (currentIndex === index) return "active";
    return "pending";
  };

  const getSeverityBadge = (severity?: string, score?: number) => {
    const s = severity?.toLowerCase();
    if (s === "critical" || (score && score >= 9.0))
      return "bg-red-100 text-red-700 border-red-200";
    if (s === "high" || (score && score >= 7.0))
      return "bg-orange-100 text-orange-700 border-orange-200";
    if (s === "medium" || (score && score >= 4.0))
      return "bg-amber-100 text-amber-700 border-amber-200";
    return "bg-slate-100 text-slate-700 border-slate-200";
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans p-6 selection:bg-indigo-100">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* HEADER & PIPELINE */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200/60 p-6">
          <div className="flex items-center justify-between mb-8">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
              <ShieldAlert className="w-6 h-6 text-indigo-600" />
              Remediation Command Center
            </h1>
            <button
              onClick={handleProcessNewData}
              className="flex items-center gap-2 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 px-4 py-2 rounded-md text-sm font-medium transition-all shadow-sm"
            >
              <RotateCcw className="w-4 h-4" />
              Process New Data
            </button>
          </div>

          {!fileUploaded ? (
            <div className="border-2 border-dashed border-slate-300 rounded-xl p-16 text-center hover:bg-slate-50 transition-colors bg-slate-50/50">
              <input
                type="file"
                id="file-upload"
                className="hidden"
                multiple
                onChange={handleFileSelect} // Updated to use the new select handler
              />

              {pendingFiles.length === 0 ? (
                /* --- DEFAULT DRAG & DROP STATE --- */
                <label
                  htmlFor="file-upload"
                  className="cursor-pointer flex flex-col items-center py-6"
                >
                  <div className="h-16 w-16 bg-white border border-slate-200 shadow-sm rounded-full flex items-center justify-center mb-4">
                    <UploadCloud className="h-8 w-8 text-indigo-600" />
                  </div>
                  <span className="text-lg font-semibold text-slate-700">
                    Drag & Drop Scan Results
                  </span>
                  <span className="text-sm text-slate-500 mt-1">
                    Supports Trivy, Nessus, JSON, or XML payloads
                  </span>
                </label>
              ) : (
                /* --- FILES SELECTED STATE WITH BUTTONS --- */
                <div className="flex flex-col items-center">
                  <div className="h-16 w-16 bg-indigo-50 border border-indigo-100 rounded-full flex items-center justify-center mb-4">
                    <CheckCircle2 className="h-8 w-8 text-indigo-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-slate-800 mb-3">
                    {pendingFiles.length} File(s) Ready
                  </h3>

                  {/* File Preview List */}
                  <div className="flex flex-col gap-2 mb-6 w-full max-w-sm text-left max-h-32 overflow-y-auto">
                    {pendingFiles.map((file, idx) => (
                      <div
                        key={idx}
                        className="text-sm text-slate-600 bg-white border border-slate-200 px-3 py-2 rounded-md shadow-sm truncate"
                      >
                        {file.name}
                      </div>
                    ))}
                  </div>

                  {/* Submit & Clear Buttons */}
                  <div className="flex gap-4">
                    <button
                      onClick={handleClearFiles}
                      className="px-6 py-2.5 border border-slate-300 rounded-lg text-slate-700 hover:bg-slate-100 font-semibold transition-colors"
                    >
                      Clear
                    </button>
                    <button
                      onClick={handleSubmitFiles}
                      className="px-6 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-semibold transition-colors shadow-sm flex items-center gap-2"
                    >
                      Start Pipeline
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-between max-w-4xl mx-auto pt-4 relative">
              <div className="absolute top-1/2 left-4 right-4 h-[2px] bg-indigo-600 -z-10 -translate-y-1/2"></div>
              <div
                className="absolute top-1/2 left-4 text-indigo-600 h-[2px] bg-indigo-600 -z-10 -translate-y-1/2 transition-all duration-500 ease-in-out"
                style={{
                  width: `${(pipelineStep / (PIPELINE_STEPS.length - 1)) * 100}%`,
                }}
              ></div>

              {PIPELINE_STEPS.map((step, idx) => {
                const isActive = pipelineStep === idx;
                const isCompleted = pipelineStep > idx;
                return (
                  <div
                    key={step}
                    className="flex flex-col items-center px-2 bg-white"
                  >
                    <div
                      className={`h-10 w-10 rounded-full flex items-center justify-center border-2 mb-3 bg-white transition-all duration-300 shadow-sm
                      ${isCompleted ? "border-indigo-600 bg-indigo-600 text-white" : isActive ? "border-indigo-600 text-indigo-600 ring-4 ring-indigo-50" : "border-slate-200 text-slate-400"}`}
                    >
                      {isCompleted ? (
                        <Check
                          className="h-5 w-5 text-indigo-600"
                          strokeWidth={3}
                        />
                      ) : (
                        <span className="font-semibold text-sm">{idx + 1}</span>
                      )}
                    </div>
                    <span
                      className={`text-sm font-semibold tracking-tight ${isActive ? "text-indigo-900" : isCompleted ? "text-slate-800" : "text-slate-400"}`}
                    >
                      {step}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* MAIN LAYOUT */}
        {fileUploaded && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[750px]">
            {/* LEFT SIDE: VULNERABILITY QUEUE */}
            <div className="col-span-1 lg:col-span-5 bg-white rounded-xl shadow-sm border border-slate-200/60 flex flex-col overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/80 backdrop-blur-sm">
                <h2 className="font-semibold text-slate-800 tracking-tight">
                  Active Queue
                </h2>
                <span className="text-xs font-bold bg-slate-200/70 text-slate-700 px-2.5 py-1 rounded-md">
                  {
                    vulnerabilities.filter((v) => v.status !== "RESOLVED")
                      .length
                  }{" "}
                  Pending
                </span>
              </div>

              <div className="flex-1 overflow-y-auto p-3 space-y-3 bg-slate-50/30">
                {vulnerabilities.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-slate-400 text-sm font-medium">
                    Booting automation pipeline...
                  </div>
                ) : (
                  vulnerabilities.map((vuln) => (
                    <div
                      key={vuln.thread_id} // Used asset_id for mapping key
                      className="bg-white border border-slate-200/80 rounded-xl shadow-sm overflow-hidden transition-all duration-200 hover:shadow-md"
                    >
                      {/* ACCORDION HEADER */}
                      <div
                        className={`p-4 cursor-pointer flex flex-col transition-colors
                          ${expandedVulnId === vuln.thread_id ? "bg-indigo-50/30 border-b border-slate-100" : ""}`}
                        onClick={() =>
                          setExpandedVulnId(
                            vuln.thread_id === expandedVulnId
                              ? null
                              : vuln.thread_id,
                          )
                        }
                      >
                        <div className="flex justify-between items-start mb-2">
                          <div className="flex items-center gap-3">
                            {vuln.status === "RESOLVED" ? (
                              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                            ) : vuln.status ===
                              "FAILED" /* 👇 ADD THIS CHECK */ ? (
                              <ShieldAlert className="h-5 w-5 text-red-500" />
                            ) : vuln.status === "IN_PROGRESS" ||
                              vuln.status === "WAITING_FOR_APPROVAL" ? (
                              <Loader2 className="h-5 w-5 text-indigo-600 animate-spin" />
                            ) : (
                              <Circle className="h-5 w-5 text-slate-300" />
                            )}
                            <span className="font-bold text-slate-900 tracking-tight">
                              {vuln.vuln_id} {/* Human readable CVE display! */}
                            </span>
                          </div>

                          {/* DYNAMIC STATUS BADGE */}
                          <span
                            className={`text-[11px] uppercase tracking-wider font-bold px-2.5 py-1 rounded-md border 
                            ${
                              vuln.status === "RESOLVED"
                                ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                                : vuln.status === "FAILED"
                                  ? "bg-red-50 text-red-700 border-red-200" /* 👇 ADD THIS RED STYLE */
                                  : vuln.status === "WAITING_FOR_APPROVAL"
                                    ? "bg-amber-50 text-amber-700 border-amber-200"
                                    : vuln.status === "IN_PROGRESS"
                                      ? "bg-indigo-50 text-indigo-700 border-indigo-200"
                                      : "bg-slate-50 text-slate-600 border-slate-200"
                            }`}
                          >
                            {vuln.status.replace(/_/g, " ")}
                          </span>
                        </div>

                        {/* METADATA BADGES */}
                        <div className="flex gap-2 pl-8">
                          <span
                            className={`text-xs font-semibold px-2 py-0.5 rounded border ${getSeverityBadge(vuln.severity, vuln.score)}`}
                          >
                            {vuln.severity || "Unknown"}
                          </span>
                          <span className="text-xs font-medium px-2 py-0.5 rounded border bg-slate-50 text-slate-600 border-slate-200">
                            CVSS: {vuln.score.toFixed(1)}
                          </span>
                        </div>
                      </div>

                      {/* REMEDIATION ACCORDION CONTENT */}
                      {expandedVulnId === vuln.thread_id && (
                        <div className="p-5 bg-white space-y-5">
                          {REMEDIATION_STEPS.map((step, idx) => {
                            const status = getStepStatus(vuln, step.id, idx);
                            const isLast = idx === REMEDIATION_STEPS.length - 1;

                            return (
                              <div
                                key={step.id}
                                className="relative flex items-start gap-4"
                              >
                                {/* Vertical Connecting Line */}
                                {!isLast && (
                                  <div
                                    className={`absolute left-[9px] top-6 bottom-[-24px] w-[2px] rounded-full 
                                    ${status === "completed" ? "bg-indigo-600" : "bg-slate-100"}`}
                                  />
                                )}

                                <div className="relative z-10 flex-shrink-0 mt-0.5 bg-white">
                                  {status === "completed" && (
                                    <CheckCircle2 className="h-5 w-5 text-indigo-600 fill-indigo-50" />
                                  )}
                                  {status === "active" && (
                                    <Loader2 className="h-5 w-5 text-indigo-600 animate-spin" />
                                  )}
                                  {status === "waiting" && (
                                    <Circle className="h-5 w-5 text-amber-500 fill-amber-50" />
                                  )}
                                  {status === "pending" && (
                                    <Circle className="h-5 w-5 text-slate-200" />
                                  )}
                                </div>

                                <div className="flex-1 pb-1">
                                  <p
                                    className={`text-sm font-semibold tracking-tight ${status === "pending" ? "text-slate-400" : "text-slate-800"}`}
                                  >
                                    {step.label}
                                  </p>

                                  {/* GITHUB WAIT STATE UI */}
                                  {status === "waiting" &&
                                    step.id === "wait_for_human_approval" && (
                                      <div className="mt-3 p-4 bg-amber-50/50 border border-amber-200/60 rounded-lg flex items-start gap-3 shadow-sm">
                                        <ExternalLink className="h-5 w-5 text-amber-600 mt-0.5 flex-shrink-0" />
                                        <div>
                                          <h4 className="text-sm font-semibold text-amber-900">
                                            Action Required in GitHub
                                          </h4>
                                          <p className="text-xs text-amber-700/80 mt-1 leading-relaxed">
                                            The AI has successfully pushed a
                                            remediation patch. Please review and
                                            merge the Pull Request to continue
                                            the deployment pipeline.
                                          </p>
                                        </div>
                                      </div>
                                    )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* RIGHT SIDE: UNIVERSAL AGENT CONSOLE */}
            <div className="col-span-1 lg:col-span-7 bg-[#0a0a0a] rounded-xl shadow-xl border border-slate-800 flex flex-col overflow-hidden font-mono text-[13px] leading-relaxed">
              <div className="bg-[#111111] px-4 py-3 flex items-center border-b border-slate-800/80">
                <div className="flex space-x-2 mr-4">
                  <div className="h-3 w-3 rounded-full bg-red-500/80 border border-red-600"></div>
                  <div className="h-3 w-3 rounded-full bg-amber-500/80 border border-amber-600"></div>
                  <div className="h-3 w-3 rounded-full bg-emerald-500/80 border border-emerald-600"></div>
                </div>
                <h2 className="text-slate-400 text-xs font-semibold tracking-widest uppercase">
                  Agent Execution Stream
                </h2>
              </div>

              <div className="flex-1 p-5 overflow-y-auto space-y-2.5">
                {logs.map((log, i) => (
                  <div
                    key={i}
                    className="flex gap-4 hover:bg-white/5 p-1 -mx-1 rounded transition-colors"
                  >
                    <span className="text-slate-600 flex-shrink-0 select-none">
                      {log.time}
                    </span>
                    <span
                      className={`break-words ${
                        log.text.includes("[CRITICAL")
                          ? "text-red-400 font-semibold"
                          : log.text.includes("[WARNING]")
                            ? "text-amber-400"
                            : log.text.includes("[SYSTEM]")
                              ? "text-slate-300"
                              : log.text.includes("[AGENT]")
                                ? "text-indigo-400"
                                : log.text.includes("[GIT]")
                                  ? "text-fuchsia-400"
                                  : log.text.includes("[AWS S3]")
                                    ? "text-orange-400"
                                    : log.text.includes("[QUEUE]")
                                      ? "text-cyan-400 font-bold"
                                      : "text-emerald-400"
                      }`}
                    >
                      {log.text}
                    </span>
                  </div>
                ))}
                {/* Blinking cursor */}
                <div className="flex mt-3 items-center">
                  <span className="text-emerald-500 font-bold mr-2 select-none">
                    agent@hpe:~$
                  </span>
                  <span className="w-2 h-4 bg-emerald-500 animate-pulse"></span>
                </div>
                <div ref={logsEndRef} />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
