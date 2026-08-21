export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ScannerType = 'zap' | 'nuclei' | 'semgrep' | 'trivy';
export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type FindingStatus = 'OPEN' | 'FIXED' | 'STILL_PRESENT' | 'FALSE_POSITIVE' | 'IGNORED';

export interface Finding {
  id: string;
  title: string;
  description?: string;
  severity: SeverityLevel;
  scanner: ScannerType | string;
  cwe?: string;
  owasp?: string;
  cvss_score?: number;
  confidence?: string;
  url?: string;
  file_path?: string;
  line_number?: number;
  evidence?: string;
  remediation?: string;
  reference?: string;
  status: FindingStatus | string;
  fingerprint?: string;
  created_at?: string;
  updated_at?: string;
  scan_id?: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  open?: number;
  fixed?: number;
}

export interface Scan {
  id: string;
  target: string;
  scanners: (ScannerType | string)[];
  options?: Record<string, any>;
  timeout?: number;
  status: ScanStatus;
  progress?: number;
  findings_count?: number;
  summary?: ScanSummary;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  duration_seconds?: number;
}

export interface ScanLog {
  timestamp: string;
  level: 'INFO' | 'WARNING' | 'ERROR' | 'SUCCESS';
  message: string;
}

export interface SecurityOverviewStats {
  posture_score: number;
  rating: string;
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  total_findings: number;
  open_findings: number;
  fixed_findings: number;
  fix_rate_percent: number;
  severity_breakdown: ScanSummary;
  scanners_status: {
    name: string;
    type: string;
    status: 'online' | 'offline' | 'busy';
    description: string;
  }[];
}

export interface FindingAnalysisResult {
  summary: string;
  business_impact: string;
  remediation_steps: string[];
  code_example: string | null;
  false_positive_likelihood: 'LOW' | 'MEDIUM' | 'HIGH' | string;
  false_positive_reasoning: string;
}

export interface RetestResponse {
  retest_id: string;
  finding_id: string;
  previous_status: string;
  new_status: string;
  duration_ms: number;
  notes: string;
  fingerprints_before: string[];
  fingerprints_after: string[];
}

export interface TargetScope {
  id: string;
  url: string;
  label?: string;
  target_type?: string;
  scope_rules: string[];
  is_active: boolean;
  created_at: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  provider?: string;
}

/* WebSocket Event Interfaces */
export interface WSBaseEvent {
  event: string;
  scan_id: string;
  timestamp?: string;
  data: Record<string, any>;
}

export interface WSScanStarted extends WSBaseEvent {
  event: 'SCAN_STARTED';
  data: {
    target: string;
    scanners: string[];
    message: string;
  };
}

export interface WSJobProgress extends WSBaseEvent {
  event: 'JOB_PROGRESS';
  data: {
    scanner: string;
    status: string;
    progress_percent: number;
    message: string;
  };
}

export interface WSJobCompleted extends WSBaseEvent {
  event: 'JOB_COMPLETED';
  data: {
    scanner: string;
    status: string;
    exit_code: number;
    findings_count: number;
    duration_ms: number;
    message: string;
  };
}

export interface WSScanFinished extends WSBaseEvent {
  event: 'SCAN_FINISHED';
  data: {
    status: string;
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    duration_ms: number;
    message: string;
  };
}

export interface WSErrorEvent extends WSBaseEvent {
  event: 'ERROR';
  data: {
    error: string;
    scanner?: string;
  };
}

export type WSEvent = WSScanStarted | WSJobProgress | WSJobCompleted | WSScanFinished | WSErrorEvent | WSBaseEvent;
