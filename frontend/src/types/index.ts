// User types
export type UserRole = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  must_change_password: boolean;
  last_login: string | null;
  created_at: string;
}

export interface UserListResponse {
  items: User[];
  total: number;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  role: UserRole;
}

export interface UpdateUserRequest {
  email?: string;
  role?: UserRole;
  is_active?: boolean;
}

export interface PasswordResetResponse {
  temporary_password: string;
  message: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

// Device types
export type DeviceStatus = 'active' | 'inactive' | 'quarantined' | 'unknown';

export interface Device {
  id: string;
  mac_address: string;
  ip_addresses: string[];
  hostname: string | null;
  manufacturer: string | null;
  device_type: string | null;
  profile_tags: string[];
  status: DeviceStatus;
  first_seen: string;
  last_seen: string;
  baseline_ready: boolean;
  notes: string | null;
}

export interface DeviceListResponse {
  items: Device[];
  total: number;
}

// Event types
export type EventType = 'dns' | 'firewall' | 'auth' | 'http' | 'system' | 'unknown';
export type EventSeverity = 'debug' | 'info' | 'warning' | 'error' | 'critical';

export interface RawEvent {
  id: string;
  timestamp: string;
  source_id: string;
  event_type: EventType;
  severity: EventSeverity;
  client_ip: string | null;
  target_ip: string | null;
  domain: string | null;
  port: number | null;
  protocol: string | null;
  action: string | null;
  raw_message: string;
  parsed_fields: Record<string, unknown>;
  device_id: string | null;
}

export interface EventListResponse {
  items: RawEvent[];
  total: number;
}

// Alert types
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'new' | 'acknowledged' | 'resolved' | 'false_positive';

export interface Alert {
  id: string;
  timestamp: string;
  device_id: string | null;
  rule_id: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  llm_analysis: Record<string, unknown> | null;
  status: AlertStatus;
  actions_taken: Record<string, unknown>[];
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved_by: string | null;
  resolved_at: string | null;
}

export interface AlertListResponse {
  items: Alert[];
  total: number;
}

// Log Source types
export type SourceType = 'api_pull' | 'file_watch' | 'api_push';
export type ParserType = 'adguard' | 'unifi' | 'pfsense' | 'json' | 'syslog' | 'nginx' | 'custom';

export interface CreateSourceRequest {
  id: string;
  name: string;
  description?: string;
  source_type: SourceType;
  parser_type: ParserType;
  config: Record<string, unknown>;
  parser_config?: Record<string, unknown>;
}

export interface LogSource {
  id: string;
  name: string;
  description: string | null;
  source_type: SourceType;
  enabled: boolean;
  config: Record<string, unknown>;
  parser_type: ParserType;
  parser_config: Record<string, unknown>;
  api_key: string | null;
  last_event_at: string | null;
  last_error: string | null;
  event_count: number;
  created_at: string;
}

export interface LogSourceListResponse {
  items: LogSource[];
  total: number;
}

// Stats types
export interface OverviewStats {
  device_count: number;
  active_devices: number;
  quarantined_devices: number;
  total_events_24h: number;
  dns_queries_24h: number;
  blocked_queries_24h: number;
  block_rate: number;
  active_alerts: number;
  critical_alerts: number;
  source_count: number;
}

export interface TopDomain {
  domain: string;
  count: number;
}

export interface TimelineBucket {
  timestamp: string;
  count: number;
}

export interface DeviceActivity {
  device_id: string;
  hostname: string | null;
  mac_address: string;
  event_count: number;
}

// Baseline types
export type BaselineType = 'dns' | 'traffic' | 'connection';
export type BaselineStatus = 'learning' | 'ready' | 'stale';

export interface DeviceBaseline {
  id: string;
  device_id: string;
  baseline_type: BaselineType;
  status: BaselineStatus;
  metrics: Record<string, unknown>;
  sample_count: number;
  min_samples: number;
  baseline_window_days: number;
  last_calculated: string | null;
  created_at: string;
  updated_at: string;
}

export interface BaselineListResponse {
  items: DeviceBaseline[];
  total: number;
}

export interface BaselineStats {
  total: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
}

// Anomaly types
export type AnomalyType =
  | 'new_domain'
  | 'volume_spike'
  | 'time_anomaly'
  | 'new_connection'
  | 'new_port'
  | 'blocked_spike'
  | 'pattern_change';
export type AnomalyStatus = 'active' | 'reviewed' | 'false_positive' | 'confirmed';

export interface AnomalyDetection {
  id: string;
  device_id: string;
  anomaly_type: AnomalyType;
  severity: AlertSeverity | 'info';
  score: number;
  status: AnomalyStatus;
  description: string;
  details: Record<string, unknown>;
  baseline_comparison: Record<string, unknown>;
  detected_at: string;
  alert_id: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AnomalyListResponse {
  items: AnomalyDetection[];
  total: number;
}

export interface AnomalyStats {
  total: number;
  active: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}

export interface DetectionRunResponse {
  anomalies_detected: number;
  alerts_created: number;
  anomalies: AnomalyDetection[];
}

export interface BulkDetectionResponse {
  devices_checked: number;
  anomalies_detected: number;
  alerts_created: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  errors: number;
}

// Chat types
export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface QueryRequest {
  query: string;
  model?: 'fast' | 'default' | 'deep';
}

export interface QueryResponse {
  query: string;
  response: string;
  model_used: string;
}

export interface ChatRequest {
  messages: ChatMessage[];
  stream?: boolean;
}

export interface ChatResponse {
  response: string;
  model_used: string;
}

export interface LLMStatus {
  enabled: boolean;
  configured: boolean;
  model_default: string;
  model_fast: string;
  model_deep: string;
}

export interface IncidentSummaryRequest {
  alert_ids?: string[];
  anomaly_ids?: string[];
  device_id?: string;
  hours?: number;
}

export interface IncidentSummaryResponse {
  title: string;
  executive_summary: string;
  technical_summary?: string;
  timeline: string[];
  impact_assessment?: string;
  root_cause?: string;
  recommendations: string[];
  severity: string;
  confidence: number;
  alert_count: number;
  anomaly_count: number;
  event_count: number;
}

export interface AnalyzeAlertRequest {
  model?: 'fast' | 'default' | 'deep';
}

export interface LLMAnalysis {
  confidence: number;
  summary: string;
  risk_level: string;
  risk_justification?: string;
  likely_cause?: string;
  recommended_actions: string[];
  false_positive_likelihood: string;
  false_positive_reasoning?: string;
  additional_context?: string;
  error?: string;
}
