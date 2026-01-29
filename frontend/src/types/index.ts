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
  totp_enabled?: boolean;
  is_external?: boolean;
  external_provider?: string | null;
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
  expires_in?: number;
  user: User;
  requires_2fa?: boolean;
  pending_token?: string;
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

export interface DeviceSyncRequest {
  source: string;
  overwrite_existing: boolean;
}

export interface DeviceSyncResponse {
  success: boolean;
  total_devices: number;
  updated_devices: number;
  skipped_devices: number;
  source: string;
  details: Array<{
    device_id: string;
    mac_address: string;
    old_hostname: string;
    new_hostname: string;
    matched_by: string;
  }>;
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
export type SourceType = 'api_pull' | 'file_watch' | 'api_push' | 'udp_listen';
export type ParserType = 'adguard' | 'authentik' | 'unifi' | 'pfsense' | 'json' | 'syslog' | 'nginx' | 'custom' | 'ollama' | 'endpoint' | 'netflow' | 'sflow' | 'loki';

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

// Detection Rule types
export interface RuleCondition {
  field: string;
  operator: string;
  value: unknown;
}

export interface RuleConditionGroup {
  logic: 'and' | 'or';
  conditions: RuleCondition[];
}

export interface RuleAction {
  type: string;
  config: Record<string, unknown>;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string | null;
  severity: AlertSeverity;
  enabled: boolean;
  conditions: RuleConditionGroup;
  response_actions: RuleAction[];
  cooldown_minutes: number;
  created_at: string;
  updated_at: string;
}

export interface DetectionRuleListResponse {
  items: DetectionRule[];
  total: number;
}

export interface CreateRuleRequest {
  id: string;
  name: string;
  description?: string;
  severity: AlertSeverity;
  enabled?: boolean;
  conditions: RuleConditionGroup;
  response_actions?: RuleAction[];
  cooldown_minutes?: number;
}

export interface UpdateRuleRequest {
  name?: string;
  description?: string;
  severity?: AlertSeverity;
  enabled?: boolean;
  conditions?: RuleConditionGroup;
  response_actions?: RuleAction[];
  cooldown_minutes?: number;
}

export interface ConditionFieldInfo {
  name: string;
  description: string;
  type: string;
  example_values?: string[];
}

export interface TestRuleRequest {
  conditions: RuleConditionGroup;
  event: Record<string, unknown>;
}

export interface TestRuleResponse {
  matches: boolean;
  condition_results: Array<{
    field: string;
    operator: string;
    expected: unknown;
    actual: unknown;
    result: boolean;
  }>;
}

// Threat Intelligence types
export type FeedType = 'csv' | 'json' | 'stix' | 'url_list' | 'ip_list';
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'cidr';

export interface ThreatIntelFeed {
  id: string;
  name: string;
  description: string | null;
  feed_type: FeedType;
  url: string;
  enabled: boolean;
  update_interval_hours: number;
  auth_type: string;
  auth_config: Record<string, unknown>;
  field_mapping: Record<string, unknown>;
  last_fetch_at: string | null;
  last_fetch_status: string | null;
  last_fetch_message: string | null;
  indicator_count: number;
  created_at: string;
  updated_at: string;
}

export interface ThreatIndicator {
  id: string;
  feed_id: string;
  feed_name: string | null;
  indicator_type: IndicatorType;
  value: string;
  confidence: number;
  severity: string;
  tags: string[];
  description: string | null;
  source_ref: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  expires_at: string | null;
  metadata: Record<string, unknown>;
  hit_count: number;
  last_hit_at: string | null;
  created_at: string;
}

export interface ThreatIntelFeedListResponse {
  items: ThreatIntelFeed[];
  total: number;
}

export interface ThreatIndicatorListResponse {
  items: ThreatIndicator[];
  total: number;
}

export interface CreateFeedRequest {
  name: string;
  description?: string;
  feed_type: FeedType;
  url: string;
  enabled?: boolean;
  update_interval_hours?: number;
  auth_type?: string;
  auth_config?: Record<string, unknown>;
  field_mapping?: Record<string, unknown>;
}

export interface UpdateFeedRequest {
  name?: string;
  description?: string;
  feed_type?: FeedType;
  url?: string;
  enabled?: boolean;
  update_interval_hours?: number;
  auth_type?: string;
  auth_config?: Record<string, unknown>;
  field_mapping?: Record<string, unknown>;
}

export interface IndicatorCheckRequest {
  value: string;
  indicator_type?: IndicatorType;
}

export interface IndicatorCheckResponse {
  found: boolean;
  matches: ThreatIndicator[];
}

export interface ThreatIntelStats {
  total_feeds: number;
  enabled_feeds: number;
  total_indicators: number;
  indicators_by_type: Record<string, number>;
  indicators_by_severity: Record<string, number>;
  recent_hits: number;
}

// Network Topology types
export interface TopologyNode {
  id: string;
  label: string;
  type: string;
  status: string;
  ip_address?: string;
  mac_address?: string;
  manufacturer?: string;
  device_type?: string;
  event_count_24h: number;
  tags: string[];
  is_quarantined: boolean;
}

export interface TopologyLink {
  source: string;
  target: string;
  traffic_volume: number;
  link_type: string;
}

export interface TopologyData {
  nodes: TopologyNode[];
  links: TopologyLink[];
  stats: {
    total_devices: number;
    active_devices: number;
    quarantined_devices: number;
    total_events: number;
    time_window_hours: number;
  };
}

// Semantic Analysis types
export type LLMProvider = 'claude' | 'ollama';
export type SuggestedRuleStatus = 'pending' | 'approved' | 'rejected' | 'implemented';
export type SuggestedRuleType = 'pattern_match' | 'threshold' | 'sequence';

export interface SemanticAnalysisConfig {
  id: string;
  source_id: string;
  enabled: boolean;
  llm_provider: LLMProvider;
  ollama_model: string | null;
  rarity_threshold: number;
  batch_size: number;
  batch_interval_minutes: number;
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface UpdateSemanticConfigRequest {
  enabled?: boolean;
  llm_provider?: LLMProvider;
  ollama_model?: string;
  rarity_threshold?: number;
  batch_size?: number;
  batch_interval_minutes?: number;
}

export interface LogPattern {
  id: string;
  source_id: string;
  normalized_pattern: string;
  pattern_hash: string;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  is_ignored: boolean;
  created_at: string;
  updated_at: string;
}

export interface LogPatternListResponse {
  items: LogPattern[];
  total: number;
}

export interface IrregularLog {
  id: string;
  event_id: string;
  event_timestamp: string;
  source_id: string;
  pattern_id: string | null;
  reason: string;
  llm_reviewed: boolean;
  llm_response: string | null;
  severity_score: number | null;
  reviewed_by_user: boolean;
  reviewed_at: string | null;
  created_at: string;
}

export interface IrregularLogListResponse {
  items: IrregularLog[];
  total: number;
}

export interface SemanticAnalysisRun {
  id: string;
  source_id: string;
  started_at: string;
  completed_at: string | null;
  status: 'running' | 'completed' | 'failed';
  events_scanned: number;
  irregulars_found: number;
  llm_provider: LLMProvider;
  llm_response_summary: string | null;
  error_message: string | null;
  created_at: string;
}

export interface SemanticAnalysisRunListResponse {
  items: SemanticAnalysisRun[];
}

export interface TriggerAnalysisResponse {
  run_id: string;
  status: string;
  message: string;
}

export interface SemanticStats {
  total_patterns: number;
  total_irregular_logs: number;
  pending_review: number;
  high_severity_count: number;
  last_run_at: string | null;
  last_run_status: string | null;
}

export interface SuggestedRule {
  id: string;
  source_id: string | null;
  analysis_run_id: string;
  irregular_log_id: string;
  name: string;
  description: string;
  reason: string;
  benefit: string;
  rule_type: SuggestedRuleType;
  rule_config: Record<string, unknown>;
  status: SuggestedRuleStatus;
  enabled: boolean;
  rule_hash: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  rejection_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface SuggestedRuleListResponse {
  items: SuggestedRule[];
  total: number;
}

export interface ApproveRuleRequest {
  enable: boolean;
  config_overrides?: Record<string, unknown>;
}

export interface RejectRuleRequest {
  reason: string;
}

export interface SuggestedRuleHistory {
  id: string;
  rule_hash: string;
  original_rule_id: string;
  status: SuggestedRuleStatus;
  created_at: string;
}

export interface SuggestedRuleHistoryListResponse {
  items: SuggestedRuleHistory[];
}
