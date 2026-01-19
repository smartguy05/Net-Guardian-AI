import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import apiClient from './client';
import { useAuthStore } from '../stores/auth';
import type {
  Alert,
  AlertListResponse,
  AnomalyDetection,
  AnomalyListResponse,
  AnomalyStats,
  BaselineListResponse,
  BaselineStats,
  BulkDetectionResponse,
  ChatMessage,
  ChatResponse,
  CreateUserRequest,
  DetectionRunResponse,
  Device,
  DeviceListResponse,
  EventListResponse,
  IncidentSummaryRequest,
  IncidentSummaryResponse,
  LLMStatus,
  LoginRequest,
  LoginResponse,
  LogSourceListResponse,
  OverviewStats,
  PasswordResetResponse,
  QueryResponse,
  TopDomain,
  UpdateUserRequest,
  User,
  UserListResponse,
} from '../types';

// Auth hooks
export function useLogin() {
  const login = useAuthStore((state) => state.login);

  return useMutation({
    mutationFn: async (credentials: LoginRequest): Promise<LoginResponse> => {
      const formData = new FormData();
      formData.append('username', credentials.username);
      formData.append('password', credentials.password);

      const response = await apiClient.post<LoginResponse>('/auth/login', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      return response.data;
    },
    onSuccess: (data) => {
      login(data.user, data.access_token, data.refresh_token);
    },
  });
}

export function useLogout() {
  const logout = useAuthStore((state) => state.logout);
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      await apiClient.post('/auth/logout');
    },
    onSettled: () => {
      logout();
      queryClient.clear();
    },
  });
}

export function useCurrentUser() {
  return useQuery({
    queryKey: ['currentUser'],
    queryFn: async (): Promise<User> => {
      const response = await apiClient.get('/auth/me');
      return response.data;
    },
  });
}

// Stats hooks
export function useOverviewStats() {
  return useQuery({
    queryKey: ['stats', 'overview'],
    queryFn: async (): Promise<OverviewStats> => {
      const response = await apiClient.get('/stats/overview');
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useTopDomains(hours = 24, limit = 10) {
  return useQuery({
    queryKey: ['stats', 'topDomains', hours, limit],
    queryFn: async (): Promise<TopDomain[]> => {
      const response = await apiClient.get('/stats/dns/top-domains', {
        params: { hours, limit },
      });
      return response.data;
    },
  });
}

// Device hooks
export function useDevices(params?: {
  status?: string;
  page?: number;
  page_size?: number;
  search?: string;
}) {
  return useQuery({
    queryKey: ['devices', params],
    queryFn: async (): Promise<DeviceListResponse> => {
      const response = await apiClient.get('/devices', { params });
      return response.data;
    },
  });
}

export function useDevice(id: string) {
  return useQuery({
    queryKey: ['devices', id],
    queryFn: async (): Promise<Device> => {
      const response = await apiClient.get(`/devices/${id}`);
      return response.data;
    },
    enabled: !!id,
  });
}

export function useQuarantineDevice() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (deviceId: string) => {
      const response = await apiClient.post(`/devices/${deviceId}/quarantine`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });
}

export function useReleaseDevice() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (deviceId: string) => {
      const response = await apiClient.delete(`/devices/${deviceId}/quarantine`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });
}

export function useUpdateDevice() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      id,
      ...data
    }: {
      id: string;
      hostname?: string;
      device_type?: string;
      profile_tags?: string[];
    }) => {
      const response = await apiClient.patch(`/devices/${id}`, data);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['devices', variables.id] });
    },
  });
}

// Event hooks
export function useEvents(params?: {
  source_id?: string;
  event_type?: string;
  severity?: string;
  device_id?: string;
  domain_contains?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['events', params],
    queryFn: async (): Promise<EventListResponse> => {
      const response = await apiClient.get('/events', { params });
      return response.data;
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });
}

export function useDnsEvents(params?: {
  device_id?: string;
  domain_contains?: string;
  blocked_only?: boolean;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['events', 'dns', params],
    queryFn: async (): Promise<EventListResponse> => {
      const response = await apiClient.get('/events/dns', { params });
      return response.data;
    },
    refetchInterval: 10000,
  });
}

// Alert hooks
export function useAlerts(params?: {
  status?: string;
  severity?: string;
  device_id?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: async (): Promise<AlertListResponse> => {
      const response = await apiClient.get('/alerts', { params });
      return response.data;
    },
    refetchInterval: 15000,
  });
}

export function useUpdateAlertStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      alertId,
      status,
    }: {
      alertId: string;
      status: string;
    }) => {
      const response = await apiClient.patch(`/alerts/${alertId}`, { status });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

// Source hooks
export function useSources() {
  return useQuery({
    queryKey: ['sources'],
    queryFn: async (): Promise<LogSourceListResponse> => {
      const response = await apiClient.get('/sources');
      return response.data;
    },
  });
}

export function useCreateSource() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: {
      id: string;
      name: string;
      description?: string;
      source_type: string;
      parser_type: string;
      config: Record<string, unknown>;
      parser_config?: Record<string, unknown>;
    }) => {
      const response = await apiClient.post('/sources', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sources'] });
    },
  });
}

export function useUpdateSource() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      id,
      ...data
    }: {
      id: string;
      name?: string;
      description?: string;
      enabled?: boolean;
      config?: Record<string, unknown>;
      parser_config?: Record<string, unknown>;
    }) => {
      const response = await apiClient.put(`/sources/${id}`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sources'] });
    },
  });
}

export function useDeleteSource() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/sources/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sources'] });
    },
  });
}

export function useTestSource() {
  return useMutation({
    mutationFn: async (id: string): Promise<{
      success: boolean;
      message: string;
      sample_events: Array<Record<string, unknown>>;
    }> => {
      const response = await apiClient.post(`/sources/${id}/test`);
      return response.data;
    },
  });
}

// User hooks (admin only)
export function useUsers(params?: { page?: number; page_size?: number }) {
  return useQuery({
    queryKey: ['users', params],
    queryFn: async (): Promise<UserListResponse> => {
      const response = await apiClient.get('/users', { params });
      return response.data;
    },
  });
}

export function useUser(id: string) {
  return useQuery({
    queryKey: ['users', id],
    queryFn: async (): Promise<User> => {
      const response = await apiClient.get(`/users/${id}`);
      return response.data;
    },
    enabled: !!id,
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: CreateUserRequest): Promise<User> => {
      const response = await apiClient.post('/users', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

export function useUpdateUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      id,
      ...data
    }: UpdateUserRequest & { id: string }): Promise<User> => {
      const response = await apiClient.patch(`/users/${id}`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

export function useDeactivateUser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const response = await apiClient.delete(`/users/${id}`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

export function useResetUserPassword() {
  return useMutation({
    mutationFn: async (id: string): Promise<PasswordResetResponse> => {
      const response = await apiClient.post(`/users/${id}/reset-password`);
      return response.data;
    },
  });
}

// Baseline hooks
export function useBaselines(params?: {
  device_id?: string;
  baseline_type?: string;
  status?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['baselines', params],
    queryFn: async (): Promise<BaselineListResponse> => {
      const response = await apiClient.get('/baselines', { params });
      return response.data;
    },
  });
}

export function useDeviceBaselines(deviceId: string) {
  return useQuery({
    queryKey: ['baselines', 'device', deviceId],
    queryFn: async (): Promise<BaselineListResponse> => {
      const response = await apiClient.get(`/baselines/device/${deviceId}`);
      return response.data;
    },
    enabled: !!deviceId,
  });
}

export function useBaselineStats() {
  return useQuery({
    queryKey: ['baselines', 'stats'],
    queryFn: async (): Promise<BaselineStats> => {
      const response = await apiClient.get('/baselines/stats/summary');
      return response.data;
    },
  });
}

export function useRecalculateBaseline() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      deviceId,
      baselineType,
    }: {
      deviceId: string;
      baselineType?: string;
    }) => {
      const response = await apiClient.post(
        `/baselines/device/${deviceId}/recalculate`,
        null,
        { params: baselineType ? { baseline_type: baselineType } : undefined }
      );
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['baselines'] });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });
}

export function useRecalculateAllBaselines() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await apiClient.post('/baselines/recalculate-all');
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['baselines'] });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });
}

// Anomaly hooks
export function useAnomalies(params?: {
  device_id?: string;
  anomaly_type?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['anomalies', params],
    queryFn: async (): Promise<AnomalyListResponse> => {
      const response = await apiClient.get('/anomalies', { params });
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useActiveAnomalies(minSeverity?: string, limit = 100) {
  return useQuery({
    queryKey: ['anomalies', 'active', minSeverity, limit],
    queryFn: async (): Promise<AnomalyListResponse> => {
      const response = await apiClient.get('/anomalies/active', {
        params: { min_severity: minSeverity, limit },
      });
      return response.data;
    },
    refetchInterval: 15000, // Refresh every 15 seconds
  });
}

export function useDeviceAnomalies(
  deviceId: string,
  params?: { status?: string; anomaly_type?: string; limit?: number }
) {
  return useQuery({
    queryKey: ['anomalies', 'device', deviceId, params],
    queryFn: async (): Promise<AnomalyListResponse> => {
      const response = await apiClient.get(`/anomalies/device/${deviceId}`, {
        params,
      });
      return response.data;
    },
    enabled: !!deviceId,
  });
}

export function useAnomaly(id: string) {
  return useQuery({
    queryKey: ['anomalies', id],
    queryFn: async (): Promise<AnomalyDetection> => {
      const response = await apiClient.get(`/anomalies/${id}`);
      return response.data;
    },
    enabled: !!id,
  });
}

export function useAnomalyStats() {
  return useQuery({
    queryKey: ['anomalies', 'stats'],
    queryFn: async (): Promise<AnomalyStats> => {
      const response = await apiClient.get('/anomalies/stats/summary');
      return response.data;
    },
  });
}

export function useUpdateAnomalyStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      anomalyId,
      status,
    }: {
      anomalyId: string;
      status: string;
    }) => {
      const response = await apiClient.patch(`/anomalies/${anomalyId}`, {
        status,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['anomalies'] });
    },
  });
}

export function useRunDeviceDetection() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      deviceId,
      timeWindowHours = 1,
      autoCreateAlerts = true,
    }: {
      deviceId: string;
      timeWindowHours?: number;
      autoCreateAlerts?: boolean;
    }): Promise<DetectionRunResponse> => {
      const response = await apiClient.post(`/anomalies/device/${deviceId}/detect`, {
        time_window_hours: timeWindowHours,
        auto_create_alerts: autoCreateAlerts,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['anomalies'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

export function useRunAllDevicesDetection() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      timeWindowHours = 1,
      autoCreateAlerts = true,
    }: {
      timeWindowHours?: number;
      autoCreateAlerts?: boolean;
    } = {}): Promise<BulkDetectionResponse> => {
      const response = await apiClient.post('/anomalies/detect-all', {
        time_window_hours: timeWindowHours,
        auto_create_alerts: autoCreateAlerts,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['anomalies'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

// Chat/LLM hooks
export function useLLMStatus() {
  return useQuery({
    queryKey: ['chat', 'status'],
    queryFn: async (): Promise<LLMStatus> => {
      const response = await apiClient.get('/chat/status');
      return response.data;
    },
  });
}

export function useNetworkQuery() {
  return useMutation({
    mutationFn: async ({
      query,
      model,
    }: {
      query: string;
      model?: 'fast' | 'default' | 'deep';
    }): Promise<QueryResponse> => {
      const response = await apiClient.post('/chat/query', { query, model });
      return response.data;
    },
  });
}

export function useChat() {
  return useMutation({
    mutationFn: async ({
      messages,
      stream = false,
    }: {
      messages: ChatMessage[];
      stream?: boolean;
    }): Promise<ChatResponse> => {
      const response = await apiClient.post('/chat/chat', { messages, stream });
      return response.data;
    },
  });
}

export function useSummarizeIncident() {
  return useMutation({
    mutationFn: async (
      request: IncidentSummaryRequest
    ): Promise<IncidentSummaryResponse> => {
      const response = await apiClient.post('/chat/summarize-incident', request);
      return response.data;
    },
  });
}

export function useAnalyzeAlert() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      alertId,
      model,
    }: {
      alertId: string;
      model?: 'fast' | 'default' | 'deep';
    }): Promise<Alert> => {
      const response = await apiClient.post(`/alerts/${alertId}/analyze`, {
        model,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

// Integration hooks
export interface IntegrationStatus {
  name: string;
  type: string;
  enabled: boolean;
  configured: boolean;
  connected?: boolean;
  details: Record<string, unknown>;
}

export interface IntegrationStatusResponse {
  integrations: IntegrationStatus[];
}

export interface TestConnectionResponse {
  success: boolean;
  message: string;
  details: Record<string, unknown>;
  error?: string;
}

export interface QuarantinedDevice {
  device_id: string;
  hostname: string | null;
  mac_address: string;
  ip_addresses: string[];
  adguard_blocked: boolean;
  router_blocked: boolean;
  router_type: string | null;
}

export function useIntegrationsStatus() {
  return useQuery({
    queryKey: ['integrations', 'status'],
    queryFn: async (): Promise<IntegrationStatusResponse> => {
      const response = await apiClient.get('/integrations/status');
      return response.data;
    },
  });
}

export function useTestAdGuardConnection() {
  return useMutation({
    mutationFn: async (): Promise<TestConnectionResponse> => {
      const response = await apiClient.post('/integrations/adguard/test');
      return response.data;
    },
  });
}

export function useTestRouterConnection() {
  return useMutation({
    mutationFn: async (): Promise<TestConnectionResponse> => {
      const response = await apiClient.post('/integrations/router/test');
      return response.data;
    },
  });
}

export function useAdGuardBlocked() {
  return useQuery({
    queryKey: ['integrations', 'adguard', 'blocked'],
    queryFn: async (): Promise<Array<Record<string, unknown>>> => {
      const response = await apiClient.get('/integrations/adguard/blocked');
      return response.data;
    },
    enabled: false, // Only fetch when needed
  });
}

export function useRouterBlocked() {
  return useQuery({
    queryKey: ['integrations', 'router', 'blocked'],
    queryFn: async (): Promise<Array<Record<string, unknown>>> => {
      const response = await apiClient.get('/integrations/router/blocked');
      return response.data;
    },
    enabled: false, // Only fetch when needed
  });
}

export function useQuarantinedDevices() {
  return useQuery({
    queryKey: ['devices', 'quarantined'],
    queryFn: async (): Promise<QuarantinedDevice[]> => {
      const response = await apiClient.get('/devices/quarantined');
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useSyncQuarantine() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (): Promise<{
      checked: number;
      synced: number;
      errors: string[];
    }> => {
      const response = await apiClient.post('/integrations/sync-quarantine');
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });
}

// Audit hooks
export interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  user_id: string | null;
  username: string | null;
  target_type: string;
  target_id: string | null;
  target_name: string | null;
  description: string;
  details: Record<string, unknown>;
  success: boolean;
  error_message: string | null;
  ip_address: string | null;
}

export interface AuditLogListResponse {
  items: AuditLog[];
  total: number;
}

export interface AuditStats {
  quarantines_24h: number;
  releases_24h: number;
  logins_24h: number;
  user_actions_24h: number;
}

export function useAuditLogs(params?: {
  action?: string;
  target_type?: string;
  target_id?: string;
  user_id?: string;
  success_only?: boolean;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['audit', params],
    queryFn: async (): Promise<AuditLogListResponse> => {
      const response = await apiClient.get('/audit', { params });
      return response.data;
    },
  });
}

export function useDeviceAuditHistory(deviceId: string, limit = 50) {
  return useQuery({
    queryKey: ['audit', 'device', deviceId],
    queryFn: async (): Promise<AuditLogListResponse> => {
      const response = await apiClient.get(`/audit/device/${deviceId}`, {
        params: { limit },
      });
      return response.data;
    },
    enabled: !!deviceId,
  });
}

export function useQuarantineHistory(hours = 24, limit = 100) {
  return useQuery({
    queryKey: ['audit', 'quarantine-history', hours, limit],
    queryFn: async (): Promise<AuditLogListResponse> => {
      const response = await apiClient.get('/audit/quarantine-history', {
        params: { hours, limit },
      });
      return response.data;
    },
  });
}

export function useAuditStats() {
  return useQuery({
    queryKey: ['audit', 'stats'],
    queryFn: async (): Promise<AuditStats> => {
      const response = await apiClient.get('/audit/stats');
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });
}
