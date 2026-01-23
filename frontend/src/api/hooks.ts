import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import apiClient from './client';
import { useAuthStore } from '../stores/auth';
import type {
  Alert,
  AlertListResponse,
  AnomalyDetection,
  AnomalyListResponse,
  AnomalyStats,
  ApproveRuleRequest,
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
  IrregularLog,
  IrregularLogListResponse,
  LLMStatus,
  LoginRequest,
  LoginResponse,
  LogPattern,
  LogPatternListResponse,
  LogSourceListResponse,
  OverviewStats,
  PasswordResetResponse,
  QueryResponse,
  RejectRuleRequest,
  SemanticAnalysisConfig,
  SemanticAnalysisRunListResponse,
  SemanticStats,
  SuggestedRule,
  SuggestedRuleHistoryListResponse,
  SuggestedRuleListResponse,
  TopDomain,
  TriggerAnalysisResponse,
  UpdateSemanticConfigRequest,
  UpdateUserRequest,
  User,
  UserListResponse,
} from '../types';

// Auth hooks
export function useLogin() {
  const login = useAuthStore((state) => state.login);
  const setPending2FA = useAuthStore((state) => state.setPending2FA);

  return useMutation({
    mutationFn: async (credentials: LoginRequest): Promise<LoginResponse> => {
      const params = new URLSearchParams();
      params.append('username', credentials.username);
      params.append('password', credentials.password);

      const response = await apiClient.post<LoginResponse>('/auth/login', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      return response.data;
    },
    onSuccess: (data) => {
      if (data.requires_2fa && data.pending_token) {
        // 2FA required - store pending state
        setPending2FA(true, data.pending_token, data.user);
      } else {
        // Normal login
        login(data.user, data.access_token, data.refresh_token);
      }
    },
  });
}

export function useVerify2FA() {
  const login = useAuthStore((state) => state.login);
  const clearPending2FA = useAuthStore((state) => state.clearPending2FA);

  return useMutation({
    mutationFn: async ({
      pendingToken,
      code,
    }: {
      pendingToken: string;
      code: string;
    }): Promise<LoginResponse> => {
      const response = await apiClient.post<LoginResponse>('/auth/2fa/verify', {
        pending_token: pendingToken,
        code,
      });
      return response.data;
    },
    onSuccess: (data) => {
      login(data.user, data.access_token, data.refresh_token);
      clearPending2FA();
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

// 2FA Management hooks
export interface TwoFactorSetupResponse {
  secret: string;
  qr_code: string;
  backup_codes: string[];
}

export interface TwoFactorStatus {
  enabled: boolean;
  backup_codes_remaining: number;
}

export function use2FAStatus() {
  return useQuery({
    queryKey: ['auth', '2fa', 'status'],
    queryFn: async (): Promise<TwoFactorStatus> => {
      const response = await apiClient.get('/auth/2fa/status');
      return response.data;
    },
  });
}

export function useSetup2FA() {
  return useMutation({
    mutationFn: async (): Promise<TwoFactorSetupResponse> => {
      const response = await apiClient.post('/auth/2fa/setup');
      return response.data;
    },
  });
}

export function useEnable2FA() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (code: string): Promise<{ message: string }> => {
      const response = await apiClient.post('/auth/2fa/enable', { code });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth', '2fa', 'status'] });
      queryClient.invalidateQueries({ queryKey: ['currentUser'] });
    },
  });
}

export function useDisable2FA() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      password,
      code,
    }: {
      password: string;
      code?: string;
    }): Promise<{ message: string }> => {
      const response = await apiClient.post('/auth/2fa/disable', {
        password,
        code,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth', '2fa', 'status'] });
      queryClient.invalidateQueries({ queryKey: ['currentUser'] });
    },
  });
}

export function useRegenerate2FABackupCodes() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (): Promise<string[]> => {
      const response = await apiClient.post('/auth/2fa/backup-codes');
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth', '2fa', 'status'] });
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
  tags?: string[];
}) {
  return useQuery({
    queryKey: ['devices', params],
    queryFn: async (): Promise<DeviceListResponse> => {
      // Convert tags array to comma-separated string for query param
      const queryParams = params ? {
        ...params,
        tags: params.tags?.join(',') || undefined,
      } : undefined;
      const response = await apiClient.get('/devices', { params: queryParams });
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
    // Optimistically update the cache for instant UI feedback
    onMutate: async (variables) => {
      // Cancel any outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['sources'] });

      // Snapshot the previous value
      const previousSources = queryClient.getQueryData<LogSourceListResponse>(['sources']);

      // Optimistically update the cache
      if (previousSources) {
        queryClient.setQueryData<LogSourceListResponse>(['sources'], {
          ...previousSources,
          items: previousSources.items.map((source) =>
            source.id === variables.id ? { ...source, ...variables } : source
          ),
        });
      }

      // Return context with the previous value for rollback
      return { previousSources };
    },
    onError: (_err, _variables, context) => {
      // Roll back to the previous value on error
      if (context?.previousSources) {
        queryClient.setQueryData(['sources'], context.previousSources);
      }
    },
    onSettled: () => {
      // Always refetch after error or success to ensure cache is in sync
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

// Notification hooks
export interface NotificationPreferences {
  id: string;
  user_id: string;
  email_enabled: boolean;
  email_address: string | null;
  email_on_critical: boolean;
  email_on_high: boolean;
  email_on_medium: boolean;
  email_on_low: boolean;
  email_on_anomaly: boolean;
  email_on_quarantine: boolean;
  ntfy_enabled: boolean;
  ntfy_topic: string | null;
  ntfy_on_critical: boolean;
  ntfy_on_high: boolean;
  ntfy_on_medium: boolean;
  ntfy_on_low: boolean;
  ntfy_on_anomaly: boolean;
  ntfy_on_quarantine: boolean;
}

export interface NotificationPreferencesUpdate {
  email_enabled?: boolean;
  email_address?: string;
  email_on_critical?: boolean;
  email_on_high?: boolean;
  email_on_medium?: boolean;
  email_on_low?: boolean;
  email_on_anomaly?: boolean;
  email_on_quarantine?: boolean;
  ntfy_enabled?: boolean;
  ntfy_topic?: string;
  ntfy_on_critical?: boolean;
  ntfy_on_high?: boolean;
  ntfy_on_medium?: boolean;
  ntfy_on_low?: boolean;
  ntfy_on_anomaly?: boolean;
  ntfy_on_quarantine?: boolean;
}

export interface NotificationStatus {
  email_configured: boolean;
  ntfy_configured: boolean;
  ntfy_server_url: string;
}

export interface TestNotificationResult {
  success: boolean;
  message?: string;
  error?: string;
}

export function useNotificationStatus() {
  return useQuery({
    queryKey: ['notifications', 'status'],
    queryFn: async (): Promise<NotificationStatus> => {
      const response = await apiClient.get('/notifications/status');
      return response.data;
    },
  });
}

export function useNotificationPreferences() {
  return useQuery({
    queryKey: ['notifications', 'preferences'],
    queryFn: async (): Promise<NotificationPreferences> => {
      const response = await apiClient.get('/notifications/preferences');
      return response.data;
    },
  });
}

export function useUpdateNotificationPreferences() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (
      data: NotificationPreferencesUpdate
    ): Promise<NotificationPreferences> => {
      const response = await apiClient.put('/notifications/preferences', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications', 'preferences'] });
    },
  });
}

export function useTestNotification() {
  return useMutation({
    mutationFn: async ({
      type,
      email_address,
      ntfy_topic,
    }: {
      type: 'email' | 'ntfy';
      email_address?: string;
      ntfy_topic?: string;
    }): Promise<TestNotificationResult> => {
      const response = await apiClient.post('/notifications/test', {
        type,
        email_address,
        ntfy_topic,
      });
      return response.data;
    },
  });
}

export function useTestEmailConnection() {
  return useMutation({
    mutationFn: async (): Promise<TestNotificationResult> => {
      const response = await apiClient.post('/notifications/test/email');
      return response.data;
    },
  });
}

export function useTestNtfyConnection() {
  return useMutation({
    mutationFn: async (topic?: string): Promise<TestNotificationResult> => {
      const response = await apiClient.post('/notifications/test/ntfy', null, {
        params: topic ? { topic } : undefined,
      });
      return response.data;
    },
  });
}

// Retention Policy hooks (Admin only)
export interface RetentionPolicy {
  id: string;
  table_name: string;
  display_name: string;
  description: string | null;
  retention_days: number;
  enabled: boolean;
  last_run: string | null;
  deleted_count: number;
}

export interface RetentionPolicyUpdate {
  retention_days?: number;
  enabled?: boolean;
}

export interface RetentionCleanupResult {
  dry_run: boolean;
  policies_processed: number;
  total_deleted: number;
  details: Array<{
    table: string;
    status: string;
    cutoff_date?: string;
    deleted?: number;
    reason?: string;
    error?: string;
  }>;
}

export interface StorageStats {
  tables: Array<{
    table_name: string;
    display_name: string;
    row_count?: number;
    table_size?: string;
    retention_days?: number;
    enabled?: boolean;
    last_run?: string | null;
    last_deleted?: number;
    error?: string;
  }>;
  total_rows: number;
}

export function useRetentionPolicies() {
  return useQuery({
    queryKey: ['admin', 'retention', 'policies'],
    queryFn: async (): Promise<RetentionPolicy[]> => {
      const response = await apiClient.get('/admin/retention/policies');
      return response.data;
    },
  });
}

export function useRetentionPolicy(policyId: string) {
  return useQuery({
    queryKey: ['admin', 'retention', 'policies', policyId],
    queryFn: async (): Promise<RetentionPolicy> => {
      const response = await apiClient.get(`/admin/retention/policies/${policyId}`);
      return response.data;
    },
    enabled: !!policyId,
  });
}

export function useUpdateRetentionPolicy() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      policyId,
      ...data
    }: RetentionPolicyUpdate & { policyId: string }): Promise<RetentionPolicy> => {
      const response = await apiClient.patch(`/admin/retention/policies/${policyId}`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'retention', 'policies'] });
    },
  });
}

export function useRunRetentionCleanup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      policyId,
      dryRun = true,
    }: {
      policyId?: string;
      dryRun?: boolean;
    }): Promise<RetentionCleanupResult> => {
      const response = await apiClient.post('/admin/retention/cleanup', {
        policy_id: policyId,
        dry_run: dryRun,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'retention'] });
    },
  });
}

export function useStorageStats() {
  return useQuery({
    queryKey: ['admin', 'retention', 'stats'],
    queryFn: async (): Promise<StorageStats> => {
      const response = await apiClient.get('/admin/retention/stats');
      return response.data;
    },
  });
}

// Export functions (not hooks - these trigger downloads directly)
export async function exportEventsCSV(params?: {
  source_id?: string;
  event_type?: string;
  severity?: string;
  device_id?: string;
  start_time?: string;
  end_time?: string;
}): Promise<void> {
  const response = await apiClient.get('/events/export/csv', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `events_${formatDateForFilename()}.csv`);
}

export async function exportEventsPDF(params?: {
  source_id?: string;
  event_type?: string;
  severity?: string;
  device_id?: string;
  start_time?: string;
  end_time?: string;
}): Promise<void> {
  const response = await apiClient.get('/events/export/pdf', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `events_${formatDateForFilename()}.pdf`);
}

export async function exportAlertsCSV(params?: {
  status?: string;
  severity?: string;
  device_id?: string;
}): Promise<void> {
  const response = await apiClient.get('/alerts/export/csv', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `alerts_${formatDateForFilename()}.csv`);
}

export async function exportAlertsPDF(params?: {
  status?: string;
  severity?: string;
  device_id?: string;
}): Promise<void> {
  const response = await apiClient.get('/alerts/export/pdf', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `alerts_${formatDateForFilename()}.pdf`);
}

export async function exportDevicesCSV(params?: {
  status?: string;
  device_type?: string;
}): Promise<void> {
  const response = await apiClient.get('/devices/export/csv', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `devices_${formatDateForFilename()}.csv`);
}

export async function exportDevicesPDF(params?: {
  status?: string;
  device_type?: string;
}): Promise<void> {
  const response = await apiClient.get('/devices/export/pdf', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `devices_${formatDateForFilename()}.pdf`);
}

export async function exportAuditCSV(params?: {
  action?: string;
  target_type?: string;
  user_id?: string;
}): Promise<void> {
  const response = await apiClient.get('/audit/export/csv', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `audit_${formatDateForFilename()}.csv`);
}

export async function exportAuditPDF(params?: {
  action?: string;
  target_type?: string;
  user_id?: string;
}): Promise<void> {
  const response = await apiClient.get('/audit/export/pdf', {
    params,
    responseType: 'blob',
  });
  downloadBlob(response.data, `audit_${formatDateForFilename()}.pdf`);
}

// Helper functions for exports
function formatDateForFilename(): string {
  const now = new Date();
  return now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

// Device Tag Management hooks
export interface TagsResponse {
  tags: string[];
  counts: Record<string, number>;
}

export interface BulkTagResponse {
  updated_count: number;
  devices: Device[];
}

export function useAllTags() {
  return useQuery({
    queryKey: ['devices', 'tags'],
    queryFn: async (): Promise<TagsResponse> => {
      const response = await apiClient.get('/devices/tags/all');
      return response.data;
    },
  });
}

export function useBulkTagDevices() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      deviceIds,
      tagsToAdd,
      tagsToRemove,
    }: {
      deviceIds: string[];
      tagsToAdd?: string[];
      tagsToRemove?: string[];
    }): Promise<BulkTagResponse> => {
      const response = await apiClient.post('/devices/bulk-tag', {
        device_ids: deviceIds,
        tags_to_add: tagsToAdd,
        tags_to_remove: tagsToRemove,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });
}

export function useSetDeviceTags() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      deviceId,
      tags,
    }: {
      deviceId: string;
      tags: string[];
    }): Promise<Device> => {
      const response = await apiClient.put(`/devices/${deviceId}/tags`, tags);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['device', variables.deviceId] });
    },
  });
}

export function useAddDeviceTag() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      deviceId,
      tag,
    }: {
      deviceId: string;
      tag: string;
    }): Promise<Device> => {
      const response = await apiClient.post(`/devices/${deviceId}/tags`, null, {
        params: { tag },
      });
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['device', variables.deviceId] });
    },
  });
}

export function useRemoveDeviceTag() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      deviceId,
      tag,
    }: {
      deviceId: string;
      tag: string;
    }): Promise<Device> => {
      const response = await apiClient.delete(`/devices/${deviceId}/tags/${encodeURIComponent(tag)}`);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['device', variables.deviceId] });
    },
  });
}

// Detection Rules hooks
import type {
  DetectionRule,
  DetectionRuleListResponse,
  CreateRuleRequest,
  UpdateRuleRequest,
  ConditionFieldInfo,
  TestRuleRequest,
  TestRuleResponse,
} from '../types';

export function useRules(params?: {
  enabled?: boolean;
  severity?: string;
  search?: string;
  page?: number;
  page_size?: number;
}) {
  return useQuery({
    queryKey: ['rules', params],
    queryFn: async (): Promise<DetectionRuleListResponse> => {
      const response = await apiClient.get('/rules', { params });
      return response.data;
    },
  });
}

export function useRule(ruleId: string) {
  return useQuery({
    queryKey: ['rules', ruleId],
    queryFn: async (): Promise<DetectionRule> => {
      const response = await apiClient.get(`/rules/${ruleId}`);
      return response.data;
    },
    enabled: !!ruleId,
  });
}

export function useRuleFields() {
  return useQuery({
    queryKey: ['rules', 'fields'],
    queryFn: async (): Promise<ConditionFieldInfo[]> => {
      const response = await apiClient.get('/rules/fields');
      return response.data;
    },
  });
}

export function useCreateRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: CreateRuleRequest): Promise<DetectionRule> => {
      const response = await apiClient.post('/rules', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
  });
}

export function useUpdateRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      ruleId,
      ...data
    }: UpdateRuleRequest & { ruleId: string }): Promise<DetectionRule> => {
      const response = await apiClient.patch(`/rules/${ruleId}`, data);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      queryClient.invalidateQueries({ queryKey: ['rules', variables.ruleId] });
    },
  });
}

export function useDeleteRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (ruleId: string): Promise<void> => {
      await apiClient.delete(`/rules/${ruleId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
  });
}

export function useEnableRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (ruleId: string): Promise<DetectionRule> => {
      const response = await apiClient.post(`/rules/${ruleId}/enable`);
      return response.data;
    },
    onSuccess: (_, ruleId) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      queryClient.invalidateQueries({ queryKey: ['rules', ruleId] });
    },
  });
}

export function useDisableRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (ruleId: string): Promise<DetectionRule> => {
      const response = await apiClient.post(`/rules/${ruleId}/disable`);
      return response.data;
    },
    onSuccess: (_, ruleId) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      queryClient.invalidateQueries({ queryKey: ['rules', ruleId] });
    },
  });
}

export function useTestRule() {
  return useMutation({
    mutationFn: async (data: TestRuleRequest): Promise<TestRuleResponse> => {
      const response = await apiClient.post('/rules/test', data);
      return response.data;
    },
  });
}

// Threat Intelligence hooks
import type {
  ThreatIntelFeed,
  ThreatIntelFeedListResponse,
  ThreatIndicatorListResponse,
  CreateFeedRequest,
  UpdateFeedRequest,
  IndicatorCheckResponse,
  ThreatIntelStats,
  FeedType,
  IndicatorType,
  TopologyData,
} from '../types';

export function useThreatFeeds(params?: {
  enabled?: boolean;
  feed_type?: FeedType;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['threat-intel', 'feeds', params],
    queryFn: async (): Promise<ThreatIntelFeedListResponse> => {
      const response = await apiClient.get('/threat-intel/feeds', { params });
      return response.data;
    },
  });
}

export function useThreatFeed(feedId: string) {
  return useQuery({
    queryKey: ['threat-intel', 'feeds', feedId],
    queryFn: async (): Promise<ThreatIntelFeed> => {
      const response = await apiClient.get(`/threat-intel/feeds/${feedId}`);
      return response.data;
    },
    enabled: !!feedId,
  });
}

export function useCreateThreatFeed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: CreateFeedRequest): Promise<ThreatIntelFeed> => {
      const response = await apiClient.post('/threat-intel/feeds', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'stats'] });
    },
  });
}

export function useUpdateThreatFeed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      feedId,
      ...data
    }: UpdateFeedRequest & { feedId: string }): Promise<ThreatIntelFeed> => {
      const response = await apiClient.patch(`/threat-intel/feeds/${feedId}`, data);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds', variables.feedId] });
    },
  });
}

export function useDeleteThreatFeed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (feedId: string): Promise<void> => {
      await apiClient.delete(`/threat-intel/feeds/${feedId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'stats'] });
    },
  });
}

export function useFetchThreatFeed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (feedId: string): Promise<{ message: string; feed_id: string }> => {
      const response = await apiClient.post(`/threat-intel/feeds/${feedId}/fetch`);
      return response.data;
    },
    onSuccess: (_, feedId) => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds', feedId] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'indicators'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'stats'] });
    },
  });
}

export function useEnableThreatFeed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (feedId: string): Promise<ThreatIntelFeed> => {
      const response = await apiClient.post(`/threat-intel/feeds/${feedId}/enable`);
      return response.data;
    },
    onSuccess: (_, feedId) => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds', feedId] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'stats'] });
    },
  });
}

export function useDisableThreatFeed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (feedId: string): Promise<ThreatIntelFeed> => {
      const response = await apiClient.post(`/threat-intel/feeds/${feedId}/disable`);
      return response.data;
    },
    onSuccess: (_, feedId) => {
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds'] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'feeds', feedId] });
      queryClient.invalidateQueries({ queryKey: ['threat-intel', 'stats'] });
    },
  });
}

export function useThreatIndicators(params?: {
  feed_id?: string;
  indicator_type?: IndicatorType;
  severity?: string;
  value_contains?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ['threat-intel', 'indicators', params],
    queryFn: async (): Promise<ThreatIndicatorListResponse> => {
      const response = await apiClient.get('/threat-intel/indicators', { params });
      return response.data;
    },
  });
}

export function useCheckIndicator() {
  return useMutation({
    mutationFn: async ({
      value,
      indicator_type,
    }: {
      value: string;
      indicator_type?: IndicatorType;
    }): Promise<IndicatorCheckResponse> => {
      const response = await apiClient.post('/threat-intel/check', {
        value,
        indicator_type,
      });
      return response.data;
    },
  });
}

export function useThreatIntelStats() {
  return useQuery({
    queryKey: ['threat-intel', 'stats'],
    queryFn: async (): Promise<ThreatIntelStats> => {
      const response = await apiClient.get('/threat-intel/stats');
      return response.data;
    },
  });
}

// Network Topology hooks
export function useTopology(params?: {
  hours?: number;
  include_inactive?: boolean;
}) {
  return useQuery({
    queryKey: ['topology', params],
    queryFn: async (): Promise<TopologyData> => {
      const response = await apiClient.get('/topology', { params });
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });
}

export interface DeviceConnectionsResponse {
  device_id: string;
  connections: Array<{
    domain: string | null;
    target_ip: string | null;
    event_type: string;
    action: string | null;
    count: number;
    last_seen: string | null;
  }>;
  time_window_hours: number;
}

export function useDeviceConnections(deviceId: string, params?: {
  hours?: number;
  limit?: number;
}) {
  return useQuery({
    queryKey: ['topology', 'connections', deviceId, params],
    queryFn: async (): Promise<DeviceConnectionsResponse> => {
      const response = await apiClient.get(`/topology/device/${deviceId}/connections`, { params });
      return response.data;
    },
    enabled: !!deviceId,
  });
}

// Semantic Analysis hooks

// Config hooks
export function useSemanticConfigs() {
  return useQuery({
    queryKey: ['semantic', 'configs'],
    queryFn: async (): Promise<SemanticAnalysisConfig[]> => {
      const response = await apiClient.get('/semantic/config');
      return response.data;
    },
  });
}

export function useSemanticConfig(sourceId: string) {
  return useQuery({
    queryKey: ['semantic', 'config', sourceId],
    queryFn: async (): Promise<SemanticAnalysisConfig> => {
      const response = await apiClient.get(`/semantic/config/${sourceId}`);
      return response.data;
    },
    enabled: !!sourceId,
  });
}

export function useUpdateSemanticConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      sourceId,
      config,
    }: {
      sourceId: string;
      config: UpdateSemanticConfigRequest;
    }): Promise<SemanticAnalysisConfig> => {
      const response = await apiClient.put(`/semantic/config/${sourceId}`, config);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['semantic', 'configs'] });
      queryClient.invalidateQueries({ queryKey: ['semantic', 'config', variables.sourceId] });
    },
  });
}

// Pattern hooks
export function usePatterns(params?: {
  source_id?: string;
  is_ignored?: boolean;
  rare_only?: boolean;
  rarity_threshold?: number;
  search?: string;
  page?: number;
  page_size?: number;
}) {
  return useQuery({
    queryKey: ['semantic', 'patterns', params],
    queryFn: async (): Promise<LogPatternListResponse> => {
      const response = await apiClient.get('/semantic/patterns', { params });
      return response.data;
    },
  });
}

export function useUpdatePattern() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      patternId,
      is_ignored,
    }: {
      patternId: string;
      is_ignored: boolean;
    }): Promise<LogPattern> => {
      const response = await apiClient.patch(`/semantic/patterns/${patternId}`, { is_ignored });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['semantic', 'patterns'] });
    },
  });
}

// Irregular log hooks
export function useIrregularLogs(params?: {
  source_id?: string;
  llm_reviewed?: boolean;
  reviewed_by_user?: boolean;
  min_severity?: number;
  start_date?: string;
  end_date?: string;
  page?: number;
  page_size?: number;
}) {
  return useQuery({
    queryKey: ['semantic', 'irregular', params],
    queryFn: async (): Promise<IrregularLogListResponse> => {
      const response = await apiClient.get('/semantic/irregular', { params });
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useIrregularLog(irregularId: string) {
  return useQuery({
    queryKey: ['semantic', 'irregular', irregularId],
    queryFn: async (): Promise<IrregularLog> => {
      const response = await apiClient.get(`/semantic/irregular/${irregularId}`);
      return response.data;
    },
    enabled: !!irregularId,
  });
}

export function useMarkIrregularReviewed() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (irregularId: string): Promise<IrregularLog> => {
      const response = await apiClient.patch(`/semantic/irregular/${irregularId}/review`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['semantic', 'irregular'] });
      queryClient.invalidateQueries({ queryKey: ['semantic', 'stats'] });
    },
  });
}

export interface ResearchQueryResponse {
  query: string;
  search_url: string;
}

export function useGenerateResearchQuery() {
  return useMutation({
    mutationFn: async (irregularId: string): Promise<ResearchQueryResponse> => {
      const response = await apiClient.get(`/semantic/irregular/${irregularId}/research-query`);
      return response.data;
    },
  });
}

// Analysis run hooks
export function useAnalysisRuns(params?: {
  source_id?: string;
  limit?: number;
}) {
  return useQuery({
    queryKey: ['semantic', 'runs', params],
    queryFn: async (): Promise<SemanticAnalysisRunListResponse> => {
      const response = await apiClient.get('/semantic/runs', { params });
      return response.data;
    },
  });
}

export function useTriggerAnalysis() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      sourceId,
      force,
    }: {
      sourceId: string;
      force?: boolean;
    }): Promise<TriggerAnalysisResponse> => {
      const response = await apiClient.post(`/semantic/runs/${sourceId}/trigger`, null, {
        params: { force },
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['semantic', 'runs'] });
      queryClient.invalidateQueries({ queryKey: ['semantic', 'irregular'] });
      queryClient.invalidateQueries({ queryKey: ['semantic', 'stats'] });
    },
  });
}

// Stats hooks
export function useSemanticStats(sourceId?: string) {
  return useQuery({
    queryKey: ['semantic', 'stats', sourceId],
    queryFn: async (): Promise<SemanticStats> => {
      const url = sourceId ? `/semantic/stats/${sourceId}` : '/semantic/stats';
      const response = await apiClient.get(url);
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

// Suggested rules hooks
export function useSuggestedRules(params?: {
  source_id?: string;
  status?: string;
  rule_type?: string;
  search?: string;
  page?: number;
  page_size?: number;
}) {
  return useQuery({
    queryKey: ['semantic', 'rules', params],
    queryFn: async (): Promise<SuggestedRuleListResponse> => {
      const response = await apiClient.get('/semantic/rules', { params });
      return response.data;
    },
  });
}

export function usePendingSuggestedRules(params?: {
  page?: number;
  page_size?: number;
}) {
  return useQuery({
    queryKey: ['semantic', 'rules', 'pending', params],
    queryFn: async (): Promise<SuggestedRuleListResponse> => {
      const response = await apiClient.get('/semantic/rules/pending', { params });
      return response.data;
    },
    refetchInterval: 30000,
  });
}

export function useSuggestedRule(ruleId: string) {
  return useQuery({
    queryKey: ['semantic', 'rules', ruleId],
    queryFn: async (): Promise<SuggestedRule> => {
      const response = await apiClient.get(`/semantic/rules/${ruleId}`);
      return response.data;
    },
    enabled: !!ruleId,
  });
}

export function useApproveRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      ruleId,
      request,
    }: {
      ruleId: string;
      request: ApproveRuleRequest;
    }): Promise<SuggestedRule> => {
      const response = await apiClient.post(`/semantic/rules/${ruleId}/approve`, request);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['semantic', 'rules'] });
      queryClient.invalidateQueries({ queryKey: ['rules'] }); // Invalidate detection rules too
    },
  });
}

export function useRejectRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      ruleId,
      request,
    }: {
      ruleId: string;
      request: RejectRuleRequest;
    }): Promise<SuggestedRule> => {
      const response = await apiClient.post(`/semantic/rules/${ruleId}/reject`, request);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['semantic', 'rules'] });
    },
  });
}

export function useRuleHistory(params?: {
  status?: string;
  page?: number;
  page_size?: number;
}) {
  return useQuery({
    queryKey: ['semantic', 'rules', 'history', params],
    queryFn: async (): Promise<SuggestedRuleHistoryListResponse> => {
      const response = await apiClient.get('/semantic/rules/history', { params });
      return response.data;
    },
  });
}
