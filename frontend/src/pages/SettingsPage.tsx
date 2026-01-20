import { useState, useEffect } from 'react';
import { Settings, Bell, Shield, Clock, Mail, Send, CheckCircle, XCircle, Loader2, ExternalLink, Key, Copy, Download, Eye, EyeOff, AlertTriangle, Database, Trash2, Play, RefreshCw } from 'lucide-react';
import { useAuthStore } from '../stores/auth';
import { useRealtime } from '../components/RealtimeProvider';
import {
  useNotificationStatus,
  useNotificationPreferences,
  useUpdateNotificationPreferences,
  useTestNotification,
  use2FAStatus,
  useSetup2FA,
  useEnable2FA,
  useDisable2FA,
  useRegenerate2FABackupCodes,
  useRetentionPolicies,
  useUpdateRetentionPolicy,
  useRunRetentionCleanup,
  useStorageStats,
  type NotificationPreferencesUpdate,
  type RetentionPolicy,
  type RetentionCleanupResult,
} from '../api/hooks';
import clsx from 'clsx';

type SettingsTab = 'general' | 'notifications' | 'security' | 'retention';

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>('general');
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';
  const { isConnected } = useRealtime();

  const tabs = [
    { id: 'general' as const, name: 'General', icon: Settings },
    { id: 'notifications' as const, name: 'Notifications', icon: Bell },
    { id: 'security' as const, name: 'Security', icon: Shield },
    ...(isAdmin ? [{ id: 'retention' as const, name: 'Data Retention', icon: Clock }] : []),
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-500 dark:text-gray-400">Manage your preferences</p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <nav className="lg:w-48 flex-shrink-0">
          <ul className="space-y-1">
            {tabs.map((tab) => (
              <li key={tab.id}>
                <button
                  onClick={() => setActiveTab(tab.id)}
                  className={clsx(
                    'w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-colors',
                    activeTab === tab.id
                      ? 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-700'
                  )}
                >
                  <tab.icon className="w-5 h-5" />
                  {tab.name}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* Content */}
        <div className="flex-1">
          {activeTab === 'general' && <GeneralSettings isConnected={isConnected} />}
          {activeTab === 'notifications' && <NotificationSettings />}
          {activeTab === 'security' && <SecuritySettings />}
          {activeTab === 'retention' && isAdmin && <RetentionSettings />}
        </div>
      </div>
    </div>
  );
}

function GeneralSettings({ isConnected }: { isConnected: boolean }) {
  const user = useAuthStore((state) => state.user);

  return (
    <div className="card p-6 space-y-6">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-white">General Settings</h2>

      {/* User Info */}
      <div className="space-y-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">Account Information</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400">Username</label>
            <p className="mt-1 text-sm text-gray-900 dark:text-white">{user?.username}</p>
          </div>
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400">Role</label>
            <p className="mt-1 text-sm text-gray-900 dark:text-white capitalize">{user?.role}</p>
          </div>
        </div>
      </div>

      {/* Connection Status */}
      <div className="space-y-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">Connection Status</h3>
        <div className="flex items-center gap-3">
          <span
            className={clsx(
              'inline-block w-3 h-3 rounded-full',
              isConnected ? 'bg-success-500' : 'bg-gray-400'
            )}
          />
          <span className="text-sm text-gray-700 dark:text-gray-300">
            Real-time updates: {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>
    </div>
  );
}

function NotificationSettings() {
  const { data: status, isLoading: statusLoading } = useNotificationStatus();
  const { data: preferences, isLoading: prefsLoading } = useNotificationPreferences();
  const updatePrefs = useUpdateNotificationPreferences();
  const testNotification = useTestNotification();

  const [emailAddress, setEmailAddress] = useState('');
  const [ntfyTopic, setNtfyTopic] = useState('');
  const [testResult, setTestResult] = useState<{ type: string; success: boolean; message: string } | null>(null);

  useEffect(() => {
    if (preferences) {
      setEmailAddress(preferences.email_address || '');
      setNtfyTopic(preferences.ntfy_topic || '');
    }
  }, [preferences]);

  const handleToggle = async (field: keyof NotificationPreferencesUpdate, value: boolean) => {
    await updatePrefs.mutateAsync({ [field]: value });
  };

  const handleSaveEmail = async () => {
    await updatePrefs.mutateAsync({ email_address: emailAddress });
  };

  const handleSaveNtfyTopic = async () => {
    await updatePrefs.mutateAsync({ ntfy_topic: ntfyTopic });
  };

  const handleTestEmail = async () => {
    setTestResult(null);
    const result = await testNotification.mutateAsync({ type: 'email', email_address: emailAddress });
    setTestResult({
      type: 'email',
      success: result.success,
      message: result.success ? result.message || 'Test email sent!' : result.error || 'Failed to send',
    });
  };

  const handleTestNtfy = async () => {
    setTestResult(null);
    const result = await testNotification.mutateAsync({ type: 'ntfy', ntfy_topic: ntfyTopic });
    setTestResult({
      type: 'ntfy',
      success: result.success,
      message: result.success ? result.message || 'Test notification sent!' : result.error || 'Failed to send',
    });
  };

  if (statusLoading || prefsLoading) {
    return (
      <div className="card p-6 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-primary-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Email Notifications */}
      <div className="card p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Mail className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Email Notifications</h2>
          </div>
          {status?.email_configured ? (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-success-600 dark:text-success-400">
              <CheckCircle className="w-4 h-4" />
              SMTP Configured
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-warning-600 dark:text-warning-400">
              <XCircle className="w-4 h-4" />
              SMTP Not Configured
            </span>
          )}
        </div>

        {!status?.email_configured && (
          <div className="p-3 bg-warning-50 dark:bg-warning-900/30 rounded-lg">
            <p className="text-sm text-warning-700 dark:text-warning-300">
              Email notifications require SMTP configuration. Set SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, and SMTP_SENDER_EMAIL environment variables.
            </p>
          </div>
        )}

        {/* Email Enable Toggle */}
        <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-zinc-600">
          <div>
            <p className="font-medium text-gray-900 dark:text-white">Enable Email Notifications</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Receive alerts via email</p>
          </div>
          <ToggleSwitch
            enabled={preferences?.email_enabled || false}
            onChange={(v) => handleToggle('email_enabled', v)}
            disabled={!status?.email_configured || updatePrefs.isPending}
          />
        </div>

        {/* Email Address */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Email Address
          </label>
          <div className="flex gap-2">
            <input
              type="email"
              value={emailAddress}
              onChange={(e) => setEmailAddress(e.target.value)}
              placeholder="your@email.com"
              className="flex-1 px-3 py-2 border border-gray-300 dark:border-zinc-600 rounded-lg bg-white dark:bg-zinc-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              disabled={!preferences?.email_enabled}
            />
            <button
              onClick={handleSaveEmail}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
              className="btn-secondary"
            >
              Save
            </button>
          </div>
        </div>

        {/* Email Severity Toggles */}
        <div className="space-y-3">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Notify on severity:</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <SeverityToggle
              label="Critical"
              enabled={preferences?.email_on_critical || false}
              onChange={(v) => handleToggle('email_on_critical', v)}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
              color="danger"
            />
            <SeverityToggle
              label="High"
              enabled={preferences?.email_on_high || false}
              onChange={(v) => handleToggle('email_on_high', v)}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
              color="warning"
            />
            <SeverityToggle
              label="Medium"
              enabled={preferences?.email_on_medium || false}
              onChange={(v) => handleToggle('email_on_medium', v)}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
              color="info"
            />
            <SeverityToggle
              label="Low"
              enabled={preferences?.email_on_low || false}
              onChange={(v) => handleToggle('email_on_low', v)}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
              color="success"
            />
          </div>
        </div>

        {/* Email Event Toggles */}
        <div className="space-y-3">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Notify on events:</p>
          <div className="flex flex-wrap gap-3">
            <EventToggle
              label="Anomalies"
              enabled={preferences?.email_on_anomaly || false}
              onChange={(v) => handleToggle('email_on_anomaly', v)}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
            />
            <EventToggle
              label="Quarantine Actions"
              enabled={preferences?.email_on_quarantine || false}
              onChange={(v) => handleToggle('email_on_quarantine', v)}
              disabled={!preferences?.email_enabled || updatePrefs.isPending}
            />
          </div>
        </div>

        {/* Test Email */}
        <div className="pt-3 border-t border-gray-200 dark:border-zinc-600">
          <button
            onClick={handleTestEmail}
            disabled={!preferences?.email_enabled || !emailAddress || testNotification.isPending}
            className="btn-secondary inline-flex items-center gap-2"
          >
            {testNotification.isPending && testNotification.variables?.type === 'email' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
            Send Test Email
          </button>
          {testResult?.type === 'email' && (
            <p className={clsx(
              'mt-2 text-sm',
              testResult.success ? 'text-success-600 dark:text-success-400' : 'text-danger-600 dark:text-danger-400'
            )}>
              {testResult.message}
            </p>
          )}
        </div>
      </div>

      {/* ntfy.sh Notifications */}
      <div className="card p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Bell className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">ntfy.sh Push Notifications</h2>
          </div>
          {status?.ntfy_configured ? (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-success-600 dark:text-success-400">
              <CheckCircle className="w-4 h-4" />
              Configured
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 dark:text-gray-400">
              No default topic
            </span>
          )}
        </div>

        <div className="p-3 bg-gray-50 dark:bg-zinc-700/50 rounded-lg">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            ntfy.sh is a simple pub-sub notification service.{' '}
            <a
              href="https://ntfy.sh"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-600 dark:text-primary-400 hover:underline inline-flex items-center gap-1"
            >
              Learn more <ExternalLink className="w-3 h-3" />
            </a>
          </p>
          {status?.ntfy_server_url && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-500">
              Server: {status.ntfy_server_url}
            </p>
          )}
        </div>

        {/* ntfy Enable Toggle */}
        <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-zinc-600">
          <div>
            <p className="font-medium text-gray-900 dark:text-white">Enable ntfy.sh Notifications</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Receive push notifications on your devices</p>
          </div>
          <ToggleSwitch
            enabled={preferences?.ntfy_enabled || false}
            onChange={(v) => handleToggle('ntfy_enabled', v)}
            disabled={updatePrefs.isPending}
          />
        </div>

        {/* ntfy Topic */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Topic Name
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={ntfyTopic}
              onChange={(e) => setNtfyTopic(e.target.value)}
              placeholder="netguardian-alerts"
              className="flex-1 px-3 py-2 border border-gray-300 dark:border-zinc-600 rounded-lg bg-white dark:bg-zinc-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              disabled={!preferences?.ntfy_enabled}
            />
            <button
              onClick={handleSaveNtfyTopic}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
              className="btn-secondary"
            >
              Save
            </button>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Subscribe to this topic in the ntfy app to receive notifications
          </p>
        </div>

        {/* ntfy Severity Toggles */}
        <div className="space-y-3">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Notify on severity:</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <SeverityToggle
              label="Critical"
              enabled={preferences?.ntfy_on_critical || false}
              onChange={(v) => handleToggle('ntfy_on_critical', v)}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
              color="danger"
            />
            <SeverityToggle
              label="High"
              enabled={preferences?.ntfy_on_high || false}
              onChange={(v) => handleToggle('ntfy_on_high', v)}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
              color="warning"
            />
            <SeverityToggle
              label="Medium"
              enabled={preferences?.ntfy_on_medium || false}
              onChange={(v) => handleToggle('ntfy_on_medium', v)}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
              color="info"
            />
            <SeverityToggle
              label="Low"
              enabled={preferences?.ntfy_on_low || false}
              onChange={(v) => handleToggle('ntfy_on_low', v)}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
              color="success"
            />
          </div>
        </div>

        {/* ntfy Event Toggles */}
        <div className="space-y-3">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Notify on events:</p>
          <div className="flex flex-wrap gap-3">
            <EventToggle
              label="Anomalies"
              enabled={preferences?.ntfy_on_anomaly || false}
              onChange={(v) => handleToggle('ntfy_on_anomaly', v)}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
            />
            <EventToggle
              label="Quarantine Actions"
              enabled={preferences?.ntfy_on_quarantine || false}
              onChange={(v) => handleToggle('ntfy_on_quarantine', v)}
              disabled={!preferences?.ntfy_enabled || updatePrefs.isPending}
            />
          </div>
        </div>

        {/* Test ntfy */}
        <div className="pt-3 border-t border-gray-200 dark:border-zinc-600">
          <button
            onClick={handleTestNtfy}
            disabled={!preferences?.ntfy_enabled || !ntfyTopic || testNotification.isPending}
            className="btn-secondary inline-flex items-center gap-2"
          >
            {testNotification.isPending && testNotification.variables?.type === 'ntfy' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
            Send Test Notification
          </button>
          {testResult?.type === 'ntfy' && (
            <p className={clsx(
              'mt-2 text-sm',
              testResult.success ? 'text-success-600 dark:text-success-400' : 'text-danger-600 dark:text-danger-400'
            )}>
              {testResult.message}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// Toggle Switch Component
function ToggleSwitch({
  enabled,
  onChange,
  disabled,
}: {
  enabled: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!enabled)}
      disabled={disabled}
      className={clsx(
        'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-zinc-800',
        enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-zinc-600',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    >
      <span
        className={clsx(
          'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
          enabled ? 'translate-x-5' : 'translate-x-0'
        )}
      />
    </button>
  );
}

// Severity Toggle Component
function SeverityToggle({
  label,
  enabled,
  onChange,
  disabled,
  color,
}: {
  label: string;
  enabled: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
  color: 'danger' | 'warning' | 'info' | 'success';
}) {
  const colorClasses = {
    danger: 'bg-danger-100 dark:bg-danger-900/30 border-danger-300 dark:border-danger-700 text-danger-700 dark:text-danger-300',
    warning: 'bg-warning-100 dark:bg-warning-900/30 border-warning-300 dark:border-warning-700 text-warning-700 dark:text-warning-300',
    info: 'bg-info-100 dark:bg-info-900/30 border-info-300 dark:border-info-700 text-info-700 dark:text-info-300',
    success: 'bg-success-100 dark:bg-success-900/30 border-success-300 dark:border-success-700 text-success-700 dark:text-success-300',
  };

  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!enabled)}
      disabled={disabled}
      className={clsx(
        'px-3 py-2 rounded-lg border text-sm font-medium transition-all',
        enabled ? colorClasses[color] : 'bg-gray-100 dark:bg-zinc-700 border-gray-300 dark:border-zinc-600 text-gray-500 dark:text-gray-400',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    >
      {label}
    </button>
  );
}

// Event Toggle Component
function EventToggle({
  label,
  enabled,
  onChange,
  disabled,
}: {
  label: string;
  enabled: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!enabled)}
      disabled={disabled}
      className={clsx(
        'px-3 py-2 rounded-lg border text-sm font-medium transition-all',
        enabled
          ? 'bg-primary-100 dark:bg-primary-900/30 border-primary-300 dark:border-primary-700 text-primary-700 dark:text-primary-300'
          : 'bg-gray-100 dark:bg-zinc-700 border-gray-300 dark:border-zinc-600 text-gray-500 dark:text-gray-400',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    >
      {label}
    </button>
  );
}

function SecuritySettings() {
  const { data: status, isLoading: statusLoading } = use2FAStatus();
  const setup2FA = useSetup2FA();
  const enable2FA = useEnable2FA();
  const disable2FA = useDisable2FA();
  const regenerateCodes = useRegenerate2FABackupCodes();

  const [setupData, setSetupData] = useState<{
    secret: string;
    qr_code: string;
    backup_codes: string[];
  } | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [showDisable, setShowDisable] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [newBackupCodes, setNewBackupCodes] = useState<string[] | null>(null);
  const [error, setError] = useState('');

  const handleSetup = async () => {
    setError('');
    try {
      const data = await setup2FA.mutateAsync();
      setSetupData(data);
    } catch (e) {
      setError('Failed to start 2FA setup');
    }
  };

  const handleEnable = async () => {
    setError('');
    try {
      await enable2FA.mutateAsync(verifyCode);
      setSetupData(null);
      setVerifyCode('');
    } catch (e) {
      setError('Invalid verification code');
    }
  };

  const handleDisable = async () => {
    setError('');
    try {
      await disable2FA.mutateAsync({
        password: disablePassword,
        code: disableCode || undefined,
      });
      setShowDisable(false);
      setDisablePassword('');
      setDisableCode('');
    } catch (e) {
      setError('Failed to disable 2FA. Check your password.');
    }
  };

  const handleRegenerateCodes = async () => {
    setError('');
    try {
      const codes = await regenerateCodes.mutateAsync();
      setNewBackupCodes(codes);
    } catch (e) {
      setError('Failed to regenerate backup codes');
    }
  };

  const copyBackupCodes = (codes: string[]) => {
    navigator.clipboard.writeText(codes.join('\n'));
  };

  const downloadBackupCodes = (codes: string[]) => {
    const content = `NetGuardian AI - Backup Codes\n\nKeep these codes safe. Each code can only be used once.\n\n${codes.join('\n')}\n\nGenerated: ${new Date().toISOString()}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'netguardian-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (statusLoading) {
    return (
      <div className="card p-6 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-primary-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Two-Factor Authentication */}
      <div className="card p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Key className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Two-Factor Authentication</h2>
          </div>
          {status?.enabled ? (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-success-600 dark:text-success-400">
              <CheckCircle className="w-4 h-4" />
              Enabled
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 dark:text-gray-400">
              <XCircle className="w-4 h-4" />
              Disabled
            </span>
          )}
        </div>

        {error && (
          <div className="p-3 bg-danger-50 dark:bg-danger-900/30 rounded-lg flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-danger-600 dark:text-danger-400" />
            <p className="text-sm text-danger-700 dark:text-danger-300">{error}</p>
          </div>
        )}

        {/* Setup flow */}
        {!status?.enabled && !setupData && (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Add an extra layer of security to your account by enabling two-factor authentication using an authenticator app like Google Authenticator or Authy.
            </p>
            <button
              onClick={handleSetup}
              disabled={setup2FA.isPending}
              className="btn-primary inline-flex items-center gap-2"
            >
              {setup2FA.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Key className="w-4 h-4" />
              )}
              Set Up Two-Factor Authentication
            </button>
          </div>
        )}

        {/* QR Code and verification */}
        {setupData && !status?.enabled && (
          <div className="space-y-6">
            <div className="p-4 bg-primary-50 dark:bg-primary-900/30 rounded-lg">
              <p className="text-sm text-primary-700 dark:text-primary-300">
                Scan this QR code with your authenticator app, then enter the verification code below.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-6">
              {/* QR Code */}
              <div className="flex-shrink-0">
                <img
                  src={setupData.qr_code}
                  alt="2FA QR Code"
                  className="w-48 h-48 border border-gray-200 dark:border-zinc-600 rounded-lg"
                />
              </div>

              {/* Manual entry */}
              <div className="space-y-4 flex-1">
                <div>
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Or enter this code manually:
                  </p>
                  <code className="block p-3 bg-gray-100 dark:bg-zinc-700 rounded text-sm font-mono break-all">
                    {setupData.secret}
                  </code>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Verification Code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={verifyCode}
                    onChange={(e) => setVerifyCode(e.target.value.replace(/\s/g, ''))}
                    placeholder="Enter 6-digit code"
                    className="input w-full max-w-xs"
                    maxLength={6}
                  />
                </div>

                <button
                  onClick={handleEnable}
                  disabled={verifyCode.length < 6 || enable2FA.isPending}
                  className="btn-primary inline-flex items-center gap-2"
                >
                  {enable2FA.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                  Enable Two-Factor Authentication
                </button>
              </div>
            </div>

            {/* Backup codes */}
            <div className="border-t border-gray-200 dark:border-zinc-600 pt-6">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Backup Codes</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Save these backup codes in a secure place. You can use them to sign in if you lose access to your authenticator app.
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-4">
                {setupData.backup_codes.map((code, idx) => (
                  <code
                    key={idx}
                    className="px-3 py-2 bg-gray-100 dark:bg-zinc-700 rounded text-sm font-mono text-center"
                  >
                    {code}
                  </code>
                ))}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => copyBackupCodes(setupData.backup_codes)}
                  className="btn-secondary inline-flex items-center gap-2"
                >
                  <Copy className="w-4 h-4" />
                  Copy
                </button>
                <button
                  onClick={() => downloadBackupCodes(setupData.backup_codes)}
                  className="btn-secondary inline-flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Already enabled */}
        {status?.enabled && (
          <div className="space-y-6">
            <div className="p-4 bg-success-50 dark:bg-success-900/30 rounded-lg">
              <p className="text-sm text-success-700 dark:text-success-300">
                Two-factor authentication is enabled. You have {status.backup_codes_remaining} backup codes remaining.
              </p>
            </div>

            {/* Backup codes management */}
            <div className="flex flex-wrap gap-3">
              <button
                onClick={() => setShowBackupCodes(!showBackupCodes)}
                className="btn-secondary inline-flex items-center gap-2"
              >
                {showBackupCodes ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                {showBackupCodes ? 'Hide' : 'View'} Backup Codes
              </button>
              <button
                onClick={handleRegenerateCodes}
                disabled={regenerateCodes.isPending}
                className="btn-secondary inline-flex items-center gap-2"
              >
                {regenerateCodes.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Regenerate Codes
              </button>
              <button
                onClick={() => setShowDisable(true)}
                className="btn-secondary text-danger-600 dark:text-danger-400 hover:bg-danger-50 dark:hover:bg-danger-900/30"
              >
                Disable 2FA
              </button>
            </div>

            {/* New backup codes */}
            {newBackupCodes && (
              <div className="p-4 bg-warning-50 dark:bg-warning-900/30 rounded-lg space-y-4">
                <p className="text-sm text-warning-700 dark:text-warning-300 font-medium">
                  New backup codes generated. Your old codes are no longer valid.
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                  {newBackupCodes.map((code, idx) => (
                    <code
                      key={idx}
                      className="px-3 py-2 bg-white dark:bg-zinc-700 rounded text-sm font-mono text-center"
                    >
                      {code}
                    </code>
                  ))}
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => copyBackupCodes(newBackupCodes)}
                    className="btn-secondary inline-flex items-center gap-2"
                  >
                    <Copy className="w-4 h-4" />
                    Copy
                  </button>
                  <button
                    onClick={() => downloadBackupCodes(newBackupCodes)}
                    className="btn-secondary inline-flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Download
                  </button>
                  <button
                    onClick={() => setNewBackupCodes(null)}
                    className="btn-secondary"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}

            {/* Disable confirmation */}
            {showDisable && (
              <div className="p-4 bg-danger-50 dark:bg-danger-900/30 rounded-lg space-y-4">
                <p className="text-sm text-danger-700 dark:text-danger-300 font-medium">
                  Are you sure you want to disable two-factor authentication?
                </p>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Confirm Password
                    </label>
                    <input
                      type="password"
                      value={disablePassword}
                      onChange={(e) => setDisablePassword(e.target.value)}
                      placeholder="Enter your password"
                      className="input w-full max-w-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      2FA Code (optional)
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      value={disableCode}
                      onChange={(e) => setDisableCode(e.target.value)}
                      placeholder="6-digit code"
                      className="input w-full max-w-xs"
                      maxLength={6}
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={handleDisable}
                    disabled={!disablePassword || disable2FA.isPending}
                    className="btn-primary bg-danger-600 hover:bg-danger-700 inline-flex items-center gap-2"
                  >
                    {disable2FA.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                    Disable 2FA
                  </button>
                  <button
                    onClick={() => {
                      setShowDisable(false);
                      setDisablePassword('');
                      setDisableCode('');
                    }}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Password Section */}
      <div className="card p-6 space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Password</h2>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          To change your password, use a secure method to update it through the API.
        </p>
      </div>
    </div>
  );
}

function RetentionSettings() {
  const { data: policies, isLoading: policiesLoading, refetch: refetchPolicies } = useRetentionPolicies();
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useStorageStats();
  const updatePolicy = useUpdateRetentionPolicy();
  const runCleanup = useRunRetentionCleanup();

  const [editingPolicy, setEditingPolicy] = useState<string | null>(null);
  const [editDays, setEditDays] = useState<number>(0);
  const [cleanupResult, setCleanupResult] = useState<RetentionCleanupResult | null>(null);
  const [showCleanupConfirm, setShowCleanupConfirm] = useState(false);

  const handleEditPolicy = (policy: RetentionPolicy) => {
    setEditingPolicy(policy.id);
    setEditDays(policy.retention_days);
  };

  const handleSavePolicy = async (policyId: string) => {
    await updatePolicy.mutateAsync({ policyId, retention_days: editDays });
    setEditingPolicy(null);
  };

  const handleToggleEnabled = async (policy: RetentionPolicy) => {
    await updatePolicy.mutateAsync({ policyId: policy.id, enabled: !policy.enabled });
  };

  const handleDryRun = async () => {
    setCleanupResult(null);
    const result = await runCleanup.mutateAsync({ dryRun: true });
    setCleanupResult(result);
  };

  const handleRunCleanup = async () => {
    setCleanupResult(null);
    setShowCleanupConfirm(false);
    const result = await runCleanup.mutateAsync({ dryRun: false });
    setCleanupResult(result);
    refetchPolicies();
    refetchStats();
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  };

  if (policiesLoading || statsLoading) {
    return (
      <div className="card p-6 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-primary-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Storage Overview */}
      <div className="card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Storage Overview</h2>
          </div>
          <button
            onClick={() => { refetchStats(); refetchPolicies(); }}
            className="btn-secondary inline-flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {stats?.tables.map((table) => (
            <div
              key={table.table_name}
              className="p-4 rounded-lg border border-gray-200 dark:border-zinc-600 bg-gray-50 dark:bg-zinc-700/50"
            >
              <div className="flex items-center justify-between mb-2">
                <p className="font-medium text-gray-900 dark:text-white">{table.display_name}</p>
                {table.enabled !== undefined && (
                  <span className={clsx(
                    'text-xs px-2 py-0.5 rounded-full',
                    table.enabled
                      ? 'bg-success-100 dark:bg-success-900/30 text-success-700 dark:text-success-300'
                      : 'bg-gray-100 dark:bg-zinc-600 text-gray-600 dark:text-gray-400'
                  )}>
                    {table.enabled ? 'Active' : 'Disabled'}
                  </span>
                )}
              </div>
              {table.error ? (
                <p className="text-sm text-danger-600 dark:text-danger-400">{table.error}</p>
              ) : (
                <>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {table.row_count?.toLocaleString() ?? '—'}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {table.table_size ?? 'Unknown size'}
                  </p>
                  {table.retention_days !== undefined && (
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                      {table.retention_days === 0 ? 'Keep forever' : `${table.retention_days} day retention`}
                    </p>
                  )}
                </>
              )}
            </div>
          ))}
        </div>

        <div className="pt-4 border-t border-gray-200 dark:border-zinc-600">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Total rows across all tables: <span className="font-semibold text-gray-900 dark:text-white">{stats?.total_rows.toLocaleString()}</span>
          </p>
        </div>
      </div>

      {/* Retention Policies */}
      <div className="card p-6 space-y-4">
        <div className="flex items-center gap-3">
          <Clock className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Retention Policies</h2>
        </div>

        <div className="p-3 bg-info-50 dark:bg-info-900/30 rounded-lg">
          <p className="text-sm text-info-700 dark:text-info-300">
            Configure how long data is retained before automatic cleanup. Set to 0 days to keep data forever.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-zinc-600">
                <th className="text-left py-3 px-4 font-medium text-gray-700 dark:text-gray-300">Policy</th>
                <th className="text-left py-3 px-4 font-medium text-gray-700 dark:text-gray-300">Description</th>
                <th className="text-center py-3 px-4 font-medium text-gray-700 dark:text-gray-300">Retention</th>
                <th className="text-center py-3 px-4 font-medium text-gray-700 dark:text-gray-300">Enabled</th>
                <th className="text-left py-3 px-4 font-medium text-gray-700 dark:text-gray-300">Last Run</th>
                <th className="text-right py-3 px-4 font-medium text-gray-700 dark:text-gray-300">Last Deleted</th>
                <th className="py-3 px-4"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-zinc-600">
              {policies?.map((policy) => (
                <tr key={policy.id} className="hover:bg-gray-50 dark:hover:bg-zinc-700/50">
                  <td className="py-3 px-4">
                    <p className="font-medium text-gray-900 dark:text-white">{policy.display_name}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{policy.table_name}</p>
                  </td>
                  <td className="py-3 px-4 text-gray-600 dark:text-gray-400 max-w-xs truncate">
                    {policy.description || '—'}
                  </td>
                  <td className="py-3 px-4 text-center">
                    {editingPolicy === policy.id ? (
                      <div className="flex items-center justify-center gap-2">
                        <input
                          type="number"
                          min="0"
                          value={editDays}
                          onChange={(e) => setEditDays(parseInt(e.target.value) || 0)}
                          className="w-20 px-2 py-1 text-center border border-gray-300 dark:border-zinc-600 rounded bg-white dark:bg-zinc-700 text-gray-900 dark:text-white"
                        />
                        <span className="text-gray-500 dark:text-gray-400">days</span>
                      </div>
                    ) : (
                      <span className={clsx(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                        policy.retention_days === 0
                          ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300'
                          : 'bg-gray-100 dark:bg-zinc-600 text-gray-700 dark:text-gray-300'
                      )}>
                        {policy.retention_days === 0 ? 'Forever' : `${policy.retention_days}d`}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <button
                      onClick={() => handleToggleEnabled(policy)}
                      disabled={updatePolicy.isPending}
                      className={clsx(
                        'relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-zinc-800',
                        policy.enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-zinc-600',
                        updatePolicy.isPending && 'opacity-50 cursor-not-allowed'
                      )}
                    >
                      <span
                        className={clsx(
                          'pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
                          policy.enabled ? 'translate-x-4' : 'translate-x-0'
                        )}
                      />
                    </button>
                  </td>
                  <td className="py-3 px-4 text-gray-600 dark:text-gray-400 text-sm">
                    {formatDate(policy.last_run)}
                  </td>
                  <td className="py-3 px-4 text-right text-gray-900 dark:text-white">
                    {policy.deleted_count.toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {editingPolicy === policy.id ? (
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleSavePolicy(policy.id)}
                          disabled={updatePolicy.isPending}
                          className="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 text-sm font-medium"
                        >
                          {updatePolicy.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Save'}
                        </button>
                        <button
                          onClick={() => setEditingPolicy(null)}
                          className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 text-sm"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleEditPolicy(policy)}
                        className="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 text-sm font-medium"
                      >
                        Edit
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Cleanup */}
      <div className="card p-6 space-y-4">
        <div className="flex items-center gap-3">
          <Trash2 className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Manual Cleanup</h2>
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-400">
          Run data cleanup based on configured retention policies. Use "Preview" to see what would be deleted without making changes.
        </p>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleDryRun}
            disabled={runCleanup.isPending}
            className="btn-secondary inline-flex items-center gap-2"
          >
            {runCleanup.isPending && runCleanup.variables?.dryRun ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Eye className="w-4 h-4" />
            )}
            Preview Cleanup
          </button>
          <button
            onClick={() => setShowCleanupConfirm(true)}
            disabled={runCleanup.isPending}
            className="btn-primary bg-danger-600 hover:bg-danger-700 inline-flex items-center gap-2"
          >
            {runCleanup.isPending && !runCleanup.variables?.dryRun ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            Run Cleanup
          </button>
        </div>

        {/* Cleanup Confirmation */}
        {showCleanupConfirm && (
          <div className="p-4 bg-danger-50 dark:bg-danger-900/30 rounded-lg space-y-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-danger-600 dark:text-danger-400" />
              <p className="font-medium text-danger-700 dark:text-danger-300">Confirm Data Deletion</p>
            </div>
            <p className="text-sm text-danger-600 dark:text-danger-400">
              This will permanently delete old records based on your retention policies. This action cannot be undone.
            </p>
            <div className="flex gap-2">
              <button
                onClick={handleRunCleanup}
                disabled={runCleanup.isPending}
                className="btn-primary bg-danger-600 hover:bg-danger-700"
              >
                Yes, Delete Data
              </button>
              <button
                onClick={() => setShowCleanupConfirm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Cleanup Results */}
        {cleanupResult && (
          <div className={clsx(
            'p-4 rounded-lg space-y-3',
            cleanupResult.dry_run
              ? 'bg-info-50 dark:bg-info-900/30'
              : 'bg-success-50 dark:bg-success-900/30'
          )}>
            <div className="flex items-center justify-between">
              <p className={clsx(
                'font-medium',
                cleanupResult.dry_run
                  ? 'text-info-700 dark:text-info-300'
                  : 'text-success-700 dark:text-success-300'
              )}>
                {cleanupResult.dry_run ? 'Preview Results' : 'Cleanup Complete'}
              </p>
              <span className={clsx(
                'text-xs px-2 py-0.5 rounded-full',
                cleanupResult.dry_run
                  ? 'bg-info-100 dark:bg-info-900/50 text-info-600 dark:text-info-400'
                  : 'bg-success-100 dark:bg-success-900/50 text-success-600 dark:text-success-400'
              )}>
                {cleanupResult.dry_run ? 'DRY RUN' : 'EXECUTED'}
              </span>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <div className="text-sm">
                <span className="text-gray-600 dark:text-gray-400">Policies processed: </span>
                <span className="font-medium text-gray-900 dark:text-white">{cleanupResult.policies_processed}</span>
              </div>
              <div className="text-sm">
                <span className="text-gray-600 dark:text-gray-400">
                  {cleanupResult.dry_run ? 'Would delete: ' : 'Total deleted: '}
                </span>
                <span className="font-medium text-gray-900 dark:text-white">{cleanupResult.total_deleted.toLocaleString()} records</span>
              </div>
            </div>

            {cleanupResult.details.length > 0 && (
              <div className="border-t border-gray-200 dark:border-zinc-600 pt-3">
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Details:</p>
                <div className="space-y-1">
                  {cleanupResult.details.map((detail, idx) => (
                    <div
                      key={idx}
                      className={clsx(
                        'text-sm px-3 py-2 rounded',
                        detail.status === 'success' && 'bg-white dark:bg-zinc-700',
                        detail.status === 'skipped' && 'bg-gray-100 dark:bg-zinc-600',
                        detail.status === 'error' && 'bg-danger-100 dark:bg-danger-900/30'
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-gray-900 dark:text-white">{detail.table}</span>
                        <span className={clsx(
                          'text-xs',
                          detail.status === 'success' && 'text-success-600 dark:text-success-400',
                          detail.status === 'skipped' && 'text-gray-500 dark:text-gray-400',
                          detail.status === 'error' && 'text-danger-600 dark:text-danger-400'
                        )}>
                          {detail.status === 'success' && `${detail.deleted?.toLocaleString() ?? 0} ${cleanupResult.dry_run ? 'to delete' : 'deleted'}`}
                          {detail.status === 'skipped' && detail.reason}
                          {detail.status === 'error' && detail.error}
                        </span>
                      </div>
                      {detail.cutoff_date && (
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          Cutoff: {new Date(detail.cutoff_date).toLocaleString()}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
