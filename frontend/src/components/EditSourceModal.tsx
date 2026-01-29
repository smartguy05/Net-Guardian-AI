import { useState, useEffect } from 'react';
import { X, Database, Globe, FileText, Upload, Radio, Settings } from 'lucide-react';
import { useUpdateSource } from '../api/hooks';
import type { LogSource, SourceType, ParserType } from '../types';
import clsx from 'clsx';

interface EditSourceModalProps {
  isOpen: boolean;
  onClose: () => void;
  source: LogSource | null;
}

const sourceTypeLabels: Record<SourceType, { label: string; icon: typeof Globe }> = {
  api_pull: { label: 'API Pull', icon: Globe },
  file_watch: { label: 'File Watch', icon: FileText },
  api_push: { label: 'API Push', icon: Upload },
  udp_listen: { label: 'UDP Listen', icon: Radio },
};

const parserTypeLabels: Record<ParserType, string> = {
  adguard: 'AdGuard Home',
  authentik: 'Authentik',
  unifi: 'UniFi Controller',
  pfsense: 'pfSense',
  loki: 'Grafana Loki',
  ollama: 'Ollama LLM',
  json: 'JSON',
  syslog: 'Syslog',
  nginx: 'Nginx',
  netflow: 'NetFlow',
  sflow: 'sFlow',
  custom: 'Custom (Regex)',
  endpoint: 'Endpoint',
};

export default function EditSourceModal({ isOpen, onClose, source }: EditSourceModalProps) {
  const updateSource = useUpdateSource();

  // Basic info
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  // API Pull config
  const [apiUrl, setApiUrl] = useState('');
  const [authType, setAuthType] = useState<'none' | 'basic' | 'bearer' | 'api_key'>('none');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [pollInterval, setPollInterval] = useState(30);

  // File Watch config
  const [filePath, setFilePath] = useState('');
  const [readFromEnd, setReadFromEnd] = useState(true);

  // UDP Listen config
  const [udpPort, setUdpPort] = useState(5514);
  const [udpHost, setUdpHost] = useState('0.0.0.0');

  // Errors
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Populate form when source changes
  useEffect(() => {
    if (source) {
      setName(source.name);
      setDescription(source.description || '');

      const config = source.config || {};

      if (source.source_type === 'api_pull') {
        setApiUrl((config.url as string) || '');
        setAuthType((config.auth_type as typeof authType) || 'none');
        setUsername((config.username as string) || '');
        // Password is masked, so keep empty unless user enters new one
        setPassword('');
        setApiKey('');
        // Token is masked too
        if (config.auth_type === 'bearer' || config.auth_type === 'api_key') {
          setApiKey('');
        }
        setPollInterval((config.poll_interval_seconds as number) || 30);
      } else if (source.source_type === 'file_watch') {
        setFilePath((config.path as string) || '');
        setReadFromEnd(config.read_from_end !== false); // Default to true if not set
      } else if (source.source_type === 'udp_listen') {
        setUdpPort((config.port as number) || 5514);
        setUdpHost((config.host as string) || '0.0.0.0');
      }

      setErrors({});
    }
  }, [source]);

  const handleClose = () => {
    setErrors({});
    onClose();
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!name.trim()) newErrors.name = 'Name is required';

    if (source?.source_type === 'api_pull') {
      if (!apiUrl.trim()) newErrors.apiUrl = 'URL is required';
      else if (!apiUrl.startsWith('http://') && !apiUrl.startsWith('https://')) {
        newErrors.apiUrl = 'URL must start with http:// or https://';
      }
      // Only validate auth fields if auth type requires them
      // Note: We allow empty password/token since they might keep the existing value
    }

    if (source?.source_type === 'file_watch') {
      if (!filePath.trim()) newErrors.filePath = 'File path is required';
      else if (!filePath.startsWith('/')) newErrors.filePath = 'Path must be absolute (start with /)';
    }

    if (source?.source_type === 'udp_listen') {
      if (!udpPort || udpPort < 1 || udpPort > 65535) {
        newErrors.udpPort = 'Port must be between 1 and 65535';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const buildConfig = (): Record<string, unknown> => {
    if (!source) return {};

    if (source.source_type === 'api_pull') {
      const config: Record<string, unknown> = {
        url: apiUrl,
        auth_type: authType,
        poll_interval_seconds: pollInterval,
      };

      if (authType === 'basic') {
        config.username = username;
        // Only include password if user provided a new one
        if (password) {
          config.password = password;
        } else if (source.config?.password) {
          // Keep existing masked password indicator - backend will preserve
          config.password = source.config.password;
        }
      }
      if (authType === 'bearer') {
        if (apiKey) {
          config.token = apiKey;
        } else if (source.config?.token) {
          config.token = source.config.token;
        }
      }
      if (authType === 'api_key') {
        if (apiKey) {
          config.api_key = apiKey;
        } else if (source.config?.api_key) {
          config.api_key = source.config.api_key;
        }
        config.api_key_header = (source.config?.api_key_header as string) || 'X-API-Key';
      }
      return config;
    }

    if (source.source_type === 'file_watch') {
      return {
        path: filePath,
        follow: true,
        encoding: 'utf-8',
        read_from_end: readFromEnd,
      };
    }

    if (source.source_type === 'udp_listen') {
      return {
        port: udpPort,
        host: udpHost,
      };
    }

    // api_push - no config needed
    return {};
  };

  const handleSubmit = async () => {
    if (!source || !validateForm()) return;

    try {
      await updateSource.mutateAsync({
        id: source.id,
        name,
        description: description || undefined,
        config: buildConfig(),
      });
      handleClose();
    } catch (error) {
      console.error('Failed to update source:', error);
      setErrors({ submit: 'Failed to update source. Please try again.' });
    }
  };

  if (!isOpen || !source) return null;

  const sourceTypeInfo = sourceTypeLabels[source.source_type];
  const SourceIcon = sourceTypeInfo?.icon || Settings;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        {/* Backdrop */}
        <div
          className="fixed inset-0 bg-black/50 transition-opacity"
          onClick={handleClose}
        />

        {/* Modal */}
        <div className="relative bg-white dark:bg-zinc-800 rounded-xl shadow-xl w-full max-w-lg">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Database className="w-5 h-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Edit Log Source</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">{source.id}</p>
              </div>
            </div>
            <button
              onClick={handleClose}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-4 space-y-4">
            {/* Source Type & Parser (read-only info) */}
            <div className="p-3 bg-gray-50 dark:bg-zinc-900 rounded-lg">
              <div className="flex items-center gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <SourceIcon className="w-4 h-4 text-gray-500 dark:text-gray-400" />
                  <span className="text-gray-600 dark:text-gray-400">Type:</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {sourceTypeInfo?.label || source.source_type}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-600 dark:text-gray-400">Parser:</span>
                  <span className="font-medium text-gray-900 dark:text-white capitalize">
                    {parserTypeLabels[source.parser_type] || source.parser_type}
                  </span>
                </div>
              </div>
            </div>

            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Display Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., AdGuard Home DNS"
                className={clsx('input', errors.name && 'border-danger-500')}
              />
              {errors.name && <p className="mt-1 text-sm text-danger-600">{errors.name}</p>}
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description <span className="text-gray-400 dark:text-gray-500">(optional)</span>
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of this log source"
                rows={2}
                className="input"
              />
            </div>

            {/* API Pull Configuration */}
            {source.source_type === 'api_pull' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    API URL
                  </label>
                  <input
                    type="url"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    placeholder="http://192.168.1.1:3000"
                    className={clsx('input', errors.apiUrl && 'border-danger-500')}
                  />
                  {errors.apiUrl && <p className="mt-1 text-sm text-danger-600">{errors.apiUrl}</p>}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Authentication
                  </label>
                  <select
                    value={authType}
                    onChange={(e) => setAuthType(e.target.value as typeof authType)}
                    className="input"
                  >
                    <option value="none">None</option>
                    <option value="basic">Basic Auth (Username/Password)</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="api_key">API Key</option>
                  </select>
                </div>

                {authType === 'basic' && (
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Username
                      </label>
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className={clsx('input', errors.username && 'border-danger-500')}
                      />
                      {errors.username && <p className="mt-1 text-sm text-danger-600">{errors.username}</p>}
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Password
                      </label>
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Leave empty to keep current"
                        className={clsx('input', errors.password && 'border-danger-500')}
                      />
                      {errors.password && <p className="mt-1 text-sm text-danger-600">{errors.password}</p>}
                    </div>
                  </div>
                )}

                {(authType === 'bearer' || authType === 'api_key') && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      {authType === 'bearer' ? 'Bearer Token' : 'API Key'}
                    </label>
                    <input
                      type="password"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="Leave empty to keep current"
                      className={clsx('input', errors.apiKey && 'border-danger-500')}
                    />
                    {errors.apiKey && <p className="mt-1 text-sm text-danger-600">{errors.apiKey}</p>}
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Poll Interval (seconds)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={300}
                    value={pollInterval}
                    onChange={(e) => setPollInterval(parseInt(e.target.value) || 30)}
                    className="input w-32"
                  />
                </div>
              </>
            )}

            {/* File Watch Configuration */}
            {source.source_type === 'file_watch' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Log File Path
                  </label>
                  <input
                    type="text"
                    value={filePath}
                    onChange={(e) => setFilePath(e.target.value)}
                    placeholder="/logs/pfsense/filter.log"
                    className={clsx('input', errors.filePath && 'border-danger-500')}
                  />
                  {errors.filePath && <p className="mt-1 text-sm text-danger-600">{errors.filePath}</p>}
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Path inside the container. Mount external logs to /logs directory.
                  </p>
                </div>

                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    id="editReadFromEnd"
                    checked={readFromEnd}
                    onChange={(e) => setReadFromEnd(e.target.checked)}
                    className="mt-1 h-4 w-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                  />
                  <div>
                    <label
                      htmlFor="editReadFromEnd"
                      className="block text-sm font-medium text-gray-700 dark:text-gray-300"
                    >
                      Read from end of file
                    </label>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      When enabled, only new log entries will be collected. Disable to read existing entries from the beginning of the file.
                    </p>
                  </div>
                </div>
              </>
            )}

            {/* UDP Listen Configuration */}
            {source.source_type === 'udp_listen' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    UDP Port
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={udpPort}
                    onChange={(e) => setUdpPort(parseInt(e.target.value) || 5514)}
                    className={clsx('input w-32', errors.udpPort && 'border-danger-500')}
                  />
                  {errors.udpPort && <p className="mt-1 text-sm text-danger-600">{errors.udpPort}</p>}
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Port to listen on. Default: 5514 (avoids privileged port 514)
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Bind Address
                  </label>
                  <input
                    type="text"
                    value={udpHost}
                    onChange={(e) => setUdpHost(e.target.value)}
                    placeholder="0.0.0.0"
                    className="input w-48"
                  />
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    IP to bind to. Use 0.0.0.0 for all interfaces.
                  </p>
                </div>

                <div className="p-4 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
                  <p className="text-sm text-amber-800 dark:text-amber-200 font-medium mb-2">
                    Important: Expose the UDP port in Docker
                  </p>
                  <p className="text-xs text-amber-700 dark:text-amber-300 mb-2">
                    Add this port mapping to your collector container:
                  </p>
                  <code className="block text-xs bg-white dark:bg-zinc-800 p-2 rounded border border-gray-200 dark:border-zinc-600 text-gray-800 dark:text-gray-200">
                    ports:<br />
                    &nbsp;&nbsp;- "{udpPort}:{udpPort}/udp"
                  </code>
                </div>
              </>
            )}

            {/* API Push Info */}
            {source.source_type === 'api_push' && (
              <div className="p-4 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
                <p className="text-sm text-primary-800 dark:text-primary-200">
                  API Push sources receive logs via HTTP. The API key cannot be changed.
                </p>
                <p className="mt-2 text-xs text-primary-600 dark:text-primary-400">
                  External services push logs to POST /api/v1/logs/ingest with the X-API-Key header.
                </p>
              </div>
            )}

            {errors.submit && (
              <div className="p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
                <p className="text-sm text-danger-700 dark:text-danger-400">{errors.submit}</p>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 p-4 border-t border-gray-200 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800/50 rounded-b-xl">
            <button
              type="button"
              onClick={handleClose}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={updateSource.isPending}
              className="btn-primary"
            >
              {updateSource.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
