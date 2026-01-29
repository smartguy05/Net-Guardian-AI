import { useState } from 'react';
import { X, Database, Globe, FileText, Upload, Radio } from 'lucide-react';
import { useCreateSource } from '../api/hooks';
import type { SourceType, ParserType } from '../types';
import clsx from 'clsx';

interface AddSourceModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const sourceTypeOptions: { value: SourceType; label: string; description: string; icon: typeof Globe }[] = [
  {
    value: 'api_pull',
    label: 'API Pull',
    description: 'Poll a REST API for logs (AdGuard, UniFi, etc.)',
    icon: Globe,
  },
  {
    value: 'file_watch',
    label: 'File Watch',
    description: 'Monitor a mounted log file directory',
    icon: FileText,
  },
  {
    value: 'api_push',
    label: 'API Push',
    description: 'Receive logs via HTTP from external services',
    icon: Upload,
  },
  {
    value: 'udp_listen',
    label: 'UDP Listen',
    description: 'Receive syslog/NetFlow/sFlow via UDP (Synology, routers, etc.)',
    icon: Radio,
  },
];

const parserTypeOptions: { value: ParserType; label: string; sourceTypes: SourceType[] }[] = [
  { value: 'adguard', label: 'AdGuard Home', sourceTypes: ['api_pull'] },
  { value: 'authentik', label: 'Authentik', sourceTypes: ['api_pull'] },
  { value: 'unifi', label: 'UniFi Controller', sourceTypes: ['api_pull'] },
  { value: 'pfsense', label: 'pfSense', sourceTypes: ['api_pull', 'file_watch'] },
  { value: 'loki', label: 'Grafana Loki', sourceTypes: ['api_pull'] },
  { value: 'ollama', label: 'Ollama LLM', sourceTypes: ['api_pull'] },
  { value: 'json', label: 'JSON', sourceTypes: ['api_pull', 'file_watch', 'api_push'] },
  { value: 'syslog', label: 'Syslog', sourceTypes: ['file_watch', 'api_push', 'udp_listen'] },
  { value: 'nginx', label: 'Nginx', sourceTypes: ['file_watch'] },
  { value: 'netflow', label: 'NetFlow', sourceTypes: ['udp_listen'] },
  { value: 'sflow', label: 'sFlow', sourceTypes: ['udp_listen'] },
  { value: 'custom', label: 'Custom (Regex)', sourceTypes: ['file_watch', 'api_push'] },
];

export default function AddSourceModal({ isOpen, onClose }: AddSourceModalProps) {
  const createSource = useCreateSource();

  const [step, setStep] = useState(1);
  const [sourceType, setSourceType] = useState<SourceType>('api_pull');
  const [parserType, setParserType] = useState<ParserType>('adguard');

  // Basic info
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  // API Pull config
  const [apiUrl, setApiUrl] = useState('');
  const [authType, setAuthType] = useState<'none' | 'basic' | 'bearer' | 'api_key'>('basic');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [pollInterval, setPollInterval] = useState(30);

  // File Watch config
  const [filePath, setFilePath] = useState('');
  const [watchDirectory, setWatchDirectory] = useState(false);
  const [filePattern, setFilePattern] = useState('*.log');
  const [readFromEnd, setReadFromEnd] = useState(true);

  // UDP Listen config
  const [udpPort, setUdpPort] = useState(5514);
  const [udpHost, setUdpHost] = useState('0.0.0.0');

  // Errors
  const [errors, setErrors] = useState<Record<string, string>>({});

  const resetForm = () => {
    setStep(1);
    setSourceType('api_pull');
    setParserType('adguard');
    setId('');
    setName('');
    setDescription('');
    setApiUrl('');
    setAuthType('basic');
    setUsername('');
    setPassword('');
    setApiKey('');
    setPollInterval(30);
    setFilePath('');
    setWatchDirectory(false);
    setFilePattern('*.log');
    setReadFromEnd(true);
    setUdpPort(5514);
    setUdpHost('0.0.0.0');
    setErrors({});
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const validateStep1 = () => {
    const newErrors: Record<string, string> = {};
    if (!id.trim()) newErrors.id = 'ID is required';
    else if (!/^[a-z0-9-]+$/.test(id)) newErrors.id = 'ID must be lowercase letters, numbers, and hyphens only';
    if (!name.trim()) newErrors.name = 'Name is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validateStep2 = () => {
    const newErrors: Record<string, string> = {};

    if (sourceType === 'api_pull') {
      if (!apiUrl.trim()) newErrors.apiUrl = 'URL is required';
      else if (!apiUrl.startsWith('http://') && !apiUrl.startsWith('https://')) {
        newErrors.apiUrl = 'URL must start with http:// or https://';
      }
      if (authType === 'basic') {
        if (!username.trim()) newErrors.username = 'Username is required';
        if (!password.trim()) newErrors.password = 'Password is required';
      }
      if (authType === 'bearer' || authType === 'api_key') {
        if (!apiKey.trim()) newErrors.apiKey = 'API key/token is required';
      }
    }

    if (sourceType === 'file_watch') {
      if (!filePath.trim()) newErrors.filePath = watchDirectory ? 'Directory path is required' : 'File path is required';
      else if (!filePath.startsWith('/')) newErrors.filePath = 'Path must be absolute (start with /)';
      if (watchDirectory && filePattern.trim() && !/^[a-zA-Z0-9*?._\-\[\]]+$/.test(filePattern)) {
        newErrors.filePattern = 'Invalid glob pattern';
      }
    }

    if (sourceType === 'udp_listen') {
      if (!udpPort || udpPort < 1 || udpPort > 65535) {
        newErrors.udpPort = 'Port must be between 1 and 65535';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleNext = () => {
    if (step === 1 && validateStep1()) {
      setStep(2);
    }
  };

  const handleBack = () => {
    setStep(1);
    setErrors({});
  };

  const buildConfig = (): Record<string, unknown> => {
    if (sourceType === 'api_pull') {
      const config: Record<string, unknown> = {
        url: apiUrl,
        auth_type: authType,
        poll_interval_seconds: pollInterval,
      };
      if (authType === 'basic') {
        config.username = username;
        config.password = password;
      }
      if (authType === 'bearer') {
        config.token = apiKey;
      }
      if (authType === 'api_key') {
        config.api_key = apiKey;
        config.api_key_header = 'X-API-Key';
      }
      return config;
    }

    if (sourceType === 'file_watch') {
      const config: Record<string, unknown> = {
        path: filePath,
        follow: true,
        encoding: 'utf-8',
        read_from_end: readFromEnd,
      };
      if (watchDirectory && filePattern.trim()) {
        config.file_pattern = filePattern;
      }
      return config;
    }

    if (sourceType === 'udp_listen') {
      return {
        port: udpPort,
        host: udpHost,
      };
    }

    // api_push - no config needed, API key auto-generated
    return {};
  };

  const handleSubmit = async () => {
    if (!validateStep2()) return;

    try {
      await createSource.mutateAsync({
        id,
        name,
        description: description || undefined,
        source_type: sourceType,
        parser_type: parserType,
        config: buildConfig(),
        parser_config: {},
      });
      handleClose();
    } catch (error) {
      console.error('Failed to create source:', error);
      setErrors({ submit: 'Failed to create source. Please try again.' });
    }
  };

  // Filter parser options based on selected source type
  const availableParsers = parserTypeOptions.filter(p => p.sourceTypes.includes(sourceType));

  // Auto-select first available parser when source type changes
  const handleSourceTypeChange = (type: SourceType) => {
    setSourceType(type);
    const available = parserTypeOptions.filter(p => p.sourceTypes.includes(type));
    if (available.length > 0 && !available.find(p => p.value === parserType)) {
      setParserType(available[0].value);
    }
  };

  if (!isOpen) return null;

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
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Add Log Source</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">Step {step} of 2</p>
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
          <div className="p-4">
            {step === 1 ? (
              <div className="space-y-4">
                {/* Source Type Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Source Type
                  </label>
                  <div className="grid grid-cols-1 gap-2">
                    {sourceTypeOptions.map((option) => {
                      const Icon = option.icon;
                      return (
                        <button
                          key={option.value}
                          type="button"
                          onClick={() => handleSourceTypeChange(option.value)}
                          className={clsx(
                            'flex items-start gap-3 p-3 rounded-lg border-2 text-left transition-colors',
                            sourceType === option.value
                              ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                              : 'border-gray-200 dark:border-zinc-600 hover:border-gray-300 dark:hover:border-zinc-500'
                          )}
                        >
                          <Icon className={clsx(
                            'w-5 h-5 mt-0.5',
                            sourceType === option.value ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400 dark:text-gray-500'
                          )} />
                          <div>
                            <div className={clsx(
                              'font-medium',
                              sourceType === option.value ? 'text-primary-900 dark:text-primary-100' : 'text-gray-900 dark:text-white'
                            )}>
                              {option.label}
                            </div>
                            <div className="text-sm text-gray-500 dark:text-gray-400">{option.description}</div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Parser Type */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Parser Type
                  </label>
                  <select
                    value={parserType}
                    onChange={(e) => setParserType(e.target.value as ParserType)}
                    className="input"
                  >
                    {availableParsers.map((parser) => (
                      <option key={parser.value} value={parser.value}>
                        {parser.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* ID */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Source ID
                  </label>
                  <input
                    type="text"
                    value={id}
                    onChange={(e) => setId(e.target.value.toLowerCase())}
                    placeholder="e.g., adguard-home, pfsense-firewall"
                    className={clsx('input', errors.id && 'border-danger-500')}
                  />
                  {errors.id && <p className="mt-1 text-sm text-danger-600">{errors.id}</p>}
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Unique identifier (lowercase, hyphens allowed)
                  </p>
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
              </div>
            ) : (
              <div className="space-y-4">
                {/* API Pull Configuration */}
                {sourceType === 'api_pull' && (
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
                {sourceType === 'file_watch' && (
                  <>
                    <div className="flex items-start gap-3">
                      <input
                        type="checkbox"
                        id="watchDirectory"
                        checked={watchDirectory}
                        onChange={(e) => setWatchDirectory(e.target.checked)}
                        className="mt-1 h-4 w-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                      />
                      <div>
                        <label
                          htmlFor="watchDirectory"
                          className="block text-sm font-medium text-gray-700 dark:text-gray-300"
                        >
                          Watch Directory
                        </label>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          Monitor all files in a directory that match a pattern (e.g., for rotated logs).
                        </p>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        {watchDirectory ? 'Log Directory Path' : 'Log File Path'}
                      </label>
                      <input
                        type="text"
                        value={filePath}
                        onChange={(e) => setFilePath(e.target.value)}
                        placeholder={watchDirectory ? '/logs/myapp/' : '/logs/pfsense/filter.log'}
                        className={clsx('input', errors.filePath && 'border-danger-500')}
                      />
                      {errors.filePath && <p className="mt-1 text-sm text-danger-600">{errors.filePath}</p>}
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                        Path inside the container. Mount external logs to /logs directory.
                      </p>
                    </div>

                    {watchDirectory && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          File Pattern
                        </label>
                        <input
                          type="text"
                          value={filePattern}
                          onChange={(e) => setFilePattern(e.target.value)}
                          placeholder="*.log"
                          className={clsx('input w-48', errors.filePattern && 'border-danger-500')}
                        />
                        {errors.filePattern && <p className="mt-1 text-sm text-danger-600">{errors.filePattern}</p>}
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                          Glob pattern to filter files (e.g., *.log, app-*.log, access.log.*)
                        </p>
                      </div>
                    )}

                    <div className="flex items-start gap-3">
                      <input
                        type="checkbox"
                        id="readFromEnd"
                        checked={readFromEnd}
                        onChange={(e) => setReadFromEnd(e.target.checked)}
                        className="mt-1 h-4 w-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                      />
                      <div>
                        <label
                          htmlFor="readFromEnd"
                          className="block text-sm font-medium text-gray-700 dark:text-gray-300"
                        >
                          Read from end of file
                        </label>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          When enabled, only new log entries will be collected. Disable to read existing entries from the beginning.
                        </p>
                      </div>
                    </div>
                  </>
                )}

                {/* UDP Listen Configuration */}
                {sourceType === 'udp_listen' && (
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
                {sourceType === 'api_push' && (
                  <div className="p-4 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
                    <p className="text-sm text-primary-800 dark:text-primary-200">
                      An API key will be automatically generated for this source.
                      External services can push logs to:
                    </p>
                    <code className="mt-2 block text-xs bg-white dark:bg-zinc-800 p-2 rounded border border-gray-200 dark:border-zinc-600 text-gray-800 dark:text-gray-200">
                      POST /api/v1/logs/ingest
                    </code>
                    <p className="mt-2 text-xs text-primary-600 dark:text-primary-400">
                      Include the API key in the X-API-Key header.
                    </p>
                  </div>
                )}

                {errors.submit && (
                  <div className="p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
                    <p className="text-sm text-danger-700 dark:text-danger-400">{errors.submit}</p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between p-4 border-t border-gray-200 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800/50 rounded-b-xl">
            {step === 1 ? (
              <>
                <button
                  type="button"
                  onClick={handleClose}
                  className="btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleNext}
                  className="btn-primary"
                >
                  Next
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={handleBack}
                  className="btn-secondary"
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={createSource.isPending}
                  className="btn-primary"
                >
                  {createSource.isPending ? 'Creating...' : 'Create Source'}
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
