import { useState } from 'react';
import { X, Plus, AlertCircle } from 'lucide-react';
import { useCreateThreatFeed } from '../api/hooks';
import type { FeedType } from '../types';

interface AddFeedModalProps {
  onClose: () => void;
}

const feedTypeOptions: { value: FeedType; label: string; description: string }[] = [
  { value: 'ip_list', label: 'IP List', description: 'Plain text file with one IP per line' },
  { value: 'url_list', label: 'URL List', description: 'Plain text file with one URL per line' },
  { value: 'csv', label: 'CSV', description: 'CSV file with configurable field mapping' },
  { value: 'json', label: 'JSON', description: 'JSON array of indicator objects' },
  { value: 'stix', label: 'STIX', description: 'STIX 2.x format threat intelligence' },
];

const authTypeOptions = [
  { value: 'none', label: 'None', description: 'No authentication required' },
  { value: 'basic', label: 'Basic Auth', description: 'Username and password' },
  { value: 'bearer', label: 'Bearer Token', description: 'Authorization header with token' },
  { value: 'api_key', label: 'API Key', description: 'Custom header with API key' },
];

export default function AddFeedModal({ onClose }: AddFeedModalProps) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [feedType, setFeedType] = useState<FeedType>('ip_list');
  const [url, setUrl] = useState('');
  const [updateInterval, setUpdateInterval] = useState(24);
  const [authType, setAuthType] = useState('none');
  const [authConfig, setAuthConfig] = useState<Record<string, string>>({});
  const [fieldMapping, setFieldMapping] = useState<Record<string, string>>({});
  const [error, setError] = useState('');

  const createFeed = useCreateThreatFeed();

  const handleSubmit = async () => {
    setError('');

    if (!name.trim()) {
      setError('Feed name is required');
      return;
    }

    if (!url.trim()) {
      setError('Feed URL is required');
      return;
    }

    try {
      await createFeed.mutateAsync({
        name: name.trim(),
        description: description.trim() || undefined,
        feed_type: feedType,
        url: url.trim(),
        enabled: true,
        update_interval_hours: updateInterval,
        auth_type: authType,
        auth_config: authConfig,
        field_mapping: feedType === 'csv' ? fieldMapping : undefined,
      });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create feed');
    }
  };

  const renderAuthFields = () => {
    switch (authType) {
      case 'basic':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Username
              </label>
              <input
                type="text"
                value={authConfig.username || ''}
                onChange={(e) => setAuthConfig({ ...authConfig, username: e.target.value })}
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Password
              </label>
              <input
                type="password"
                value={authConfig.password || ''}
                onChange={(e) => setAuthConfig({ ...authConfig, password: e.target.value })}
                className="input"
              />
            </div>
          </div>
        );
      case 'bearer':
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Bearer Token
            </label>
            <input
              type="password"
              value={authConfig.token || ''}
              onChange={(e) => setAuthConfig({ ...authConfig, token: e.target.value })}
              className="input"
              placeholder="Enter bearer token"
            />
          </div>
        );
      case 'api_key':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Header Name
              </label>
              <input
                type="text"
                value={authConfig.header_name || ''}
                onChange={(e) => setAuthConfig({ ...authConfig, header_name: e.target.value })}
                className="input"
                placeholder="e.g., X-API-Key"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                API Key
              </label>
              <input
                type="password"
                value={authConfig.api_key || ''}
                onChange={(e) => setAuthConfig({ ...authConfig, api_key: e.target.value })}
                className="input"
              />
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-zinc-800 rounded-xl shadow-xl max-w-lg w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Add Threat Intelligence Feed
          </h2>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-zinc-700 rounded"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Step Indicator */}
        <div className="px-6 pt-4">
          <div className="flex items-center justify-between">
            {[1, 2, 3].map((s) => (
              <div key={s} className="flex items-center">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    s < step
                      ? 'bg-primary-600 text-white'
                      : s === step
                      ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400 border-2 border-primary-600'
                      : 'bg-gray-100 dark:bg-zinc-700 text-gray-400'
                  }`}
                >
                  {s}
                </div>
                {s < 3 && (
                  <div
                    className={`w-full h-0.5 mx-2 ${
                      s < step ? 'bg-primary-600' : 'bg-gray-200 dark:bg-zinc-700'
                    }`}
                    style={{ width: '80px' }}
                  />
                )}
              </div>
            ))}
          </div>
          <div className="flex justify-between mt-2 text-xs text-gray-500 dark:text-gray-400">
            <span>Basic Info</span>
            <span>Feed Config</span>
            <span>Authentication</span>
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 rounded-lg flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {step === 1 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Feed Name *
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="input"
                  placeholder="e.g., AlienVault OTX IP Reputation"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="input"
                  rows={3}
                  placeholder="Optional description of the feed"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Feed Type *
                </label>
                <div className="space-y-2">
                  {feedTypeOptions.map((opt) => (
                    <label
                      key={opt.value}
                      className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                        feedType === opt.value
                          ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                          : 'border-gray-200 dark:border-zinc-700 hover:border-gray-300 dark:hover:border-zinc-600'
                      }`}
                    >
                      <input
                        type="radio"
                        name="feedType"
                        value={opt.value}
                        checked={feedType === opt.value}
                        onChange={(e) => setFeedType(e.target.value as FeedType)}
                        className="mt-0.5"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">
                          {opt.label}
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {opt.description}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Feed URL *
                </label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="input"
                  placeholder="https://example.com/feed.txt"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  The URL to fetch the threat intelligence feed from
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Update Interval (hours)
                </label>
                <input
                  type="number"
                  value={updateInterval}
                  onChange={(e) => setUpdateInterval(parseInt(e.target.value) || 24)}
                  min={1}
                  max={168}
                  className="input w-32"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  How often to fetch updates (1-168 hours)
                </p>
              </div>

              {feedType === 'csv' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    CSV Field Mapping
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
                    Map CSV column names to indicator fields
                  </p>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={fieldMapping.value_column || ''}
                        onChange={(e) =>
                          setFieldMapping({ ...fieldMapping, value_column: e.target.value })
                        }
                        className="input flex-1"
                        placeholder="Value column name"
                      />
                      <span className="text-sm text-gray-500">=</span>
                      <span className="text-sm text-gray-700 dark:text-gray-300 w-24">
                        indicator
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={fieldMapping.type_column || ''}
                        onChange={(e) =>
                          setFieldMapping({ ...fieldMapping, type_column: e.target.value })
                        }
                        className="input flex-1"
                        placeholder="Type column (optional)"
                      />
                      <span className="text-sm text-gray-500">=</span>
                      <span className="text-sm text-gray-700 dark:text-gray-300 w-24">type</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={fieldMapping.description_column || ''}
                        onChange={(e) =>
                          setFieldMapping({ ...fieldMapping, description_column: e.target.value })
                        }
                        className="input flex-1"
                        placeholder="Description column (optional)"
                      />
                      <span className="text-sm text-gray-500">=</span>
                      <span className="text-sm text-gray-700 dark:text-gray-300 w-24">
                        description
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Authentication Type
                </label>
                <div className="space-y-2">
                  {authTypeOptions.map((opt) => (
                    <label
                      key={opt.value}
                      className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                        authType === opt.value
                          ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                          : 'border-gray-200 dark:border-zinc-700 hover:border-gray-300 dark:hover:border-zinc-600'
                      }`}
                    >
                      <input
                        type="radio"
                        name="authType"
                        value={opt.value}
                        checked={authType === opt.value}
                        onChange={(e) => {
                          setAuthType(e.target.value);
                          setAuthConfig({});
                        }}
                        className="mt-0.5"
                      />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">
                          {opt.label}
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {opt.description}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {renderAuthFields()}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-4 border-t border-gray-200 dark:border-zinc-700">
          <button
            onClick={() => (step > 1 ? setStep(step - 1) : onClose())}
            className="btn-secondary"
          >
            {step > 1 ? 'Back' : 'Cancel'}
          </button>
          {step < 3 ? (
            <button
              onClick={() => setStep(step + 1)}
              disabled={step === 1 && !name.trim()}
              className="btn-primary"
            >
              Next
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              disabled={createFeed.isPending || !name.trim() || !url.trim()}
              className="btn-primary"
            >
              <Plus className="w-4 h-4 mr-2" />
              {createFeed.isPending ? 'Creating...' : 'Create Feed'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
