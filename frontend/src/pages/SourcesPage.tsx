import { useState } from 'react';
import {
  Database,
  Plus,
  RefreshCw,
  Trash2,
  Power,
  PowerOff,
  Copy,
  Check,
} from 'lucide-react';
import { useSources, useUpdateSource, useDeleteSource } from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { LogSource } from '../types';
import AddSourceModal from '../components/AddSourceModal';

const sourceTypeLabels: Record<string, string> = {
  api_pull: 'API Pull',
  file_watch: 'File Watch',
  api_push: 'API Push',
};

function SourceCard({ source }: { source: LogSource }) {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';
  const updateSource = useUpdateSource();
  const deleteSource = useDeleteSource();
  const [copied, setCopied] = useState(false);

  const handleToggle = () => {
    updateSource.mutate({ id: source.id, enabled: !source.enabled });
  };

  const handleDelete = () => {
    if (confirm(`Delete source "${source.name}"? This cannot be undone.`)) {
      deleteSource.mutate(source.id);
    }
  };

  const copyApiKey = () => {
    if (source.api_key) {
      navigator.clipboard.writeText(source.api_key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold text-gray-900">{source.name}</h3>
            <span
              className={clsx(
                'badge',
                source.enabled ? 'badge-success' : 'bg-gray-100 text-gray-500'
              )}
            >
              {source.enabled ? 'Active' : 'Disabled'}
            </span>
          </div>

          {source.description && (
            <p className="mt-1 text-sm text-gray-600">{source.description}</p>
          )}

          <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Type</span>
              <p className="font-medium text-gray-900">
                {sourceTypeLabels[source.source_type] || source.source_type}
              </p>
            </div>
            <div>
              <span className="text-gray-500">Parser</span>
              <p className="font-medium text-gray-900 capitalize">
                {source.parser_type}
              </p>
            </div>
            <div>
              <span className="text-gray-500">Events</span>
              <p className="font-medium text-gray-900">
                {source.event_count.toLocaleString()}
              </p>
            </div>
            <div>
              <span className="text-gray-500">Last Event</span>
              <p className="font-medium text-gray-900">
                {source.last_event_at
                  ? formatDistanceToNow(new Date(source.last_event_at), {
                      addSuffix: true,
                    })
                  : 'Never'}
              </p>
            </div>
          </div>

          {source.last_error && (
            <div className="mt-4 p-3 bg-danger-50 border border-danger-200 rounded-lg">
              <p className="text-sm text-danger-700">{source.last_error}</p>
            </div>
          )}

          {source.source_type === 'api_push' && source.api_key && (
            <div className="mt-4 p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <span className="text-xs text-gray-500">API Key</span>
                  <p className="font-mono text-sm text-gray-900 truncate">
                    {source.api_key}
                  </p>
                </div>
                <button
                  onClick={copyApiKey}
                  className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
                >
                  {copied ? (
                    <Check className="w-4 h-4 text-success-600" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>
          )}
        </div>

        {isAdmin && (
          <div className="flex flex-col gap-2">
            <button
              onClick={handleToggle}
              disabled={updateSource.isPending}
              className={clsx(
                'btn text-xs px-3 py-1.5',
                source.enabled
                  ? 'bg-warning-50 text-warning-700 hover:bg-warning-100'
                  : 'bg-success-50 text-success-700 hover:bg-success-100'
              )}
            >
              {source.enabled ? (
                <>
                  <PowerOff className="w-3 h-3 mr-1" />
                  Disable
                </>
              ) : (
                <>
                  <Power className="w-3 h-3 mr-1" />
                  Enable
                </>
              )}
            </button>
            <button
              onClick={handleDelete}
              disabled={deleteSource.isPending}
              className="btn-danger text-xs px-3 py-1.5"
            >
              <Trash2 className="w-3 h-3 mr-1" />
              Delete
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function SourcesPage() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const { data, isLoading, refetch, isFetching } = useSources();

  const activeCount = data?.items.filter((s) => s.enabled).length || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Log Sources</h1>
          <p className="text-gray-500">
            {activeCount} of {data?.total || 0} sources active
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary"
          >
            <RefreshCw
              className={clsx('w-4 h-4 mr-2', isFetching && 'animate-spin')}
            />
            Refresh
          </button>
          {isAdmin && (
            <button
              className="btn-primary"
              onClick={() => setIsAddModalOpen(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Source
            </button>
          )}
        </div>
      </div>

      {!isAdmin && (
        <div className="p-4 bg-primary-50 border border-primary-200 rounded-lg">
          <p className="text-sm text-primary-700">
            Only administrators can manage log sources. Contact your admin to add
            or modify sources.
          </p>
        </div>
      )}

      {/* Source cards */}
      <div className="space-y-4">
        {isLoading ? (
          [...Array(2)].map((_, i) => (
            <div key={i} className="card p-6">
              <div className="animate-pulse space-y-3">
                <div className="h-6 bg-gray-100 rounded w-1/3" />
                <div className="h-4 bg-gray-100 rounded w-2/3" />
                <div className="grid grid-cols-4 gap-4">
                  {[...Array(4)].map((_, j) => (
                    <div key={j} className="h-12 bg-gray-100 rounded" />
                  ))}
                </div>
              </div>
            </div>
          ))
        ) : data?.items.length ? (
          data.items.map((source) => (
            <SourceCard key={source.id} source={source} />
          ))
        ) : (
          <div className="card p-12 text-center">
            <Database className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p className="text-gray-500">No log sources configured</p>
            {isAdmin && (
              <p className="text-sm text-gray-400 mt-2">
                Add a source to start collecting logs
              </p>
            )}
          </div>
        )}
      </div>

      {/* Add Source Modal */}
      <AddSourceModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
      />
    </div>
  );
}
