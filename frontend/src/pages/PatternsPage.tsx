import { useState } from 'react';
import { format, formatDistanceToNow } from 'date-fns';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  EyeOff,
  Filter,
  Hash,
  RefreshCw,
  Search,
  Check,
} from 'lucide-react';
import clsx from 'clsx';
import { usePatterns, useUpdatePattern, useSources, useSemanticStats } from '../api/hooks';
import Pagination from '../components/Pagination';
import type { LogPattern, LogSource } from '../types';

interface PatternRowProps {
  pattern: LogPattern;
  sources: LogSource[];
  onToggleIgnore: (patternId: string, currentIgnored: boolean) => void;
  isUpdating: boolean;
}

function PatternRow({ pattern, sources, onToggleIgnore, isUpdating }: PatternRowProps) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const source = sources.find((s) => s.id === pattern.source_id);
  const sourceName = source?.name || pattern.source_id;

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(pattern.normalized_pattern);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <tr
        className={clsx(
          'hover:bg-gray-50 dark:hover:bg-zinc-800/50 cursor-pointer',
          pattern.is_ignored && 'opacity-60'
        )}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-gray-400 flex-shrink-0" />
            ) : (
              <ChevronRight className="h-4 w-4 text-gray-400 flex-shrink-0" />
            )}
            <div className="max-w-md">
              <code className="text-xs text-gray-800 dark:text-gray-200 bg-gray-100 dark:bg-zinc-800 px-2 py-1 rounded block truncate">
                {pattern.normalized_pattern}
              </code>
            </div>
          </div>
        </td>
        <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">
          <span className="truncate max-w-[120px]" title={sourceName}>
            {sourceName}
          </span>
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span
            className={clsx(
              'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
              pattern.occurrence_count < 3
                ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300'
                : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
            )}
          >
            {pattern.occurrence_count.toLocaleString()}
            {pattern.occurrence_count < 3 && (
              <AlertTriangle className="h-3 w-3 ml-1" />
            )}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300 whitespace-nowrap">
          {format(new Date(pattern.first_seen), 'MMM d, yyyy')}
        </td>
        <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300 whitespace-nowrap">
          {format(new Date(pattern.last_seen), 'MMM d, HH:mm')}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          {pattern.is_ignored ? (
            <span className="inline-flex items-center gap-1 text-gray-500 dark:text-gray-400">
              <EyeOff className="h-4 w-4" />
              Ignored
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400">
              <Eye className="h-4 w-4" />
              Active
            </span>
          )}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggleIgnore(pattern.id, pattern.is_ignored);
            }}
            disabled={isUpdating}
            className={clsx(
              'btn px-2 py-1 text-xs flex items-center gap-1',
              pattern.is_ignored ? 'btn-primary' : 'btn-secondary'
            )}
          >
            {pattern.is_ignored ? (
              <>
                <Eye className="h-3 w-3" />
                Unignore
              </>
            ) : (
              <>
                <EyeOff className="h-3 w-3" />
                Ignore
              </>
            )}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-4 py-4 bg-gray-50 dark:bg-zinc-800">
            <div className="space-y-4">
              {/* Full Pattern */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
                    <Hash className="h-4 w-4 text-primary-500" />
                    Normalized Pattern
                  </div>
                  <button
                    onClick={handleCopy}
                    className="btn btn-secondary px-2 py-1 text-xs flex items-center gap-1"
                  >
                    {copied ? (
                      <>
                        <Check className="h-3 w-3" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        Copy
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-3 bg-gray-900 text-gray-100 rounded-lg overflow-x-auto text-xs whitespace-pre-wrap break-all">
                  {pattern.normalized_pattern}
                </pre>
              </div>

              {/* Metadata */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Source:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">{sourceName}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Pattern Hash:</span>
                  <span className="ml-2 font-mono text-xs text-gray-900 dark:text-white">
                    {pattern.pattern_hash.substring(0, 12)}...
                  </span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Occurrences:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">
                    {pattern.occurrence_count.toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Status:</span>
                  <span className={clsx(
                    'ml-2',
                    pattern.is_ignored ? 'text-gray-500' : 'text-green-600 dark:text-green-400'
                  )}>
                    {pattern.is_ignored ? 'Ignored' : 'Active'}
                  </span>
                </div>
              </div>

              {/* Timestamps */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-gray-500 dark:text-gray-400">First Seen:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">
                    {format(new Date(pattern.first_seen), 'MMM d, yyyy HH:mm:ss')}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Last Seen:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">
                    {format(new Date(pattern.last_seen), 'MMM d, yyyy HH:mm:ss')}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Last Activity:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">
                    {formatDistanceToNow(new Date(pattern.last_seen), { addSuffix: true })}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Pattern ID:</span>
                  <span className="ml-2 font-mono text-xs text-gray-900 dark:text-white">
                    {pattern.id.substring(0, 8)}...
                  </span>
                </div>
              </div>

              {/* Rare Pattern Warning */}
              {pattern.occurrence_count < 3 && (
                <div className="flex items-center gap-2 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg text-yellow-800 dark:text-yellow-200 text-sm">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                  <span>
                    This is a rare pattern (seen only {pattern.occurrence_count} time{pattern.occurrence_count !== 1 ? 's' : ''}).
                    Rare patterns may indicate unusual or suspicious activity.
                  </span>
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center gap-3 pt-2 border-t border-gray-200 dark:border-zinc-700">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onToggleIgnore(pattern.id, pattern.is_ignored);
                  }}
                  disabled={isUpdating}
                  className={clsx(
                    'btn flex items-center gap-2',
                    pattern.is_ignored ? 'btn-primary' : 'btn-secondary'
                  )}
                >
                  {pattern.is_ignored ? (
                    <>
                      <Eye className="h-4 w-4" />
                      Unignore Pattern
                    </>
                  ) : (
                    <>
                      <EyeOff className="h-4 w-4" />
                      Ignore Pattern
                    </>
                  )}
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function PatternsPage() {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [ignoredFilter, setIgnoredFilter] = useState<string>('');
  const [rareOnly, setRareOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchInput, setSearchInput] = useState('');

  const { data: stats } = useSemanticStats();
  const { data: sources } = useSources();
  const { data: patterns, isLoading, refetch } = usePatterns({
    source_id: sourceFilter || undefined,
    is_ignored: ignoredFilter === 'ignored' ? true : ignoredFilter === 'active' ? false : undefined,
    rare_only: rareOnly,
    rarity_threshold: 3,
    search: searchQuery || undefined,
    page,
    page_size: pageSize,
  });

  const updatePattern = useUpdatePattern();

  const handleToggleIgnore = async (patternId: string, currentIgnored: boolean) => {
    await updatePattern.mutateAsync({
      patternId,
      is_ignored: !currentIgnored,
    });
  };

  const handleSearch = () => {
    setSearchQuery(searchInput);
    setPage(1);
  };

  const totalPages = patterns ? Math.ceil(patterns.total / pageSize) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Log Patterns
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            View and manage learned log patterns from semantic analysis
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="btn btn-secondary flex items-center gap-2"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Stats Summary */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30">
                <Hash className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Total Patterns</p>
                <p className="text-xl font-semibold text-gray-900 dark:text-white">
                  {stats.total_patterns.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-100 dark:bg-yellow-900/30">
                <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Irregular Detected</p>
                <p className="text-xl font-semibold text-gray-900 dark:text-white">
                  {stats.total_irregular_logs.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700">
                <EyeOff className="h-5 w-5 text-gray-600 dark:text-gray-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Last Analysis</p>
                <p className="text-xl font-semibold text-gray-900 dark:text-white">
                  {stats.last_run_at
                    ? format(new Date(stats.last_run_at), 'MMM d, HH:mm')
                    : 'Never'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filters:</span>
          </div>
          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setPage(1);
            }}
            className="input px-3 py-1.5 text-sm"
          >
            <option value="">All Sources</option>
            {sources?.items.map((source) => (
              <option key={source.id} value={source.id}>
                {source.name}
              </option>
            ))}
          </select>
          <select
            value={ignoredFilter}
            onChange={(e) => {
              setIgnoredFilter(e.target.value);
              setPage(1);
            }}
            className="input px-3 py-1.5 text-sm"
          >
            <option value="">All Patterns</option>
            <option value="active">Active Only</option>
            <option value="ignored">Ignored Only</option>
          </select>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={rareOnly}
              onChange={(e) => {
                setRareOnly(e.target.checked);
                setPage(1);
              }}
              className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
            />
            <span className="text-gray-700 dark:text-gray-300">Rare patterns only</span>
          </label>
          <div className="flex-1 min-w-[200px]">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder="Search patterns..."
                  className="input pl-9 py-1.5 text-sm w-full"
                />
              </div>
              <button onClick={handleSearch} className="btn btn-primary px-3 py-1.5 text-sm">
                Search
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Patterns Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            Loading patterns...
          </div>
        ) : patterns?.items.length === 0 ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            <Hash className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p className="text-lg font-medium">No patterns found</p>
            <p className="text-sm mt-1">
              {searchQuery
                ? 'Try adjusting your search or filters'
                : 'Patterns will appear as logs are processed'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-zinc-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Pattern
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Occurrences
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    First Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Last Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-zinc-700">
                {patterns?.items.map((pattern) => (
                  <PatternRow
                    key={pattern.id}
                    pattern={pattern}
                    sources={sources?.items || []}
                    onToggleIgnore={handleToggleIgnore}
                    isUpdating={updatePattern.isPending}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {patterns && patterns.total > pageSize && (
          <div className="px-4 py-3 border-t border-gray-200 dark:border-zinc-700">
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              totalItems={patterns.total}
              pageSize={pageSize}
              onPageChange={setPage}
            />
          </div>
        )}
      </div>
    </div>
  );
}
