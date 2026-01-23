import { useState } from 'react';
import { format } from 'date-fns';
import {
  AlertTriangle,
  Eye,
  EyeOff,
  Filter,
  Hash,
  RefreshCw,
  Search,
} from 'lucide-react';
import clsx from 'clsx';
import { usePatterns, useUpdatePattern, useSources, useSemanticStats } from '../api/hooks';
import Pagination from '../components/Pagination';

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
                  <tr
                    key={pattern.id}
                    className={clsx(
                      'hover:bg-gray-50 dark:hover:bg-zinc-800/50',
                      pattern.is_ignored && 'opacity-60'
                    )}
                  >
                    <td className="px-4 py-3">
                      <div className="max-w-md">
                        <code className="text-xs text-gray-800 dark:text-gray-200 bg-gray-100 dark:bg-zinc-800 px-2 py-1 rounded block truncate">
                          {pattern.normalized_pattern}
                        </code>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">
                      {pattern.source_id}
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
                        onClick={() => handleToggleIgnore(pattern.id, pattern.is_ignored)}
                        disabled={updatePattern.isPending}
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
              onPageChange={setPage}
            />
          </div>
        )}
      </div>
    </div>
  );
}
