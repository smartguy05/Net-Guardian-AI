import { useState } from 'react';
import {
  Shield,
  RefreshCw,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Database,
  MoreVertical,
  Trash2,
  Download,
  Eye,
  EyeOff,
  Code,
  FileText,
  Play,
} from 'lucide-react';
import {
  useSecurityPatterns,
  useSecurityPatternFeeds,
  useSecurityPatternStats,
  useDeleteSecurityPattern,
  useEnableSecurityPattern,
  useDisableSecurityPattern,
  useDeleteSecurityPatternFeed,
  useFetchSecurityPatternFeed,
  useEnableSecurityPatternFeed,
  useDisableSecurityPatternFeed,
  useTestSecurityPattern,
  useMatchText,
} from '../api/hooks';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { SecurityPattern, SecurityPatternFeed, PatternCategory, PatternType } from '../types';
import Pagination from '../components/Pagination';
import { useAuthStore } from '../stores/auth';

const categoryLabels: Record<PatternCategory, string> = {
  sql_injection: 'SQL Injection',
  command_injection: 'Command Injection',
  path_traversal: 'Path Traversal',
  xss: 'XSS',
  deserialization: 'Deserialization',
  ssrf: 'SSRF',
  auth_bypass: 'Auth Bypass',
  log_injection: 'Log Injection',
  ldap_injection: 'LDAP Injection',
  xxe: 'XXE',
  custom: 'Custom',
};

const patternTypeLabels: Record<PatternType, string> = {
  regex: 'Regex',
  literal: 'Literal',
  keyword: 'Keyword',
};

const severityColors: Record<string, string> = {
  info: 'badge-info',
  low: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400',
  medium: 'badge-warning',
  high: 'badge-danger',
  critical: 'bg-red-700 text-white',
};

const sourceLabels: Record<string, string> = {
  builtin: 'Built-in',
  user: 'User',
  feed: 'Feed',
};

function PatternCard({
  pattern,
  onDelete,
  onToggle,
  isAdmin,
}: {
  pattern: SecurityPattern;
  onDelete: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
  isAdmin: boolean;
}) {
  const [showMenu, setShowMenu] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const canDelete = pattern.source !== 'builtin';

  return (
    <div
      className={clsx(
        'card p-4 hover:shadow-md transition-shadow cursor-pointer',
        !pattern.enabled && 'opacity-60'
      )}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-semibold text-gray-900 dark:text-white truncate">
              {pattern.name}
            </h3>
            <span className="badge bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300 text-xs">
              {categoryLabels[pattern.category]}
            </span>
            <span className={clsx('badge text-xs', severityColors[pattern.severity])}>
              {pattern.severity}
            </span>
            <span className="badge bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 text-xs">
              {sourceLabels[pattern.source]}
            </span>
            {!pattern.enabled && (
              <span className="badge bg-gray-300 dark:bg-zinc-600 text-gray-600 dark:text-gray-400 text-xs">
                Disabled
              </span>
            )}
          </div>
          {pattern.description && (
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">
              {pattern.description}
            </p>
          )}
        </div>

        {isAdmin && (
          <div className="relative ml-2" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={() => setShowMenu(!showMenu)}
              className="p-1 hover:bg-gray-100 dark:hover:bg-zinc-700 rounded"
            >
              <MoreVertical className="w-4 h-4 text-gray-500" />
            </button>
            {showMenu && (
              <>
                <div
                  className="fixed inset-0 z-10"
                  onClick={() => setShowMenu(false)}
                />
                <div className="absolute right-0 top-8 z-20 w-48 bg-white dark:bg-zinc-800 rounded-lg shadow-lg border border-gray-200 dark:border-zinc-700 py-1">
                  <button
                    onClick={() => {
                      onToggle(pattern.id, !pattern.enabled);
                      setShowMenu(false);
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-2"
                  >
                    {pattern.enabled ? (
                      <>
                        <EyeOff className="w-4 h-4" />
                        Disable
                      </>
                    ) : (
                      <>
                        <Eye className="w-4 h-4" />
                        Enable
                      </>
                    )}
                  </button>
                  {canDelete && (
                    <>
                      <hr className="my-1 border-gray-200 dark:border-zinc-700" />
                      <button
                        onClick={() => {
                          onDelete(pattern.id);
                          setShowMenu(false);
                        }}
                        className="w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2"
                      >
                        <Trash2 className="w-4 h-4" />
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Type</div>
          <div className="font-semibold text-gray-900 dark:text-white">
            {patternTypeLabels[pattern.pattern_type]}
          </div>
        </div>
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Hits</div>
          <div className="font-semibold text-gray-900 dark:text-white">
            {pattern.hit_count.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Last Hit</div>
          <div className="text-gray-900 dark:text-white">
            {pattern.last_hit_at
              ? formatDistanceToNow(new Date(pattern.last_hit_at), { addSuffix: true })
              : 'Never'}
          </div>
        </div>
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Tags</div>
          <div className="text-gray-900 dark:text-white">
            {pattern.tags.length > 0 ? pattern.tags.slice(0, 2).join(', ') : '-'}
            {pattern.tags.length > 2 && ` +${pattern.tags.length - 2}`}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-zinc-700 space-y-3">
          <div>
            <div className="text-gray-500 dark:text-gray-400 text-xs mb-1">Pattern</div>
            <code className="block p-2 bg-gray-100 dark:bg-zinc-900 rounded text-sm font-mono break-all">
              {pattern.pattern}
            </code>
          </div>
          {pattern.examples.length > 0 && (
            <div>
              <div className="text-gray-500 dark:text-gray-400 text-xs mb-1">Examples</div>
              <div className="space-y-1">
                {pattern.examples.map((example, idx) => (
                  <code
                    key={idx}
                    className="block p-2 bg-red-50 dark:bg-red-900/20 rounded text-sm font-mono break-all text-red-700 dark:text-red-400"
                  >
                    {example}
                  </code>
                ))}
              </div>
            </div>
          )}
          {pattern.tags.length > 0 && (
            <div>
              <div className="text-gray-500 dark:text-gray-400 text-xs mb-1">All Tags</div>
              <div className="flex flex-wrap gap-1">
                {pattern.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-2 py-0.5 bg-gray-200 dark:bg-zinc-600 rounded text-xs"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FeedCard({
  feed,
  onRefresh,
  onDelete,
  onToggle,
  isAdmin,
}: {
  feed: SecurityPatternFeed;
  onRefresh: (id: string) => void;
  onDelete: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
  isAdmin: boolean;
}) {
  const [showMenu, setShowMenu] = useState(false);

  const statusIcon = feed.last_fetch_status === 'success' ? (
    <CheckCircle className="w-4 h-4 text-green-500" />
  ) : feed.last_fetch_status === 'error' ? (
    <XCircle className="w-4 h-4 text-red-500" />
  ) : (
    <Clock className="w-4 h-4 text-gray-400" />
  );

  return (
    <div
      className={clsx(
        'card p-4 hover:shadow-md transition-shadow',
        !feed.enabled && 'opacity-60'
      )}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-gray-900 dark:text-white truncate">
              {feed.name}
            </h3>
            {!feed.enabled && (
              <span className="badge bg-gray-300 dark:bg-zinc-600 text-gray-600 dark:text-gray-400 text-xs">
                Disabled
              </span>
            )}
          </div>
          {feed.description && (
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">
              {feed.description}
            </p>
          )}
        </div>

        {isAdmin && (
          <div className="relative ml-2">
            <button
              onClick={() => setShowMenu(!showMenu)}
              className="p-1 hover:bg-gray-100 dark:hover:bg-zinc-700 rounded"
            >
              <MoreVertical className="w-4 h-4 text-gray-500" />
            </button>
            {showMenu && (
              <>
                <div
                  className="fixed inset-0 z-10"
                  onClick={() => setShowMenu(false)}
                />
                <div className="absolute right-0 top-8 z-20 w-48 bg-white dark:bg-zinc-800 rounded-lg shadow-lg border border-gray-200 dark:border-zinc-700 py-1">
                  <button
                    onClick={() => {
                      onRefresh(feed.id);
                      setShowMenu(false);
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Fetch Now
                  </button>
                  <button
                    onClick={() => {
                      onToggle(feed.id, !feed.enabled);
                      setShowMenu(false);
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-2"
                  >
                    {feed.enabled ? (
                      <>
                        <EyeOff className="w-4 h-4" />
                        Disable
                      </>
                    ) : (
                      <>
                        <Eye className="w-4 h-4" />
                        Enable
                      </>
                    )}
                  </button>
                  <hr className="my-1 border-gray-200 dark:border-zinc-700" />
                  <button
                    onClick={() => {
                      onDelete(feed.id);
                      setShowMenu(false);
                    }}
                    className="w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2"
                  >
                    <Trash2 className="w-4 h-4" />
                    Delete
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Patterns</div>
          <div className="font-semibold text-gray-900 dark:text-white">
            {feed.pattern_count.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Update Interval</div>
          <div className="font-semibold text-gray-900 dark:text-white">
            {feed.update_interval_hours}h
          </div>
        </div>
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Last Fetch</div>
          <div className="flex items-center gap-1">
            {statusIcon}
            <span className="text-gray-900 dark:text-white">
              {feed.last_fetch_at
                ? formatDistanceToNow(new Date(feed.last_fetch_at), { addSuffix: true })
                : 'Never'}
            </span>
          </div>
        </div>
        <div>
          <div className="text-gray-500 dark:text-gray-400 text-xs">Authentication</div>
          <div className="text-gray-900 dark:text-white capitalize">{feed.auth_type}</div>
        </div>
      </div>

      {feed.last_fetch_status === 'error' && feed.last_fetch_message && (
        <div className="mt-3 p-2 bg-red-50 dark:bg-red-900/20 rounded text-sm text-red-600 dark:text-red-400">
          {feed.last_fetch_message}
        </div>
      )}
    </div>
  );
}

export default function SecurityPatternsPage() {
  const [activeTab, setActiveTab] = useState<'patterns' | 'feeds' | 'test'>('patterns');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [testText, setTestText] = useState('');
  const [testPattern, setTestPattern] = useState('');
  const [testPatternType, setTestPatternType] = useState<PatternType>('regex');

  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';

  const { data: patterns, isLoading: patternsLoading, refetch: refetchPatterns } = useSecurityPatterns({
    category: categoryFilter as PatternCategory || undefined,
    source: sourceFilter || undefined,
    search: searchQuery || undefined,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  });
  const { data: feeds, isLoading: feedsLoading, refetch: refetchFeeds } = useSecurityPatternFeeds();
  const { data: stats } = useSecurityPatternStats();

  const deletePattern = useDeleteSecurityPattern();
  const enablePattern = useEnableSecurityPattern();
  const disablePattern = useDisableSecurityPattern();
  const deleteFeed = useDeleteSecurityPatternFeed();
  const fetchFeed = useFetchSecurityPatternFeed();
  const enableFeed = useEnableSecurityPatternFeed();
  const disableFeed = useDisableSecurityPatternFeed();
  const testPatternMutation = useTestSecurityPattern();
  const matchTextMutation = useMatchText();

  const handleDeletePattern = async (patternId: string) => {
    if (confirm('Are you sure you want to delete this pattern?')) {
      await deletePattern.mutateAsync(patternId);
    }
  };

  const handleTogglePattern = async (patternId: string, enabled: boolean) => {
    if (enabled) {
      await enablePattern.mutateAsync(patternId);
    } else {
      await disablePattern.mutateAsync(patternId);
    }
  };

  const handleDeleteFeed = async (feedId: string) => {
    if (confirm('Are you sure you want to delete this feed? All patterns from this feed will also be deleted.')) {
      await deleteFeed.mutateAsync(feedId);
    }
  };

  const handleFetchFeed = async (feedId: string) => {
    await fetchFeed.mutateAsync(feedId);
  };

  const handleToggleFeed = async (feedId: string, enabled: boolean) => {
    if (enabled) {
      await enableFeed.mutateAsync(feedId);
    } else {
      await disableFeed.mutateAsync(feedId);
    }
  };

  const handleTestPattern = async () => {
    if (!testPattern.trim() || !testText.trim()) return;
    await testPatternMutation.mutateAsync({
      pattern: testPattern.trim(),
      pattern_type: testPatternType,
      test_text: testText.trim(),
    });
  };

  const handleMatchText = async () => {
    if (!testText.trim()) return;
    await matchTextMutation.mutateAsync({
      text: testText.trim(),
    });
  };

  const totalPages = patterns ? Math.ceil(patterns.total / pageSize) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Security Patterns
          </h1>
          <p className="text-gray-500 dark:text-gray-400">
            Manage security detection patterns and feeds
          </p>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Shield className="w-5 h-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.total_patterns}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Total Patterns
                </div>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.enabled_patterns}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Enabled
                </div>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
                <Database className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.total_feeds}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Feeds
                </div>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
                <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.total_hits.toLocaleString()}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Total Hits
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-zinc-700">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('patterns')}
            className={clsx(
              'py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'patterns'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            <Shield className="w-4 h-4 inline-block mr-2" />
            Patterns
          </button>
          <button
            onClick={() => setActiveTab('feeds')}
            className={clsx(
              'py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'feeds'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            <Database className="w-4 h-4 inline-block mr-2" />
            Feeds
          </button>
          <button
            onClick={() => setActiveTab('test')}
            className={clsx(
              'py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'test'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            <Code className="w-4 h-4 inline-block mr-2" />
            Test
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'patterns' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search patterns..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                className="input pl-10"
              />
            </div>
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setPage(1);
              }}
              className="input w-full sm:w-48"
            >
              <option value="">All Categories</option>
              {Object.entries(categoryLabels).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select>
            <select
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setPage(1);
              }}
              className="input w-full sm:w-36"
            >
              <option value="">All Sources</option>
              <option value="builtin">Built-in</option>
              <option value="user">User</option>
              <option value="feed">Feed</option>
            </select>
            <button
              onClick={() => refetchPatterns()}
              disabled={patternsLoading}
              className="btn-secondary"
            >
              <RefreshCw className={clsx('w-4 h-4 mr-2', patternsLoading && 'animate-spin')} />
              Refresh
            </button>
          </div>

          {/* Pattern List */}
          {patternsLoading ? (
            <div className="grid gap-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="card p-4 animate-pulse">
                  <div className="h-6 bg-gray-200 dark:bg-zinc-700 rounded w-1/4 mb-4" />
                  <div className="h-4 bg-gray-200 dark:bg-zinc-700 rounded w-3/4" />
                </div>
              ))}
            </div>
          ) : patterns?.items.length ? (
            <>
              <div className="grid gap-4">
                {patterns.items.map((pattern) => (
                  <PatternCard
                    key={pattern.id}
                    pattern={pattern}
                    onDelete={handleDeletePattern}
                    onToggle={handleTogglePattern}
                    isAdmin={isAdmin}
                  />
                ))}
              </div>
              {patterns.total > pageSize && (
                <Pagination
                  currentPage={page}
                  totalPages={totalPages}
                  totalItems={patterns.total}
                  pageSize={pageSize}
                  onPageChange={setPage}
                  onPageSizeChange={(size) => {
                    setPageSize(size);
                    setPage(1);
                  }}
                  pageSizeOptions={[10, 25, 50, 100]}
                />
              )}
            </>
          ) : (
            <div className="card p-12 text-center">
              <Shield className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No Patterns Found
              </h3>
              <p className="text-gray-500 dark:text-gray-400">
                {searchQuery || categoryFilter || sourceFilter
                  ? 'No patterns match your filters.'
                  : 'No security patterns have been configured yet.'}
              </p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'feeds' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={() => refetchFeeds()}
              disabled={feedsLoading}
              className="btn-secondary"
            >
              <RefreshCw className={clsx('w-4 h-4 mr-2', feedsLoading && 'animate-spin')} />
              Refresh
            </button>
          </div>

          {feedsLoading ? (
            <div className="grid gap-4">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="card p-4 animate-pulse">
                  <div className="h-6 bg-gray-200 dark:bg-zinc-700 rounded w-1/4 mb-4" />
                  <div className="h-4 bg-gray-200 dark:bg-zinc-700 rounded w-3/4" />
                </div>
              ))}
            </div>
          ) : feeds?.items.length ? (
            <div className="grid gap-4">
              {feeds.items.map((feed) => (
                <FeedCard
                  key={feed.id}
                  feed={feed}
                  onRefresh={handleFetchFeed}
                  onDelete={handleDeleteFeed}
                  onToggle={handleToggleFeed}
                  isAdmin={isAdmin}
                />
              ))}
            </div>
          ) : (
            <div className="card p-12 text-center">
              <Database className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No Feeds Configured
              </h3>
              <p className="text-gray-500 dark:text-gray-400">
                Add security pattern feeds to import patterns from external sources.
              </p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'test' && (
        <div className="space-y-6">
          {/* Test Single Pattern */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              <Code className="w-5 h-5" />
              Test Pattern
            </h3>
            <p className="text-gray-500 dark:text-gray-400 mb-6">
              Test a regex, literal, or keyword pattern against sample text.
            </p>

            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="md:col-span-3">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Pattern
                  </label>
                  <input
                    type="text"
                    placeholder="Enter pattern (e.g., (?i)union\s+select)"
                    value={testPattern}
                    onChange={(e) => setTestPattern(e.target.value)}
                    className="input font-mono"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Type
                  </label>
                  <select
                    value={testPatternType}
                    onChange={(e) => setTestPatternType(e.target.value as PatternType)}
                    className="input"
                  >
                    <option value="regex">Regex</option>
                    <option value="literal">Literal</option>
                    <option value="keyword">Keyword</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Test Text
                </label>
                <textarea
                  placeholder="Enter text to test against..."
                  value={testText}
                  onChange={(e) => setTestText(e.target.value)}
                  rows={4}
                  className="input font-mono"
                />
              </div>

              <button
                onClick={handleTestPattern}
                disabled={!testPattern.trim() || !testText.trim() || testPatternMutation.isPending}
                className="btn-primary"
              >
                {testPatternMutation.isPending ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Play className="w-4 h-4 mr-2" />
                )}
                Test Pattern
              </button>

              {testPatternMutation.data && (
                <div className="mt-4">
                  {testPatternMutation.data.matched ? (
                    <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                      <div className="flex items-center gap-2 text-red-600 dark:text-red-400 font-medium mb-2">
                        <AlertTriangle className="w-5 h-5" />
                        Pattern Matched
                      </div>
                      <div className="text-sm text-gray-700 dark:text-gray-300">
                        Matched text:{' '}
                        <code className="px-1 py-0.5 bg-red-100 dark:bg-red-900/30 rounded">
                          {testPatternMutation.data.matched_text}
                        </code>
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        Position: {testPatternMutation.data.match_start} - {testPatternMutation.data.match_end}
                      </div>
                    </div>
                  ) : (
                    <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                      <span className="text-green-600 dark:text-green-400 font-medium">
                        No match found
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Match Against All Patterns */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5" />
              Match Against All Patterns
            </h3>
            <p className="text-gray-500 dark:text-gray-400 mb-6">
              Check text against all enabled security patterns to see which ones match.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Text to Analyze
                </label>
                <textarea
                  placeholder="Enter log message or text to analyze..."
                  value={testText}
                  onChange={(e) => setTestText(e.target.value)}
                  rows={4}
                  className="input font-mono"
                />
              </div>

              <button
                onClick={handleMatchText}
                disabled={!testText.trim() || matchTextMutation.isPending}
                className="btn-primary"
              >
                {matchTextMutation.isPending ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Search className="w-4 h-4 mr-2" />
                )}
                Check All Patterns
              </button>

              {matchTextMutation.data && (
                <div className="mt-4">
                  {matchTextMutation.data.length > 0 ? (
                    <div className="space-y-3">
                      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
                        <span className="text-red-600 dark:text-red-400 font-medium">
                          {matchTextMutation.data.length} pattern(s) matched
                        </span>
                      </div>
                      {matchTextMutation.data.map((match, idx) => (
                        <div
                          key={idx}
                          className="p-4 border border-gray-200 dark:border-zinc-700 rounded-lg"
                        >
                          <div className="flex items-center gap-2 mb-2 flex-wrap">
                            <span className="font-semibold text-gray-900 dark:text-white">
                              {match.pattern_name}
                            </span>
                            <span className="badge bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300 text-xs">
                              {categoryLabels[match.category]}
                            </span>
                            <span className={clsx('badge text-xs', severityColors[match.severity])}>
                              {match.severity}
                            </span>
                          </div>
                          <div className="text-sm">
                            Matched:{' '}
                            <code className="px-1 py-0.5 bg-red-100 dark:bg-red-900/30 rounded">
                              {match.matched_text}
                            </code>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                      <span className="text-green-600 dark:text-green-400 font-medium">
                        No security patterns matched
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
