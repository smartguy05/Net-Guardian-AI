import { useState } from 'react';
import {
  Shield,
  Plus,
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
} from 'lucide-react';
import {
  useThreatFeeds,
  useThreatIndicators,
  useThreatIntelStats,
  useDeleteThreatFeed,
  useFetchThreatFeed,
  useEnableThreatFeed,
  useDisableThreatFeed,
  useCheckIndicator,
} from '../api/hooks';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import type { ThreatIntelFeed, ThreatIndicator, IndicatorType, FeedType } from '../types';
import AddFeedModal from '../components/AddFeedModal';
import Pagination from '../components/Pagination';
import { useAuthStore } from '../stores/auth';

const feedTypeLabels: Record<FeedType, string> = {
  csv: 'CSV',
  json: 'JSON',
  stix: 'STIX',
  url_list: 'URL List',
  ip_list: 'IP List',
};

const indicatorTypeLabels: Record<IndicatorType, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash_md5: 'MD5 Hash',
  hash_sha1: 'SHA1 Hash',
  hash_sha256: 'SHA256 Hash',
  email: 'Email',
  cidr: 'CIDR Range',
};

const severityColors: Record<string, string> = {
  low: 'badge-info',
  medium: 'badge-warning',
  high: 'badge-danger',
  critical: 'bg-red-700 text-white',
};

function FeedCard({
  feed,
  onRefresh,
  onDelete,
  onToggle,
  isAdmin,
}: {
  feed: ThreatIntelFeed;
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
            <span className="badge bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300 text-xs">
              {feedTypeLabels[feed.feed_type]}
            </span>
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
                    className="w-full px-4 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Fetch Now
                  </button>
                  <button
                    onClick={() => {
                      onToggle(feed.id, !feed.enabled);
                      setShowMenu(false);
                    }}
                    className="w-full px-4 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-2"
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
          <div className="text-gray-500 dark:text-gray-400 text-xs">Indicators</div>
          <div className="font-semibold text-gray-900 dark:text-white">
            {feed.indicator_count.toLocaleString()}
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

function IndicatorRow({ indicator }: { indicator: ThreatIndicator }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        className="hover:bg-gray-50 dark:hover:bg-zinc-700/50 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3 whitespace-nowrap text-sm">
          <span className="badge bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 text-xs">
            {indicatorTypeLabels[indicator.indicator_type]}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100 font-mono max-w-xs truncate">
          {indicator.value}
        </td>
        <td className="hidden md:table-cell px-4 py-3 whitespace-nowrap">
          <span className={clsx('badge text-xs', severityColors[indicator.severity])}>
            {indicator.severity}
          </span>
        </td>
        <td className="hidden sm:table-cell px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
          {indicator.confidence}%
        </td>
        <td className="hidden lg:table-cell px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
          {indicator.feed_name || 'Unknown'}
        </td>
        <td className="hidden xl:table-cell px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
          {indicator.hit_count}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} className="px-4 py-3 bg-gray-50 dark:bg-zinc-800">
            <div className="text-sm space-y-2">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <div className="text-gray-500 dark:text-gray-400 text-xs">First Seen</div>
                  <div className="text-gray-900 dark:text-white">
                    {indicator.first_seen_at
                      ? format(new Date(indicator.first_seen_at), 'PPp')
                      : '-'}
                  </div>
                </div>
                <div>
                  <div className="text-gray-500 dark:text-gray-400 text-xs">Last Seen</div>
                  <div className="text-gray-900 dark:text-white">
                    {indicator.last_seen_at
                      ? format(new Date(indicator.last_seen_at), 'PPp')
                      : '-'}
                  </div>
                </div>
                <div>
                  <div className="text-gray-500 dark:text-gray-400 text-xs">Expires</div>
                  <div className="text-gray-900 dark:text-white">
                    {indicator.expires_at
                      ? format(new Date(indicator.expires_at), 'PPp')
                      : 'Never'}
                  </div>
                </div>
                <div>
                  <div className="text-gray-500 dark:text-gray-400 text-xs">Last Hit</div>
                  <div className="text-gray-900 dark:text-white">
                    {indicator.last_hit_at
                      ? format(new Date(indicator.last_hit_at), 'PPp')
                      : 'Never'}
                  </div>
                </div>
              </div>
              {indicator.description && (
                <div>
                  <div className="text-gray-500 dark:text-gray-400 text-xs">Description</div>
                  <div className="text-gray-900 dark:text-white">{indicator.description}</div>
                </div>
              )}
              {indicator.tags.length > 0 && (
                <div>
                  <div className="text-gray-500 dark:text-gray-400 text-xs mb-1">Tags</div>
                  <div className="flex flex-wrap gap-1">
                    {indicator.tags.map((tag) => (
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
          </td>
        </tr>
      )}
    </>
  );
}

export default function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState<'feeds' | 'indicators' | 'lookup'>('feeds');
  const [showAddModal, setShowAddModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [indicatorType, setIndicatorType] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [lookupValue, setLookupValue] = useState('');
  const [lookupType, setLookupType] = useState<IndicatorType | ''>('');

  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';

  const { data: feeds, isLoading: feedsLoading, refetch: refetchFeeds } = useThreatFeeds();
  const { data: stats } = useThreatIntelStats();
  const { data: indicators, isLoading: indicatorsLoading } = useThreatIndicators({
    indicator_type: indicatorType as IndicatorType || undefined,
    severity: severity || undefined,
    value_contains: searchQuery || undefined,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  });

  const deleteFeed = useDeleteThreatFeed();
  const fetchFeed = useFetchThreatFeed();
  const enableFeed = useEnableThreatFeed();
  const disableFeed = useDisableThreatFeed();
  const checkIndicator = useCheckIndicator();

  const handleDeleteFeed = async (feedId: string) => {
    if (confirm('Are you sure you want to delete this feed? All indicators from this feed will also be deleted.')) {
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

  const handleLookup = async () => {
    if (!lookupValue.trim()) return;
    await checkIndicator.mutateAsync({
      value: lookupValue.trim(),
      indicator_type: lookupType as IndicatorType || undefined,
    });
  };

  const totalPages = indicators ? Math.ceil(indicators.total / pageSize) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Threat Intelligence
          </h1>
          <p className="text-gray-500 dark:text-gray-400">
            Manage threat feeds and indicators
          </p>
        </div>
        {isAdmin && (
          <button onClick={() => setShowAddModal(true)} className="btn-primary">
            <Plus className="w-4 h-4 mr-2" />
            Add Feed
          </button>
        )}
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Database className="w-5 h-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.total_feeds}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Total Feeds
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
                  {stats.enabled_feeds}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Active Feeds
                </div>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
                <Shield className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stats.total_indicators.toLocaleString()}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Indicators
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
                  {stats.recent_hits}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Recent Hits
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
            onClick={() => setActiveTab('feeds')}
            className={clsx(
              'py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'feeds'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            Feeds
          </button>
          <button
            onClick={() => setActiveTab('indicators')}
            className={clsx(
              'py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'indicators'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            Indicators
          </button>
          <button
            onClick={() => setActiveTab('lookup')}
            className={clsx(
              'py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'lookup'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            Lookup
          </button>
        </nav>
      </div>

      {/* Tab Content */}
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
              <Shield className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No Feeds Configured
              </h3>
              <p className="text-gray-500 dark:text-gray-400 mb-4">
                Add threat intelligence feeds to start collecting indicators.
              </p>
              {isAdmin && (
                <button onClick={() => setShowAddModal(true)} className="btn-primary">
                  <Plus className="w-4 h-4 mr-2" />
                  Add Your First Feed
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'indicators' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search indicators..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                className="input pl-10"
              />
            </div>
            <select
              value={indicatorType}
              onChange={(e) => {
                setIndicatorType(e.target.value);
                setPage(1);
              }}
              className="input w-full sm:w-40"
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash_md5">MD5 Hash</option>
              <option value="hash_sha1">SHA1 Hash</option>
              <option value="hash_sha256">SHA256 Hash</option>
              <option value="email">Email</option>
              <option value="cidr">CIDR Range</option>
            </select>
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className="input w-full sm:w-36"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Table */}
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-zinc-700">
                <thead className="bg-gray-50 dark:bg-zinc-800/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Value
                    </th>
                    <th className="hidden md:table-cell px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="hidden sm:table-cell px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Confidence
                    </th>
                    <th className="hidden lg:table-cell px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Feed
                    </th>
                    <th className="hidden xl:table-cell px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Hits
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-zinc-800 divide-y divide-gray-200 dark:divide-zinc-700">
                  {indicatorsLoading ? (
                    [...Array(10)].map((_, i) => (
                      <tr key={i}>
                        <td colSpan={6} className="px-4 py-3">
                          <div className="animate-pulse h-8 bg-gray-100 dark:bg-zinc-700 rounded" />
                        </td>
                      </tr>
                    ))
                  ) : indicators?.items.length ? (
                    indicators.items.map((indicator) => (
                      <IndicatorRow key={indicator.id} indicator={indicator} />
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-gray-500 dark:text-gray-400">
                        <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300 dark:text-gray-600" />
                        No indicators found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {indicators && indicators.total > 0 && (
              <div className="border-t border-gray-200 dark:border-zinc-700">
                <Pagination
                  currentPage={page}
                  totalPages={totalPages}
                  totalItems={indicators.total}
                  pageSize={pageSize}
                  onPageChange={setPage}
                  onPageSizeChange={(size) => {
                    setPageSize(size);
                    setPage(1);
                  }}
                  pageSizeOptions={[25, 50, 100, 200]}
                />
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'lookup' && (
        <div className="card p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Indicator Lookup
          </h3>
          <p className="text-gray-500 dark:text-gray-400 mb-6">
            Check if an IP, domain, URL, or hash is in your threat intelligence database.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="flex-1">
              <input
                type="text"
                placeholder="Enter IP, domain, URL, or hash..."
                value={lookupValue}
                onChange={(e) => setLookupValue(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
                className="input"
              />
            </div>
            <select
              value={lookupType}
              onChange={(e) => setLookupType(e.target.value as IndicatorType | '')}
              className="input w-full sm:w-40"
            >
              <option value="">Auto-detect</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash_md5">MD5 Hash</option>
              <option value="hash_sha1">SHA1 Hash</option>
              <option value="hash_sha256">SHA256 Hash</option>
              <option value="email">Email</option>
              <option value="cidr">CIDR Range</option>
            </select>
            <button
              onClick={handleLookup}
              disabled={!lookupValue.trim() || checkIndicator.isPending}
              className="btn-primary"
            >
              {checkIndicator.isPending ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Search className="w-4 h-4 mr-2" />
              )}
              Lookup
            </button>
          </div>

          {/* Lookup Results */}
          {checkIndicator.data && (
            <div className="space-y-4">
              {checkIndicator.data.found ? (
                <>
                  <div className="flex items-center gap-2 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                    <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
                    <span className="font-medium text-red-600 dark:text-red-400">
                      Found {checkIndicator.data.matches.length} matching indicator(s)
                    </span>
                  </div>
                  <div className="space-y-3">
                    {checkIndicator.data.matches.map((match) => (
                      <div
                        key={match.id}
                        className="p-4 border border-gray-200 dark:border-zinc-700 rounded-lg"
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <span className="badge bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400">
                            {indicatorTypeLabels[match.indicator_type]}
                          </span>
                          <span className={clsx('badge', severityColors[match.severity])}>
                            {match.severity}
                          </span>
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            {match.confidence}% confidence
                          </span>
                        </div>
                        <div className="font-mono text-sm text-gray-900 dark:text-white mb-2">
                          {match.value}
                        </div>
                        {match.description && (
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {match.description}
                          </div>
                        )}
                        <div className="mt-2 text-xs text-gray-400">
                          From: {match.feed_name || 'Unknown feed'}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="flex items-center gap-2 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                  <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                  <span className="font-medium text-green-600 dark:text-green-400">
                    No matches found - indicator not in database
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Add Feed Modal */}
      {showAddModal && <AddFeedModal onClose={() => setShowAddModal(false)} />}
    </div>
  );
}
