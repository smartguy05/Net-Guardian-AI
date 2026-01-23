import { useState } from 'react';
import { format } from 'date-fns';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Eye,
  Filter,
  RefreshCw,
  Search,
  XCircle,
} from 'lucide-react';
import clsx from 'clsx';
import {
  useIrregularLogs,
  useMarkIrregularReviewed,
  useSemanticStats,
  useSources,
} from '../api/hooks';
import Pagination from '../components/Pagination';

export default function SemanticReviewPage() {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [reviewedFilter, setReviewedFilter] = useState<string>('unreviewed');
  const [severityFilter, setSeverityFilter] = useState<number | undefined>();
  const [searchQuery, setSearchQuery] = useState('');

  const { data: stats, isLoading: statsLoading } = useSemanticStats();
  const { data: sources } = useSources();
  const { data: irregularLogs, isLoading, refetch } = useIrregularLogs({
    source_id: sourceFilter || undefined,
    reviewed_by_user: reviewedFilter === 'reviewed' ? true : reviewedFilter === 'unreviewed' ? false : undefined,
    min_severity: severityFilter,
    page,
    page_size: pageSize,
  });

  const markReviewed = useMarkIrregularReviewed();

  const handleMarkReviewed = async (irregularId: string) => {
    await markReviewed.mutateAsync(irregularId);
  };

  const getSeverityColor = (score: number | null) => {
    if (score === null) return 'text-gray-500 dark:text-gray-400';
    if (score >= 0.8) return 'text-red-600 dark:text-red-400';
    if (score >= 0.6) return 'text-orange-600 dark:text-orange-400';
    if (score >= 0.4) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-green-600 dark:text-green-400';
  };

  const getSeverityLabel = (score: number | null) => {
    if (score === null) return 'Unknown';
    if (score >= 0.8) return 'Critical';
    if (score >= 0.6) return 'High';
    if (score >= 0.4) return 'Medium';
    return 'Low';
  };

  const totalPages = irregularLogs ? Math.ceil(irregularLogs.total / pageSize) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Semantic Review
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Review irregular log patterns detected by semantic analysis
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

      {/* Stats Cards */}
      {!statsLoading && stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30">
                <Search className="h-5 w-5 text-blue-600 dark:text-blue-400" />
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
                <p className="text-sm text-gray-500 dark:text-gray-400">Irregular Logs</p>
                <p className="text-xl font-semibold text-gray-900 dark:text-white">
                  {stats.total_irregular_logs.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-100 dark:bg-orange-900/30">
                <Clock className="h-5 w-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Pending Review</p>
                <p className="text-xl font-semibold text-gray-900 dark:text-white">
                  {stats.pending_review.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-100 dark:bg-red-900/30">
                <XCircle className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">High Severity</p>
                <p className="text-xl font-semibold text-gray-900 dark:text-white">
                  {stats.high_severity_count.toLocaleString()}
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
            value={reviewedFilter}
            onChange={(e) => {
              setReviewedFilter(e.target.value);
              setPage(1);
            }}
            className="input px-3 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="unreviewed">Unreviewed</option>
            <option value="reviewed">Reviewed</option>
          </select>
          <select
            value={severityFilter?.toString() ?? ''}
            onChange={(e) => {
              setSeverityFilter(e.target.value ? Number(e.target.value) : undefined);
              setPage(1);
            }}
            className="input px-3 py-1.5 text-sm"
          >
            <option value="">All Severities</option>
            <option value="0.8">Critical (0.8+)</option>
            <option value="0.6">High (0.6+)</option>
            <option value="0.4">Medium (0.4+)</option>
          </select>
        </div>
      </div>

      {/* Irregular Logs Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            Loading irregular logs...
          </div>
        ) : irregularLogs?.items.length === 0 ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            <CheckCircle2 className="h-12 w-12 mx-auto mb-4 text-green-500" />
            <p className="text-lg font-medium">No irregular logs to review</p>
            <p className="text-sm mt-1">All logs are following normal patterns</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-zinc-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Reason
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    LLM Analysis
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
                {irregularLogs?.items.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-gray-50 dark:hover:bg-zinc-800/50"
                  >
                    <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100 whitespace-nowrap">
                      {format(new Date(log.event_timestamp), 'MMM d, HH:mm:ss')}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">
                      {log.source_id}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span
                        className={clsx(
                          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                          getSeverityColor(log.severity_score)
                        )}
                      >
                        {log.severity_score !== null
                          ? `${getSeverityLabel(log.severity_score)} (${(log.severity_score * 100).toFixed(0)}%)`
                          : 'Pending'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300 max-w-xs truncate">
                      {log.reason}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300 max-w-sm">
                      {log.llm_reviewed ? (
                        <div className="truncate" title={log.llm_response || ''}>
                          {log.llm_response || 'No specific concerns'}
                        </div>
                      ) : (
                        <span className="text-gray-400 italic">Pending analysis</span>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {log.reviewed_by_user ? (
                        <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400">
                          <CheckCircle2 className="h-4 w-4" />
                          Reviewed
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-yellow-600 dark:text-yellow-400">
                          <Clock className="h-4 w-4" />
                          Pending
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {!log.reviewed_by_user && (
                        <button
                          onClick={() => handleMarkReviewed(log.id)}
                          disabled={markReviewed.isPending}
                          className="btn btn-secondary px-2 py-1 text-xs flex items-center gap-1"
                        >
                          <Eye className="h-3 w-3" />
                          Mark Reviewed
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {irregularLogs && irregularLogs.total > pageSize && (
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
