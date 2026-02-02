import { useState } from 'react';
import { ClipboardList, RefreshCw, CheckCircle, XCircle } from 'lucide-react';
import { useAuditLogs, exportAuditCSV, exportAuditPDF } from '../api/hooks';
import { format } from 'date-fns';
import clsx from 'clsx';
import Pagination from '../components/Pagination';
import ExportButton from '../components/ExportButton';

const actionOptions = [
  { value: '', label: 'All actions' },
  { value: 'quarantine', label: 'Quarantine' },
  { value: 'release', label: 'Release' },
  { value: 'login', label: 'Login' },
  { value: 'logout', label: 'Logout' },
  { value: 'create_user', label: 'Create User' },
  { value: 'update_user', label: 'Update User' },
  { value: 'delete_user', label: 'Delete User' },
  { value: 'create_rule', label: 'Create Rule' },
  { value: 'update_rule', label: 'Update Rule' },
  { value: 'delete_rule', label: 'Delete Rule' },
  { value: 'create_source', label: 'Create Source' },
  { value: 'update_source', label: 'Update Source' },
  { value: 'delete_source', label: 'Delete Source' },
];

const targetTypeOptions = [
  { value: '', label: 'All targets' },
  { value: 'device', label: 'Device' },
  { value: 'user', label: 'User' },
  { value: 'rule', label: 'Rule' },
  { value: 'source', label: 'Source' },
  { value: 'alert', label: 'Alert' },
  { value: 'feed', label: 'Feed' },
];

export default function AuditPage() {
  const [actionFilter, setActionFilter] = useState('');
  const [targetTypeFilter, setTargetTypeFilter] = useState('');
  const [successFilter, setSuccessFilter] = useState<'' | 'true' | 'false'>('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const offset = (page - 1) * pageSize;

  const { data, isLoading, refetch, isFetching } = useAuditLogs({
    action: actionFilter || undefined,
    target_type: targetTypeFilter || undefined,
    success_only: successFilter === 'true' ? true : successFilter === 'false' ? false : undefined,
    limit: pageSize,
    offset,
  });

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
  };

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize);
    setPage(1);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Audit Logs</h1>
          <p className="text-gray-500 dark:text-gray-400">
            {data?.total ?? 0} total entries
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ExportButton
            onExportCSV={() => exportAuditCSV({
              action: actionFilter || undefined,
              target_type: targetTypeFilter || undefined,
            })}
            onExportPDF={() => exportAuditPDF({
              action: actionFilter || undefined,
              target_type: targetTypeFilter || undefined,
            })}
          />
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
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <select
          value={actionFilter}
          onChange={(e) => {
            setActionFilter(e.target.value);
            setPage(1);
          }}
          className="input w-full sm:w-48"
        >
          {actionOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <select
          value={targetTypeFilter}
          onChange={(e) => {
            setTargetTypeFilter(e.target.value);
            setPage(1);
          }}
          className="input w-full sm:w-48"
        >
          {targetTypeOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <select
          value={successFilter}
          onChange={(e) => {
            setSuccessFilter(e.target.value as '' | 'true' | 'false');
            setPage(1);
          }}
          className="input w-full sm:w-40"
        >
          <option value="">All results</option>
          <option value="true">Success only</option>
          <option value="false">Failed only</option>
        </select>
      </div>

      {/* Audit logs table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-zinc-800 border-b border-gray-200 dark:border-zinc-700">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Action
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  User
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Description
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-zinc-700">
              {isLoading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i}>
                    <td colSpan={6} className="px-4 py-3">
                      <div className="animate-pulse h-4 bg-gray-100 dark:bg-zinc-700 rounded w-full" />
                    </td>
                  </tr>
                ))
              ) : data?.items.length ? (
                data.items.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50 dark:hover:bg-zinc-800/50">
                    <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100 whitespace-nowrap">
                      {format(new Date(log.timestamp), 'MMM d, yyyy HH:mm:ss')}
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-800 dark:text-primary-300">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100">
                      {log.username || 'System'}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                      {log.target_type && (
                        <span className="text-xs text-gray-500 dark:text-gray-500 mr-1">
                          [{log.target_type}]
                        </span>
                      )}
                      {log.target_name || log.target_id || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400 max-w-xs truncate" title={log.description}>
                      {log.description}
                    </td>
                    <td className="px-4 py-3">
                      {log.success ? (
                        <span className="inline-flex items-center gap-1 text-success-600 dark:text-success-400">
                          <CheckCircle className="w-4 h-4" />
                          <span className="text-xs">Success</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-danger-600 dark:text-danger-400" title={log.error_message || undefined}>
                          <XCircle className="w-4 h-4" />
                          <span className="text-xs">Failed</span>
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center">
                    <ClipboardList className="w-12 h-12 mx-auto mb-3 text-gray-300 dark:text-gray-600" />
                    <p className="text-gray-500 dark:text-gray-400">No audit logs found</p>
                    <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">
                      Audit logs will appear here when actions are performed
                    </p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.total > 0 && (
          <div className="border-t border-gray-200 dark:border-zinc-700">
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              totalItems={data.total}
              pageSize={pageSize}
              onPageChange={handlePageChange}
              onPageSizeChange={handlePageSizeChange}
              pageSizeOptions={[10, 25, 50, 100]}
            />
          </div>
        )}
      </div>
    </div>
  );
}
