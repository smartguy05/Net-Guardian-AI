import { useState } from 'react';
import { Bell, Search, RefreshCw, CheckCircle, XCircle, Eye } from 'lucide-react';
import { useAlerts, useUpdateAlertStatus } from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import type { Alert, AlertSeverity, AlertStatus } from '../types';
import Pagination from '../components/Pagination';

const severityColors: Record<AlertSeverity, string> = {
  low: 'badge-info',
  medium: 'badge-warning',
  high: 'badge-danger',
  critical: 'badge-danger bg-danger-600 text-white',
};

const statusColors: Record<AlertStatus, string> = {
  new: 'badge-danger',
  acknowledged: 'badge-warning',
  resolved: 'badge-success',
  false_positive: 'bg-gray-100 text-gray-700',
};

function AlertCard({ alert }: { alert: Alert }) {
  const user = useAuthStore((state) => state.user);
  const canManage = user?.role === 'admin' || user?.role === 'operator';
  const updateStatus = useUpdateAlertStatus();

  const handleAcknowledge = () => {
    updateStatus.mutate({ alertId: alert.id, status: 'acknowledged' });
  };

  const handleResolve = () => {
    updateStatus.mutate({ alertId: alert.id, status: 'resolved' });
  };

  const handleFalsePositive = () => {
    updateStatus.mutate({ alertId: alert.id, status: 'false_positive' });
  };

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={severityColors[alert.severity]}>
              {alert.severity}
            </span>
            <span className={statusColors[alert.status]}>
              {alert.status.replace('_', ' ')}
            </span>
          </div>
          <h3 className="mt-2 text-lg font-semibold text-gray-900">
            {alert.title}
          </h3>
          <p className="mt-1 text-sm text-gray-600">{alert.description}</p>

          <div className="mt-4 flex flex-wrap gap-4 text-sm text-gray-500">
            <span>
              Created: {format(new Date(alert.timestamp), 'MMM d, yyyy HH:mm')}
            </span>
            {alert.acknowledged_at && (
              <span>
                Acknowledged:{' '}
                {formatDistanceToNow(new Date(alert.acknowledged_at), {
                  addSuffix: true,
                })}
              </span>
            )}
            {alert.resolved_at && (
              <span>
                Resolved:{' '}
                {formatDistanceToNow(new Date(alert.resolved_at), {
                  addSuffix: true,
                })}
              </span>
            )}
          </div>
        </div>

        {canManage && alert.status !== 'resolved' && alert.status !== 'false_positive' && (
          <div className="flex flex-col gap-2">
            {alert.status === 'new' && (
              <button
                onClick={handleAcknowledge}
                disabled={updateStatus.isPending}
                className="btn-secondary text-xs px-3 py-1.5"
              >
                <Eye className="w-3 h-3 mr-1" />
                Acknowledge
              </button>
            )}
            <button
              onClick={handleResolve}
              disabled={updateStatus.isPending}
              className="btn-primary text-xs px-3 py-1.5"
            >
              <CheckCircle className="w-3 h-3 mr-1" />
              Resolve
            </button>
            <button
              onClick={handleFalsePositive}
              disabled={updateStatus.isPending}
              className="text-xs px-3 py-1.5 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg"
            >
              <XCircle className="w-3 h-3 mr-1 inline" />
              False Positive
            </button>
          </div>
        )}
      </div>

      {alert.llm_analysis && (
        <div className="mt-4 p-4 bg-primary-50 rounded-lg">
          <h4 className="text-sm font-medium text-primary-900 mb-2">
            AI Analysis
          </h4>
          <p className="text-sm text-primary-700">
            {typeof alert.llm_analysis === 'object'
              ? JSON.stringify(alert.llm_analysis, null, 2)
              : alert.llm_analysis}
          </p>
        </div>
      )}
    </div>
  );
}

export default function AlertsPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const offset = (page - 1) * pageSize;

  const { data, isLoading, refetch, isFetching } = useAlerts({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    limit: pageSize,
    offset,
  });

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  const filteredAlerts = data?.items.filter((alert) => {
    if (!search) return true;
    const searchLower = search.toLowerCase();
    return (
      alert.title.toLowerCase().includes(searchLower) ||
      alert.description.toLowerCase().includes(searchLower)
    );
  });

  const activeCount = data?.items.filter(
    (a) => a.status === 'new' || a.status === 'acknowledged'
  ).length || 0;

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
          <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
          <p className="text-gray-500">
            {activeCount} active alerts
          </p>
        </div>
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

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="input pl-10"
          />
        </div>
        <div className="flex gap-2">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="input w-full sm:w-40"
          >
            <option value="">All statuses</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="input w-full sm:w-40"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Alert cards */}
      <div className="space-y-4">
        {isLoading ? (
          [...Array(3)].map((_, i) => (
            <div key={i} className="card p-6">
              <div className="animate-pulse space-y-3">
                <div className="h-4 bg-gray-100 rounded w-24" />
                <div className="h-6 bg-gray-100 rounded w-3/4" />
                <div className="h-4 bg-gray-100 rounded w-full" />
              </div>
            </div>
          ))
        ) : filteredAlerts?.length ? (
          filteredAlerts.map((alert) => (
            <AlertCard key={alert.id} alert={alert} />
          ))
        ) : (
          <div className="card p-12 text-center">
            <Bell className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p className="text-gray-500">No alerts found</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {data && data.total > 0 && (
        <div className="card">
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
  );
}
