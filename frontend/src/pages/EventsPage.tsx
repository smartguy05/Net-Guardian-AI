import { useState } from 'react';
import { Activity, Search, RefreshCw } from 'lucide-react';
import { useEvents } from '../api/hooks';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import type { RawEvent, EventSeverity } from '../types';
import Pagination from '../components/Pagination';

const severityColors: Record<EventSeverity, string> = {
  debug: 'bg-gray-100 text-gray-700',
  info: 'badge-info',
  warning: 'badge-warning',
  error: 'badge-danger',
  critical: 'badge-danger',
};

const eventTypeLabels: Record<string, string> = {
  dns: 'DNS',
  firewall: 'Firewall',
  auth: 'Auth',
  http: 'HTTP',
  system: 'System',
  unknown: 'Unknown',
};

function EventRow({ event }: { event: RawEvent }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        className="hover:bg-gray-50 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
          <div className="flex flex-col">
            <span>{format(new Date(event.timestamp), 'HH:mm:ss')}</span>
            <span className="text-xs text-gray-400">
              {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
            </span>
          </div>
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className="badge bg-primary-50 text-primary-700">
            {eventTypeLabels[event.event_type] || event.event_type}
          </span>
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className={severityColors[event.severity]}>
            {event.severity}
          </span>
        </td>
        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
          {event.client_ip || '-'}
        </td>
        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
          {event.domain || '-'}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          {event.action && (
            <span
              className={clsx(
                'badge',
                event.action === 'blocked' || event.action === 'block'
                  ? 'badge-danger'
                  : event.action === 'allowed' || event.action === 'allow'
                  ? 'badge-success'
                  : 'bg-gray-100 text-gray-700'
              )}
            >
              {event.action}
            </span>
          )}
        </td>
        <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate">
          {event.raw_message}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-4 py-3 bg-gray-50">
            <div className="text-sm">
              <div className="font-medium text-gray-900 mb-2">Raw Message</div>
              <pre className="p-3 bg-gray-900 text-gray-100 rounded-lg overflow-x-auto text-xs">
                {event.raw_message}
              </pre>
              {Object.keys(event.parsed_fields).length > 0 && (
                <>
                  <div className="font-medium text-gray-900 mt-4 mb-2">
                    Parsed Fields
                  </div>
                  <pre className="p-3 bg-gray-100 rounded-lg overflow-x-auto text-xs">
                    {JSON.stringify(event.parsed_fields, null, 2)}
                  </pre>
                </>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function EventsPage() {
  const [search, setSearch] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  const offset = (page - 1) * pageSize;

  const { data, isLoading, refetch, isFetching } = useEvents({
    event_type: eventType || undefined,
    severity: severity || undefined,
    domain_contains: search || undefined,
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
          <h1 className="text-2xl font-bold text-gray-900">Events</h1>
          <p className="text-gray-500">
            {data?.total || 0} events recorded
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
            placeholder="Search by domain..."
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
            value={eventType}
            onChange={(e) => {
              setEventType(e.target.value);
              setPage(1);
            }}
            className="input w-full sm:w-36"
          >
            <option value="">All types</option>
            <option value="dns">DNS</option>
            <option value="firewall">Firewall</option>
            <option value="auth">Auth</option>
            <option value="http">HTTP</option>
            <option value="system">System</option>
          </select>
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            className="input w-full sm:w-36"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
            <option value="debug">Debug</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Client IP
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Domain
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Action
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Message
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {isLoading ? (
                [...Array(10)].map((_, i) => (
                  <tr key={i}>
                    <td colSpan={7} className="px-4 py-3">
                      <div className="animate-pulse h-8 bg-gray-100 rounded" />
                    </td>
                  </tr>
                ))
              ) : data?.items.length ? (
                data.items.map((event) => (
                  <EventRow key={event.id} event={event} />
                ))
              ) : (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-12 text-center text-gray-500"
                  >
                    <Activity className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                    No events found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.total > 0 && (
          <div className="border-t border-gray-200">
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              totalItems={data.total}
              pageSize={pageSize}
              onPageChange={handlePageChange}
              onPageSizeChange={handlePageSizeChange}
              pageSizeOptions={[25, 50, 100, 200]}
            />
          </div>
        )}
      </div>
    </div>
  );
}
