import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Monitor, Shield, ShieldOff, Search, RefreshCw, ExternalLink } from 'lucide-react';
import { useDevices, useQuarantineDevice, useReleaseDevice } from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { Device, DeviceStatus } from '../types';
import Pagination from '../components/Pagination';

const statusConfig: Record<DeviceStatus, { label: string; class: string }> = {
  active: { label: 'Active', class: 'badge-success' },
  inactive: { label: 'Inactive', class: 'bg-gray-100 text-gray-700' },
  quarantined: { label: 'Quarantined', class: 'badge-danger' },
  unknown: { label: 'Unknown', class: 'bg-gray-100 text-gray-700' },
};

function DeviceRow({ device }: { device: Device }) {
  const user = useAuthStore((state) => state.user);
  const canManage = user?.role === 'admin' || user?.role === 'operator';

  const quarantine = useQuarantineDevice();
  const release = useReleaseDevice();

  const handleQuarantine = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (confirm(`Quarantine device "${device.hostname || device.mac_address}"?`)) {
      quarantine.mutate(device.id);
    }
  };

  const handleRelease = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    release.mutate(device.id);
  };

  const status = statusConfig[device.status] || statusConfig.unknown;

  return (
    <tr className="hover:bg-gray-50 cursor-pointer">
      <td className="px-6 py-4 whitespace-nowrap">
        <Link to={`/devices/${device.id}`} className="flex items-center gap-3">
          <div className="flex-shrink-0 w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
            <Monitor className="w-5 h-5 text-gray-500" />
          </div>
          <div>
            <div className="text-sm font-medium text-gray-900 hover:text-primary-600 flex items-center gap-1">
              {device.hostname || 'Unknown'}
              <ExternalLink className="w-3 h-3 text-gray-400" />
            </div>
            <div className="text-xs text-gray-500">{device.mac_address}</div>
          </div>
        </Link>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <div className="text-sm text-gray-900">
          {device.ip_addresses.join(', ') || '-'}
        </div>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <div className="text-sm text-gray-900">
          {device.manufacturer || '-'}
        </div>
        <div className="text-xs text-gray-500">
          {device.device_type || 'Unknown type'}
        </div>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <span className={status.class}>{status.label}</span>
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        {formatDistanceToNow(new Date(device.last_seen), { addSuffix: true })}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
        {canManage && (
          <div className="flex items-center justify-end gap-2">
            {device.status === 'quarantined' ? (
              <button
                onClick={handleRelease}
                disabled={release.isPending}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-success-700 bg-success-50 rounded hover:bg-success-100 transition-colors"
              >
                <Shield className="w-3 h-3" />
                Release
              </button>
            ) : (
              <button
                onClick={handleQuarantine}
                disabled={quarantine.isPending}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-danger-700 bg-danger-50 rounded hover:bg-danger-100 transition-colors"
              >
                <ShieldOff className="w-3 h-3" />
                Quarantine
              </button>
            )}
          </div>
        )}
      </td>
    </tr>
  );
}

export default function DevicesPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const { data, isLoading, refetch, isFetching } = useDevices({
    status: statusFilter || undefined,
    page,
    page_size: pageSize,
    search: search || undefined,
  } as { status?: string; page?: number; page_size?: number });

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
          <h1 className="text-2xl font-bold text-gray-900">Devices</h1>
          <p className="text-gray-500">
            {data?.total || 0} devices discovered on your network
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
            placeholder="Search devices..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="input pl-10"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="input w-full sm:w-40"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="quarantined">Quarantined</option>
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Device
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  IP Address
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Manufacturer
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Seen
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {isLoading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i}>
                    <td colSpan={6} className="px-6 py-4">
                      <div className="animate-pulse h-10 bg-gray-100 rounded" />
                    </td>
                  </tr>
                ))
              ) : data?.items.length ? (
                data.items.map((device) => (
                  <DeviceRow key={device.id} device={device} />
                ))
              ) : (
                <tr>
                  <td
                    colSpan={6}
                    className="px-6 py-12 text-center text-gray-500"
                  >
                    No devices found
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
              pageSizeOptions={[10, 25, 50, 100]}
            />
          </div>
        )}
      </div>
    </div>
  );
}
