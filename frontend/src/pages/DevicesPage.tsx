import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Monitor, Shield, ShieldOff, Search, RefreshCw, ExternalLink, Tag, Square, CheckSquare } from 'lucide-react';
import { useDevices, useQuarantineDevice, useReleaseDevice, exportDevicesCSV, exportDevicesPDF, useAllTags, useBulkTagDevices } from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { Device, DeviceStatus } from '../types';
import Pagination from '../components/Pagination';
import ExportButton from '../components/ExportButton';
import TagFilter from '../components/TagFilter';
import BulkTagModal from '../components/BulkTagModal';

const statusConfig: Record<DeviceStatus, { label: string; class: string }> = {
  active: { label: 'Active', class: 'badge-success' },
  inactive: { label: 'Inactive', class: 'bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300' },
  quarantined: { label: 'Quarantined', class: 'badge-danger' },
  unknown: { label: 'Unknown', class: 'bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300' },
};

interface DeviceRowProps {
  device: Device;
  isSelected: boolean;
  onSelectChange: (selected: boolean) => void;
  showCheckbox: boolean;
}

function DeviceRow({ device, isSelected, onSelectChange, showCheckbox }: DeviceRowProps) {
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

  const handleCheckboxClick = (e: React.MouseEvent) => {
    e.stopPropagation();
  };

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-zinc-700/50 cursor-pointer">
      {showCheckbox && (
        <td className="px-4 py-4 whitespace-nowrap" onClick={handleCheckboxClick}>
          <button
            onClick={() => onSelectChange(!isSelected)}
            className="p-1 rounded hover:bg-gray-200 dark:hover:bg-zinc-600"
          >
            {isSelected ? (
              <CheckSquare className="w-5 h-5 text-primary-600 dark:text-primary-400" />
            ) : (
              <Square className="w-5 h-5 text-gray-400 dark:text-gray-500" />
            )}
          </button>
        </td>
      )}
      <td className="px-4 sm:px-6 py-4 whitespace-nowrap">
        <Link to={`/devices/${device.id}`} className="flex items-center gap-2 sm:gap-3">
          <div className="flex-shrink-0 w-8 h-8 sm:w-10 sm:h-10 bg-gray-100 dark:bg-zinc-700 rounded-lg flex items-center justify-center">
            <Monitor className="w-4 h-4 sm:w-5 sm:h-5 text-gray-500 dark:text-gray-400" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium text-gray-900 dark:text-white hover:text-primary-600 dark:hover:text-primary-400 flex items-center gap-1 truncate">
              {device.hostname || 'Unknown'}
              <ExternalLink className="w-3 h-3 text-gray-400 flex-shrink-0 hidden sm:block" />
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{device.mac_address}</div>
            {/* Show IP on mobile since column is hidden */}
            <div className="text-xs text-gray-400 dark:text-gray-500 md:hidden truncate">
              {device.ip_addresses[0] || '-'}
            </div>
          </div>
        </Link>
      </td>
      <td className="hidden md:table-cell px-6 py-4 whitespace-nowrap">
        <div className="text-sm text-gray-900 dark:text-gray-100">
          {device.ip_addresses.join(', ') || '-'}
        </div>
      </td>
      <td className="hidden lg:table-cell px-6 py-4 whitespace-nowrap">
        <div className="text-sm text-gray-900 dark:text-gray-100">
          {device.manufacturer || '-'}
        </div>
        <div className="text-xs text-gray-500 dark:text-gray-400">
          {device.device_type || 'Unknown type'}
        </div>
      </td>
      <td className="px-4 sm:px-6 py-4 whitespace-nowrap">
        <span className={clsx(status.class, 'text-xs sm:text-sm')}>{status.label}</span>
      </td>
      <td className="hidden sm:table-cell px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
        {formatDistanceToNow(new Date(device.last_seen), { addSuffix: true })}
      </td>
      <td className="px-4 sm:px-6 py-4 whitespace-nowrap text-right text-sm">
        {canManage && (
          <div className="flex items-center justify-end gap-2">
            {device.status === 'quarantined' ? (
              <button
                onClick={handleRelease}
                disabled={release.isPending}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-success-700 dark:text-success-400 bg-success-50 dark:bg-success-900/30 rounded hover:bg-success-100 dark:hover:bg-success-900/50 transition-colors"
              >
                <Shield className="w-3 h-3" />
                Release
              </button>
            ) : (
              <button
                onClick={handleQuarantine}
                disabled={quarantine.isPending}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-danger-700 dark:text-danger-400 bg-danger-50 dark:bg-danger-900/30 rounded hover:bg-danger-100 dark:hover:bg-danger-900/50 transition-colors"
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
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set());
  const [showBulkTagModal, setShowBulkTagModal] = useState(false);

  const user = useAuthStore((state) => state.user);
  const canManage = user?.role === 'admin' || user?.role === 'operator';

  const { data, isLoading, refetch, isFetching } = useDevices({
    status: statusFilter || undefined,
    page,
    page_size: pageSize,
    search: search || undefined,
    tags: selectedTags.length > 0 ? selectedTags : undefined,
  } as { status?: string; page?: number; page_size?: number; tags?: string[] });

  const { data: tagsData } = useAllTags();
  const bulkTagMutation = useBulkTagDevices();

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;
  const availableTags = tagsData?.tags || [];
  const tagCounts = tagsData?.counts || {};

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
  };

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize);
    setPage(1);
  };

  const handleSelectDevice = (deviceId: string, selected: boolean) => {
    setSelectedDevices((prev) => {
      const next = new Set(prev);
      if (selected) {
        next.add(deviceId);
      } else {
        next.delete(deviceId);
      }
      return next;
    });
  };

  const handleSelectAll = () => {
    if (!data?.items) return;
    const allIds = data.items.map((d) => d.id);
    const allSelected = allIds.every((id) => selectedDevices.has(id));
    if (allSelected) {
      setSelectedDevices((prev) => {
        const next = new Set(prev);
        allIds.forEach((id) => next.delete(id));
        return next;
      });
    } else {
      setSelectedDevices((prev) => {
        const next = new Set(prev);
        allIds.forEach((id) => next.add(id));
        return next;
      });
    }
  };

  const handleBulkTag = async (tagsToAdd: string[], tagsToRemove: string[]) => {
    await bulkTagMutation.mutateAsync({
      deviceIds: Array.from(selectedDevices),
      tagsToAdd: tagsToAdd,
      tagsToRemove: tagsToRemove,
    });
    setSelectedDevices(new Set());
  };

  const clearSelection = () => {
    setSelectedDevices(new Set());
  };

  const currentPageIds = data?.items?.map((d) => d.id) || [];
  const allCurrentSelected = currentPageIds.length > 0 && currentPageIds.every((id) => selectedDevices.has(id));
  const someCurrentSelected = currentPageIds.some((id) => selectedDevices.has(id));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Devices</h1>
          <p className="text-gray-500 dark:text-gray-400">
            {data?.total || 0} devices discovered on your network
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ExportButton
            onExportCSV={() => exportDevicesCSV({
              status: statusFilter || undefined,
            })}
            onExportPDF={() => exportDevicesPDF({
              status: statusFilter || undefined,
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
        <TagFilter
          availableTags={availableTags}
          selectedTags={selectedTags}
          onChange={(tags) => {
            setSelectedTags(tags);
            setPage(1);
          }}
          tagCounts={tagCounts}
          className="w-full sm:w-56"
        />
      </div>

      {/* Bulk Actions Bar */}
      {selectedDevices.size > 0 && canManage && (
        <div className="flex items-center justify-between p-3 bg-primary-50 dark:bg-primary-900/20 rounded-lg border border-primary-200 dark:border-primary-800">
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-primary-700 dark:text-primary-300">
              {selectedDevices.size} device{selectedDevices.size !== 1 ? 's' : ''} selected
            </span>
            <button
              onClick={clearSelection}
              className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-800 dark:hover:text-primary-200"
            >
              Clear selection
            </button>
          </div>
          <button
            onClick={() => setShowBulkTagModal(true)}
            className="btn-secondary inline-flex items-center gap-2"
          >
            <Tag className="w-4 h-4" />
            Manage Tags
          </button>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-zinc-700">
            <thead className="bg-gray-50 dark:bg-zinc-800/50">
              <tr>
                {canManage && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider w-12">
                    <button
                      onClick={handleSelectAll}
                      className="p-1 rounded hover:bg-gray-200 dark:hover:bg-zinc-600"
                      title={allCurrentSelected ? 'Deselect all' : 'Select all'}
                    >
                      {allCurrentSelected ? (
                        <CheckSquare className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                      ) : someCurrentSelected ? (
                        <CheckSquare className="w-5 h-5 text-gray-400 dark:text-gray-500" />
                      ) : (
                        <Square className="w-5 h-5 text-gray-400 dark:text-gray-500" />
                      )}
                    </button>
                  </th>
                )}
                <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Device
                </th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  IP Address
                </th>
                <th className="hidden lg:table-cell px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Manufacturer
                </th>
                <th className="px-4 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="hidden sm:table-cell px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Last Seen
                </th>
                <th className="px-4 sm:px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-zinc-800 divide-y divide-gray-200 dark:divide-zinc-700">
              {isLoading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i}>
                    <td colSpan={canManage ? 7 : 6} className="px-6 py-4">
                      <div className="animate-pulse h-10 bg-gray-100 dark:bg-zinc-700 rounded" />
                    </td>
                  </tr>
                ))
              ) : data?.items.length ? (
                data.items.map((device) => (
                  <DeviceRow
                    key={device.id}
                    device={device}
                    isSelected={selectedDevices.has(device.id)}
                    onSelectChange={(selected) => handleSelectDevice(device.id, selected)}
                    showCheckbox={canManage}
                  />
                ))
              ) : (
                <tr>
                  <td
                    colSpan={canManage ? 7 : 6}
                    className="px-6 py-12 text-center text-gray-500 dark:text-gray-400"
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

      {/* Bulk Tag Modal */}
      <BulkTagModal
        isOpen={showBulkTagModal}
        onClose={() => setShowBulkTagModal(false)}
        selectedCount={selectedDevices.size}
        availableTags={availableTags}
        onApply={handleBulkTag}
      />
    </div>
  );
}
