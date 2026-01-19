import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Monitor,
  Smartphone,
  Server,
  Wifi,
  HelpCircle,
  Shield,
  Activity,
  AlertTriangle,
  Edit2,
  X,
  ShieldOff,
  ShieldCheck,
  BarChart3,
  RefreshCw,
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import {
  useDevice,
  useEvents,
  useAlerts,
  useUpdateDevice,
  useQuarantineDevice,
  useReleaseDevice,
  useDeviceBaselines,
  useDeviceAnomalies,
  useRecalculateBaseline,
} from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import Pagination from '../components/Pagination';
import type { Device, DeviceStatus, RawEvent, Alert, DeviceBaseline, AnomalyDetection } from '../types';

const deviceTypeIcons: Record<string, typeof Monitor> = {
  pc: Monitor,
  mobile: Smartphone,
  server: Server,
  network: Wifi,
  iot: Wifi,
  unknown: HelpCircle,
};

const statusColors: Record<DeviceStatus, string> = {
  active: 'bg-success-100 text-success-700',
  inactive: 'bg-gray-100 text-gray-700',
  quarantined: 'bg-danger-100 text-danger-700',
  unknown: 'bg-gray-100 text-gray-500',
};

const deviceTypeOptions = [
  { value: 'pc', label: 'PC/Laptop' },
  { value: 'mobile', label: 'Mobile Device' },
  { value: 'server', label: 'Server' },
  { value: 'network', label: 'Network Device' },
  { value: 'iot', label: 'IoT Device' },
  { value: 'unknown', label: 'Unknown' },
];

function EditDeviceForm({
  device,
  onClose,
}: {
  device: Device;
  onClose: () => void;
}) {
  const [hostname, setHostname] = useState(device.hostname || '');
  const [deviceType, setDeviceType] = useState(device.device_type || 'unknown');
  const [tags, setTags] = useState(device.profile_tags.join(', '));
  const updateDevice = useUpdateDevice();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await updateDevice.mutateAsync({
        id: device.id,
        hostname: hostname || undefined,
        device_type: deviceType,
        profile_tags: tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      });
      onClose();
    } catch (error) {
      console.error('Failed to update device:', error);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        <div
          className="fixed inset-0 bg-gray-900/50 transition-opacity"
          onClick={onClose}
        />
        <div className="relative w-full max-w-md bg-white rounded-xl shadow-xl">
          <div className="flex items-center justify-between p-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Edit Device</h2>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Hostname
              </label>
              <input
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="input w-full"
                placeholder="e.g., johns-laptop"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Device Type
              </label>
              <select
                value={deviceType}
                onChange={(e) => setDeviceType(e.target.value)}
                className="input w-full"
              >
                {deviceTypeOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Tags (comma-separated)
              </label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                className="input w-full"
                placeholder="e.g., trusted, family, work"
              />
            </div>

            <div className="flex gap-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 btn-secondary"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={updateDevice.isPending}
                className="flex-1 btn-primary"
              >
                {updateDevice.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

function EventsTable({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useEvents({
    device_id: deviceId,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  });

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 bg-gray-100 rounded" />
        ))}
      </div>
    );
  }

  if (!data?.items.length) {
    return (
      <div className="text-center py-8 text-gray-500">
        <Activity className="w-8 h-8 mx-auto mb-2 text-gray-300" />
        <p>No events found for this device</p>
      </div>
    );
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left text-sm text-gray-500 border-b">
              <th className="pb-2 font-medium">Time</th>
              <th className="pb-2 font-medium">Type</th>
              <th className="pb-2 font-medium">Domain/Target</th>
              <th className="pb-2 font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {data.items.map((event: RawEvent) => (
              <tr key={event.id} className="text-sm">
                <td className="py-2 text-gray-600">
                  {format(new Date(event.timestamp), 'MMM d, HH:mm:ss')}
                </td>
                <td className="py-2">
                  <span
                    className={clsx(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      event.event_type === 'dns'
                        ? 'bg-blue-100 text-blue-700'
                        : event.event_type === 'firewall'
                        ? 'bg-orange-100 text-orange-700'
                        : 'bg-gray-100 text-gray-700'
                    )}
                  >
                    {event.event_type}
                  </span>
                </td>
                <td className="py-2 font-mono text-xs text-gray-700">
                  {event.domain || event.target_ip || '-'}
                </td>
                <td className="py-2">
                  {event.action && (
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        event.action === 'blocked'
                          ? 'bg-danger-100 text-danger-700'
                          : 'bg-success-100 text-success-700'
                      )}
                    >
                      {event.action}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pagination
        currentPage={page}
        totalPages={totalPages}
        totalItems={data.total}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={(size) => {
          setPageSize(size);
          setPage(1);
        }}
        pageSizeOptions={[10, 25, 50]}
      />
    </div>
  );
}

function AlertsList({ deviceId }: { deviceId: string }) {
  const { data, isLoading } = useAlerts({ device_id: deviceId, limit: 10 });

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-16 bg-gray-100 rounded" />
        ))}
      </div>
    );
  }

  if (!data?.items.length) {
    return (
      <div className="text-center py-8 text-gray-500">
        <Shield className="w-8 h-8 mx-auto mb-2 text-gray-300" />
        <p>No alerts for this device</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {data.items.map((alert: Alert) => (
        <div
          key={alert.id}
          className={clsx(
            'p-3 rounded-lg border',
            alert.severity === 'critical'
              ? 'border-danger-200 bg-danger-50'
              : alert.severity === 'high'
              ? 'border-warning-200 bg-warning-50'
              : 'border-gray-200 bg-gray-50'
          )}
        >
          <div className="flex items-start justify-between">
            <div>
              <h4 className="font-medium text-gray-900">{alert.title}</h4>
              <p className="text-sm text-gray-600 mt-1">{alert.description}</p>
            </div>
            <span
              className={clsx(
                'px-2 py-0.5 rounded text-xs font-medium',
                alert.status === 'new'
                  ? 'bg-danger-100 text-danger-700'
                  : alert.status === 'acknowledged'
                  ? 'bg-warning-100 text-warning-700'
                  : 'bg-gray-100 text-gray-700'
              )}
            >
              {alert.status}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-2">
            {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
          </p>
        </div>
      ))}
    </div>
  );
}

const baselineStatusColors = {
  learning: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  ready: 'bg-green-100 text-green-700 border-green-200',
  stale: 'bg-gray-100 text-gray-700 border-gray-200',
};

const baselineTypeLabels = {
  dns: 'DNS Activity',
  traffic: 'Traffic Patterns',
  connection: 'Connections',
};

function BaselinesList({ deviceId }: { deviceId: string }) {
  const { data, isLoading, refetch } = useDeviceBaselines(deviceId);
  const recalculate = useRecalculateBaseline();
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';

  const handleRecalculate = async () => {
    try {
      await recalculate.mutateAsync({ deviceId });
      refetch();
    } catch (error) {
      console.error('Failed to recalculate baselines:', error);
    }
  };

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-24 bg-gray-100 rounded" />
        ))}
      </div>
    );
  }

  if (!data?.items.length) {
    return (
      <div className="text-center py-8 text-gray-500">
        <BarChart3 className="w-8 h-8 mx-auto mb-2 text-gray-300" />
        <p>No baselines established yet</p>
        <p className="text-sm mt-1">Baselines are created as the device generates activity</p>
        {isAdmin && (
          <button
            onClick={handleRecalculate}
            disabled={recalculate.isPending}
            className="mt-4 btn-secondary"
          >
            <RefreshCw className={clsx('w-4 h-4 mr-2', recalculate.isPending && 'animate-spin')} />
            Calculate Baselines
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {isAdmin && (
        <div className="flex justify-end">
          <button
            onClick={handleRecalculate}
            disabled={recalculate.isPending}
            className="btn-secondary text-sm"
          >
            <RefreshCw className={clsx('w-4 h-4 mr-2', recalculate.isPending && 'animate-spin')} />
            Recalculate
          </button>
        </div>
      )}
      <div className="grid gap-4">
        {data.items.map((baseline: DeviceBaseline) => (
          <div
            key={baseline.id}
            className="p-4 rounded-lg border border-gray-200 bg-white"
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h4 className="font-medium text-gray-900">
                  {baselineTypeLabels[baseline.baseline_type] || baseline.baseline_type}
                </h4>
                <p className="text-sm text-gray-500">
                  {baseline.sample_count} samples collected
                </p>
              </div>
              <span
                className={clsx(
                  'px-2 py-1 rounded-full text-xs font-medium border',
                  baselineStatusColors[baseline.status]
                )}
              >
                {baseline.status}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500">Window:</span>{' '}
                <span className="text-gray-900">{baseline.baseline_window_days} days</span>
              </div>
              <div>
                <span className="text-gray-500">Min samples:</span>{' '}
                <span className="text-gray-900">{baseline.min_samples}</span>
              </div>
              {baseline.last_calculated && (
                <div className="col-span-2">
                  <span className="text-gray-500">Last calculated:</span>{' '}
                  <span className="text-gray-900">
                    {formatDistanceToNow(new Date(baseline.last_calculated), { addSuffix: true })}
                  </span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const anomalySeverityColors = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

const anomalyTypeLabels = {
  new_domain: 'New Domain',
  volume_spike: 'Volume Spike',
  time_anomaly: 'Time Anomaly',
  new_connection: 'New Connection',
  new_port: 'New Port',
  blocked_spike: 'Blocked Spike',
  pattern_change: 'Pattern Change',
};

function AnomaliesList({ deviceId }: { deviceId: string }) {
  const { data, isLoading } = useDeviceAnomalies(deviceId, { limit: 20 });

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-20 bg-gray-100 rounded" />
        ))}
      </div>
    );
  }

  if (!data?.items.length) {
    return (
      <div className="text-center py-8 text-gray-500">
        <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-gray-300" />
        <p>No anomalies detected</p>
        <p className="text-sm mt-1">Anomalies will appear when behavior deviates from baseline</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {data.items.map((anomaly: AnomalyDetection) => (
        <div
          key={anomaly.id}
          className={clsx(
            'p-3 rounded-lg border',
            anomaly.severity === 'critical'
              ? 'border-red-200 bg-red-50'
              : anomaly.severity === 'high'
              ? 'border-orange-200 bg-orange-50'
              : 'border-gray-200 bg-gray-50'
          )}
        >
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-2">
              <AlertTriangle
                className={clsx(
                  'w-4 h-4 mt-0.5',
                  anomaly.severity === 'critical'
                    ? 'text-red-500'
                    : anomaly.severity === 'high'
                    ? 'text-orange-500'
                    : 'text-gray-400'
                )}
              />
              <div>
                <h4 className="font-medium text-gray-900">
                  {anomalyTypeLabels[anomaly.anomaly_type] || anomaly.anomaly_type}
                </h4>
                <p className="text-sm text-gray-600 mt-0.5">{anomaly.description}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={clsx(
                  'px-2 py-0.5 rounded text-xs font-medium border',
                  anomalySeverityColors[anomaly.severity]
                )}
              >
                {anomaly.severity}
              </span>
              <span
                className={clsx(
                  'px-2 py-0.5 rounded text-xs font-medium',
                  anomaly.status === 'active'
                    ? 'bg-red-100 text-red-700'
                    : 'bg-gray-100 text-gray-700'
                )}
              >
                {anomaly.status}
              </span>
            </div>
          </div>
          <div className="flex items-center justify-between mt-2">
            <p className="text-xs text-gray-500">
              Detected {formatDistanceToNow(new Date(anomaly.detected_at), { addSuffix: true })}
            </p>
            <p className="text-xs text-gray-500">Score: {anomaly.score.toFixed(2)}</p>
          </div>
        </div>
      ))}
      {data.total > 20 && (
        <Link
          to={`/anomalies?device_id=${deviceId}`}
          className="block text-center text-sm text-primary-600 hover:text-primary-700 py-2"
        >
          View all {data.total} anomalies
        </Link>
      )}
    </div>
  );
}

export default function DeviceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const user = useAuthStore((state) => state.user);
  const [isEditing, setIsEditing] = useState(false);
  const [activeTab, setActiveTab] = useState<'events' | 'alerts' | 'baselines' | 'anomalies'>('events');

  const { data: device, isLoading, error } = useDevice(id || '');
  const quarantineDevice = useQuarantineDevice();
  const releaseDevice = useReleaseDevice();

  const isOperator = user?.role === 'admin' || user?.role === 'operator';

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-48 mb-4" />
          <div className="h-64 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  if (error || !device) {
    return (
      <div className="space-y-6">
        <Link
          to="/devices"
          className="inline-flex items-center text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Devices
        </Link>
        <div className="card p-12 text-center">
          <AlertTriangle className="w-12 h-12 mx-auto mb-3 text-danger-500" />
          <h2 className="text-xl font-semibold text-gray-900">Device Not Found</h2>
          <p className="text-gray-500 mt-2">
            The device you're looking for doesn't exist or has been removed.
          </p>
        </div>
      </div>
    );
  }

  const DeviceIcon = deviceTypeIcons[device.device_type || 'unknown'] || HelpCircle;

  const handleQuarantine = () => {
    if (confirm(`Quarantine device "${device.hostname || device.mac_address}"?`)) {
      quarantineDevice.mutate(device.id);
    }
  };

  const handleRelease = () => {
    if (confirm(`Release device "${device.hostname || device.mac_address}" from quarantine?`)) {
      releaseDevice.mutate(device.id);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            to="/devices"
            className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              {device.hostname || device.mac_address}
            </h1>
            <p className="text-gray-500">{device.mac_address}</p>
          </div>
        </div>

        {isOperator && (
          <div className="flex gap-2">
            <button
              onClick={() => setIsEditing(true)}
              className="btn-secondary"
            >
              <Edit2 className="w-4 h-4 mr-2" />
              Edit
            </button>
            {device.status === 'quarantined' ? (
              <button
                onClick={handleRelease}
                disabled={releaseDevice.isPending}
                className="btn-primary"
              >
                <ShieldCheck className="w-4 h-4 mr-2" />
                Release
              </button>
            ) : (
              <button
                onClick={handleQuarantine}
                disabled={quarantineDevice.isPending}
                className="bg-danger-600 text-white px-4 py-2 rounded-lg font-medium hover:bg-danger-700 flex items-center"
              >
                <ShieldOff className="w-4 h-4 mr-2" />
                Quarantine
              </button>
            )}
          </div>
        )}
      </div>

      {/* Device Info Card */}
      <div className="card p-6">
        <div className="flex items-start gap-6">
          <div
            className={clsx(
              'flex h-16 w-16 items-center justify-center rounded-xl',
              statusColors[device.status]
            )}
          >
            <DeviceIcon className="w-8 h-8" />
          </div>

          <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <h3 className="text-sm font-medium text-gray-500">Status</h3>
              <span
                className={clsx(
                  'inline-flex mt-1 px-3 py-1 rounded-full text-sm font-medium',
                  statusColors[device.status]
                )}
              >
                {device.status}
              </span>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-500">Device Type</h3>
              <p className="mt-1 text-gray-900 capitalize">
                {device.device_type || 'Unknown'}
              </p>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-500">Manufacturer</h3>
              <p className="mt-1 text-gray-900">
                {device.manufacturer || 'Unknown'}
              </p>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-500">IP Addresses</h3>
              <div className="mt-1 flex flex-wrap gap-1">
                {device.ip_addresses.length > 0 ? (
                  device.ip_addresses.map((ip) => (
                    <span
                      key={ip}
                      className="px-2 py-0.5 bg-gray-100 rounded text-sm font-mono"
                    >
                      {ip}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-500">No IPs recorded</span>
                )}
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-500">First Seen</h3>
              <p className="mt-1 text-gray-900">
                {format(new Date(device.first_seen), 'MMM d, yyyy HH:mm')}
              </p>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-500">Last Seen</h3>
              <p className="mt-1 text-gray-900">
                {formatDistanceToNow(new Date(device.last_seen), { addSuffix: true })}
              </p>
            </div>

            {device.profile_tags.length > 0 && (
              <div className="md:col-span-3">
                <h3 className="text-sm font-medium text-gray-500">Tags</h3>
                <div className="mt-1 flex flex-wrap gap-2">
                  {device.profile_tags.map((tag) => (
                    <span
                      key={tag}
                      className="px-2 py-1 bg-primary-100 text-primary-700 rounded text-sm"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-6">
          <button
            onClick={() => setActiveTab('events')}
            className={clsx(
              'pb-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'events'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            <Activity className="w-4 h-4 inline-block mr-2" />
            Events
          </button>
          <button
            onClick={() => setActiveTab('alerts')}
            className={clsx(
              'pb-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'alerts'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            <Shield className="w-4 h-4 inline-block mr-2" />
            Alerts
          </button>
          <button
            onClick={() => setActiveTab('baselines')}
            className={clsx(
              'pb-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'baselines'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            <BarChart3 className="w-4 h-4 inline-block mr-2" />
            Baselines
          </button>
          <button
            onClick={() => setActiveTab('anomalies')}
            className={clsx(
              'pb-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'anomalies'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            <AlertTriangle className="w-4 h-4 inline-block mr-2" />
            Anomalies
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      <div className="card p-6">
        {activeTab === 'events' && <EventsTable deviceId={device.id} />}
        {activeTab === 'alerts' && <AlertsList deviceId={device.id} />}
        {activeTab === 'baselines' && <BaselinesList deviceId={device.id} />}
        {activeTab === 'anomalies' && <AnomaliesList deviceId={device.id} />}
      </div>

      {/* Edit Modal */}
      {isEditing && (
        <EditDeviceForm device={device} onClose={() => setIsEditing(false)} />
      )}
    </div>
  );
}
