import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ShieldOff,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Monitor,
  Wifi,
  Server,
  History,
  Sync,
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import {
  useQuarantinedDevices,
  useReleaseDevice,
  useSyncQuarantine,
  useIntegrationsStatus,
  useQuarantineHistory,
  useAuditStats,
  type QuarantinedDevice,
  type AuditLog,
} from '../api/hooks';
import { useAuthStore } from '../stores/auth';

function IntegrationStatusCard({
  name,
  type,
  enabled,
  configured,
  icon: Icon,
}: {
  name: string;
  type: string;
  enabled: boolean;
  configured: boolean;
  icon: React.ElementType;
}) {
  const statusColor = enabled && configured ? 'text-success-600' : configured ? 'text-warning-600' : 'text-gray-400';
  const bgColor = enabled && configured ? 'bg-success-50' : configured ? 'bg-warning-50' : 'bg-gray-50';

  return (
    <div className={clsx('card p-4', bgColor)}>
      <div className="flex items-center gap-3">
        <div className={clsx('p-2 rounded-lg', enabled && configured ? 'bg-success-100' : 'bg-gray-100')}>
          <Icon className={clsx('w-5 h-5', statusColor)} />
        </div>
        <div className="flex-1">
          <div className="font-medium text-gray-900">{name}</div>
          <div className="text-xs text-gray-500 capitalize">{type}</div>
        </div>
        <div className="text-right">
          {enabled && configured ? (
            <span className="inline-flex items-center gap-1 text-success-700 text-sm">
              <CheckCircle className="w-4 h-4" />
              Active
            </span>
          ) : configured ? (
            <span className="inline-flex items-center gap-1 text-warning-700 text-sm">
              <AlertTriangle className="w-4 h-4" />
              Disabled
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-gray-500 text-sm">
              <XCircle className="w-4 h-4" />
              Not configured
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function QuarantinedDeviceRow({
  device,
  onRelease,
  isReleasing,
}: {
  device: QuarantinedDevice;
  onRelease: (deviceId: string) => void;
  isReleasing: boolean;
}) {
  const user = useAuthStore((state) => state.user);
  const canManage = user?.role === 'admin' || user?.role === 'operator';

  return (
    <tr className="hover:bg-gray-50">
      <td className="px-6 py-4 whitespace-nowrap">
        <Link to={`/devices/${device.device_id}`} className="flex items-center gap-3">
          <div className="flex-shrink-0 w-10 h-10 bg-danger-100 rounded-lg flex items-center justify-center">
            <Monitor className="w-5 h-5 text-danger-500" />
          </div>
          <div>
            <div className="text-sm font-medium text-gray-900 hover:text-primary-600">
              {device.hostname || 'Unknown'}
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
        <div className="flex items-center gap-2">
          {device.adguard_blocked ? (
            <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-success-700 bg-success-50 rounded">
              <CheckCircle className="w-3 h-3" />
              Blocked
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-warning-700 bg-warning-50 rounded">
              <AlertTriangle className="w-3 h-3" />
              Not synced
            </span>
          )}
        </div>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <div className="flex items-center gap-2">
          {device.router_type ? (
            device.router_blocked ? (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-success-700 bg-success-50 rounded">
                <CheckCircle className="w-3 h-3" />
                Blocked ({device.router_type})
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-warning-700 bg-warning-50 rounded">
                <AlertTriangle className="w-3 h-3" />
                Not synced
              </span>
            )
          ) : (
            <span className="text-xs text-gray-400">No router</span>
          )}
        </div>
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
        {canManage && (
          <button
            onClick={() => onRelease(device.device_id)}
            disabled={isReleasing}
            className="inline-flex items-center gap-1 px-3 py-1.5 text-sm font-medium text-success-700 bg-success-50 rounded hover:bg-success-100 transition-colors disabled:opacity-50"
          >
            <Shield className="w-4 h-4" />
            Release
          </button>
        )}
      </td>
    </tr>
  );
}

function ActivityLogRow({ log }: { log: AuditLog }) {
  const isQuarantine = log.action === 'device_quarantine';

  return (
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="text-xs text-gray-500">
          {format(new Date(log.timestamp), 'MMM d, HH:mm')}
        </div>
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        <span
          className={clsx(
            'inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded',
            isQuarantine ? 'text-danger-700 bg-danger-50' : 'text-success-700 bg-success-50'
          )}
        >
          {isQuarantine ? (
            <ShieldOff className="w-3 h-3" />
          ) : (
            <Shield className="w-3 h-3" />
          )}
          {isQuarantine ? 'Quarantined' : 'Released'}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="text-sm text-gray-900">{log.target_name || 'Unknown device'}</div>
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="text-sm text-gray-500">{log.username || 'System'}</div>
      </td>
    </tr>
  );
}

export default function QuarantinePage() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';

  const { data: quarantinedDevices, isLoading, refetch, isFetching } = useQuarantinedDevices();
  const { data: integrationsStatus } = useIntegrationsStatus();
  const { data: auditStats } = useAuditStats();
  const { data: recentActivity } = useQuarantineHistory(24, 10);

  const release = useReleaseDevice();
  const syncQuarantine = useSyncQuarantine();

  const handleRelease = (deviceId: string) => {
    if (confirm('Release this device from quarantine?')) {
      release.mutate(deviceId);
    }
  };

  const handleSync = () => {
    syncQuarantine.mutate();
  };

  const adguard = integrationsStatus?.integrations.find((i) => i.type === 'adguard_home');
  const router = integrationsStatus?.integrations.find((i) => i.type !== 'adguard_home' && i.type !== 'none');

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Quarantine Management</h1>
          <p className="text-gray-500">
            Manage quarantined devices and integration status
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isAdmin && (
            <button
              onClick={handleSync}
              disabled={syncQuarantine.isPending}
              className="btn-secondary"
            >
              <Sync className={clsx('w-4 h-4 mr-2', syncQuarantine.isPending && 'animate-spin')} />
              Sync Status
            </button>
          )}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary"
          >
            <RefreshCw className={clsx('w-4 h-4 mr-2', isFetching && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-danger-100 rounded-lg">
              <ShieldOff className="w-5 h-5 text-danger-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-gray-900">
                {quarantinedDevices?.length || 0}
              </div>
              <div className="text-xs text-gray-500">Quarantined Devices</div>
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary-100 rounded-lg">
              <ShieldOff className="w-5 h-5 text-primary-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-gray-900">
                {auditStats?.quarantines_24h || 0}
              </div>
              <div className="text-xs text-gray-500">Quarantines (24h)</div>
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-success-100 rounded-lg">
              <Shield className="w-5 h-5 text-success-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-gray-900">
                {auditStats?.releases_24h || 0}
              </div>
              <div className="text-xs text-gray-500">Releases (24h)</div>
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-100 rounded-lg">
              <History className="w-5 h-5 text-gray-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-gray-900">
                {(auditStats?.quarantines_24h || 0) + (auditStats?.releases_24h || 0)}
              </div>
              <div className="text-xs text-gray-500">Total Actions (24h)</div>
            </div>
          </div>
        </div>
      </div>

      {/* Integration Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <IntegrationStatusCard
          name={adguard?.name || 'AdGuard Home'}
          type={adguard?.type || 'adguard_home'}
          enabled={adguard?.enabled || false}
          configured={adguard?.configured || false}
          icon={Wifi}
        />
        <IntegrationStatusCard
          name={router?.name || 'Router'}
          type={router?.type || 'none'}
          enabled={router?.enabled || false}
          configured={router?.configured || false}
          icon={Server}
        />
      </div>

      {/* Sync Results */}
      {syncQuarantine.data && (
        <div
          className={clsx(
            'card p-4',
            syncQuarantine.data.errors.length > 0 ? 'bg-warning-50' : 'bg-success-50'
          )}
        >
          <div className="flex items-center gap-3">
            <Sync className="w-5 h-5 text-gray-600" />
            <div>
              <div className="font-medium">Sync Complete</div>
              <div className="text-sm text-gray-600">
                Checked {syncQuarantine.data.checked} devices, synced {syncQuarantine.data.synced}
                {syncQuarantine.data.errors.length > 0 && (
                  <span className="text-warning-700">
                    {' '}
                    ({syncQuarantine.data.errors.length} errors)
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Quarantined Devices Table */}
        <div className="lg:col-span-2 card overflow-hidden">
          <div className="p-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Quarantined Devices</h2>
          </div>
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
                    AdGuard
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Router
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {isLoading ? (
                  [...Array(3)].map((_, i) => (
                    <tr key={i}>
                      <td colSpan={5} className="px-6 py-4">
                        <div className="animate-pulse h-10 bg-gray-100 rounded" />
                      </td>
                    </tr>
                  ))
                ) : quarantinedDevices && quarantinedDevices.length > 0 ? (
                  quarantinedDevices.map((device) => (
                    <QuarantinedDeviceRow
                      key={device.device_id}
                      device={device}
                      onRelease={handleRelease}
                      isReleasing={release.isPending}
                    />
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <Shield className="w-12 h-12 text-success-300 mx-auto mb-3" />
                      <div className="text-gray-500">No devices are currently quarantined</div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="card overflow-hidden">
          <div className="p-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Recent Activity</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Time
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Action
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Device
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    User
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {recentActivity?.items && recentActivity.items.length > 0 ? (
                  recentActivity.items.map((log) => (
                    <ActivityLogRow key={log.id} log={log} />
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-gray-500 text-sm">
                      No recent activity
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="p-3 border-t border-gray-200 text-center">
            <Link to="/audit" className="text-sm text-primary-600 hover:text-primary-700">
              View all audit logs
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
