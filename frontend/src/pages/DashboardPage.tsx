import {
  Monitor,
  Activity,
  ShieldAlert,
  Database,
  TrendingUp,
  AlertTriangle,
} from 'lucide-react';
import { useOverviewStats, useTopDomains, useAlerts } from '../api/hooks';
import clsx from 'clsx';

function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  color = 'primary',
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  trend?: string;
  color?: 'primary' | 'success' | 'warning' | 'danger';
}) {
  const colorClasses = {
    primary: 'bg-primary-50 text-primary-600',
    success: 'bg-success-50 text-success-600',
    warning: 'bg-warning-50 text-warning-600',
    danger: 'bg-danger-50 text-danger-600',
  };

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="mt-1 text-2xl font-semibold text-gray-900">{value}</p>
          {trend && (
            <p className="mt-1 text-xs text-gray-500 flex items-center gap-1">
              <TrendingUp className="w-3 h-3" />
              {trend}
            </p>
          )}
        </div>
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

function TopDomainsTable() {
  const { data: domains, isLoading } = useTopDomains(24, 10);

  if (isLoading) {
    return (
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Top Queried Domains
        </h3>
        <div className="animate-pulse space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-8 bg-gray-100 rounded" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="card p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">
        Top Queried Domains (24h)
      </h3>
      <div className="space-y-3">
        {domains?.map((domain, index) => (
          <div key={domain.domain} className="flex items-center gap-3">
            <span className="w-6 text-sm text-gray-400 text-right">
              {index + 1}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-gray-900 truncate">
                  {domain.domain}
                </span>
                <span className="text-sm text-gray-500">
                  {domain.count.toLocaleString()}
                </span>
              </div>
              <div className="mt-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary-500 rounded-full"
                  style={{
                    width: `${(domain.count / (domains[0]?.count || 1)) * 100}%`,
                  }}
                />
              </div>
            </div>
          </div>
        ))}
        {(!domains || domains.length === 0) && (
          <p className="text-sm text-gray-500 text-center py-4">
            No DNS queries recorded yet
          </p>
        )}
      </div>
    </div>
  );
}

function RecentAlerts() {
  const { data, isLoading } = useAlerts({ limit: 5 });

  const severityColors = {
    critical: 'badge-danger',
    high: 'badge-danger',
    medium: 'badge-warning',
    low: 'badge-info',
  };

  if (isLoading) {
    return (
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Recent Alerts
        </h3>
        <div className="animate-pulse space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-16 bg-gray-100 rounded" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="card p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Alerts</h3>
      <div className="space-y-3">
        {data?.items.map((alert) => (
          <div
            key={alert.id}
            className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg"
          >
            <AlertTriangle className="w-5 h-5 text-warning-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-900 truncate">
                  {alert.title}
                </span>
                <span
                  className={
                    severityColors[alert.severity as keyof typeof severityColors]
                  }
                >
                  {alert.severity}
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-0.5 truncate">
                {alert.description}
              </p>
            </div>
          </div>
        ))}
        {(!data?.items || data.items.length === 0) && (
          <p className="text-sm text-gray-500 text-center py-4">
            No alerts to display
          </p>
        )}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { data: stats, isLoading } = useOverviewStats();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-500">Network security overview</p>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Active Devices"
          value={isLoading ? '...' : stats?.active_devices || 0}
          icon={Monitor}
          trend={`${stats?.device_count || 0} total`}
          color="primary"
        />
        <StatCard
          title="Events (24h)"
          value={isLoading ? '...' : stats?.total_events_24h.toLocaleString() || 0}
          icon={Activity}
          trend={`${stats?.dns_queries_24h.toLocaleString() || 0} DNS queries`}
          color="success"
        />
        <StatCard
          title="Active Alerts"
          value={isLoading ? '...' : stats?.active_alerts || 0}
          icon={ShieldAlert}
          trend={`${stats?.critical_alerts || 0} critical`}
          color={stats?.critical_alerts ? 'danger' : 'warning'}
        />
        <StatCard
          title="Log Sources"
          value={isLoading ? '...' : stats?.source_count || 0}
          icon={Database}
          trend="Active sources"
          color="primary"
        />
      </div>

      {/* Block rate */}
      {stats && stats.dns_queries_24h > 0 && (
        <div className="card p-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">
              DNS Block Rate (24h)
            </span>
            <span className="text-lg font-semibold text-gray-900">
              {stats.block_rate}%
            </span>
          </div>
          <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
            <div
              className="h-full bg-warning-500 rounded-full transition-all"
              style={{ width: `${stats.block_rate}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            {stats.blocked_queries_24h.toLocaleString()} blocked out of{' '}
            {stats.dns_queries_24h.toLocaleString()} queries
          </p>
        </div>
      )}

      {/* Two column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopDomainsTable />
        <RecentAlerts />
      </div>
    </div>
  );
}
