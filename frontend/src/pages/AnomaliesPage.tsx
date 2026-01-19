import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  Activity,
  RefreshCw,
  Filter,
  ExternalLink,
  CheckCircle,
  XCircle,
  Eye,
} from 'lucide-react';
import {
  useAnomalies,
  useAnomalyStats,
  useUpdateAnomalyStatus,
  useRunAllDevicesDetection,
} from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import Pagination from '../components/Pagination';
import clsx from 'clsx';
import type { AnomalyDetection, AnomalyStatus, AnomalyType } from '../types';

const PAGE_SIZE = 20;

const severityColors = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

const statusColors = {
  active: 'bg-red-100 text-red-700',
  reviewed: 'bg-blue-100 text-blue-700',
  false_positive: 'bg-gray-100 text-gray-700',
  confirmed: 'bg-green-100 text-green-700',
};

const anomalyTypeLabels: Record<AnomalyType, string> = {
  new_domain: 'New Domain',
  volume_spike: 'Volume Spike',
  time_anomaly: 'Time Anomaly',
  new_connection: 'New Connection',
  new_port: 'New Port',
  blocked_spike: 'Blocked Spike',
  pattern_change: 'Pattern Change',
};

function formatDate(dateString: string) {
  return new Date(dateString).toLocaleString();
}

export default function AnomaliesPage() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === 'admin';
  const isOperator = user?.role === 'admin' || user?.role === 'operator';

  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyDetection | null>(null);

  const { data: anomalies, isLoading, refetch } = useAnomalies({
    status: statusFilter || undefined,
    anomaly_type: typeFilter || undefined,
    severity: severityFilter || undefined,
    limit: PAGE_SIZE,
    offset: (page - 1) * PAGE_SIZE,
  });

  const { data: stats } = useAnomalyStats();
  const updateStatus = useUpdateAnomalyStatus();
  const runDetection = useRunAllDevicesDetection();

  const handleStatusUpdate = (anomalyId: string, status: AnomalyStatus) => {
    updateStatus.mutate({ anomalyId, status });
    setSelectedAnomaly(null);
  };

  const handleRunDetection = () => {
    if (confirm('Run anomaly detection for all devices with ready baselines?')) {
      runDetection.mutate({});
    }
  };

  const totalPages = anomalies ? Math.ceil(anomalies.total / PAGE_SIZE) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Anomaly Detection</h1>
          <p className="text-gray-600 mt-1">
            Monitor behavioral anomalies detected across your network devices
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          {isAdmin && (
            <button
              onClick={handleRunDetection}
              disabled={runDetection.isPending}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:opacity-50"
            >
              <Activity className="h-4 w-4" />
              {runDetection.isPending ? 'Running...' : 'Run Detection'}
            </button>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-100 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-red-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.active}</p>
                <p className="text-sm text-gray-600">Active Anomalies</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-100 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">
                  {(stats.by_severity?.critical || 0) + (stats.by_severity?.high || 0)}
                </p>
                <p className="text-sm text-gray-600">High/Critical</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 rounded-lg">
                <CheckCircle className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">
                  {stats.by_status?.reviewed || 0}
                </p>
                <p className="text-sm text-gray-600">Reviewed</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gray-100 rounded-lg">
                <Activity className="h-5 w-5 text-gray-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
                <p className="text-sm text-gray-600">Total Anomalies</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg border border-gray-200 p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">Filters:</span>
          </div>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1.5"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="reviewed">Reviewed</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False Positive</option>
          </select>
          <select
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value);
              setPage(1);
            }}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1.5"
          >
            <option value="">All Types</option>
            <option value="new_domain">New Domain</option>
            <option value="volume_spike">Volume Spike</option>
            <option value="time_anomaly">Time Anomaly</option>
            <option value="new_connection">New Connection</option>
            <option value="new_port">New Port</option>
            <option value="blocked_spike">Blocked Spike</option>
            <option value="pattern_change">Pattern Change</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1.5"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {/* Anomalies List */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading anomalies...</div>
        ) : !anomalies?.items.length ? (
          <div className="p-8 text-center text-gray-500">
            <AlertTriangle className="h-12 w-12 mx-auto mb-3 text-gray-300" />
            <p>No anomalies found</p>
            <p className="text-sm mt-1">
              {statusFilter || typeFilter || severityFilter
                ? 'Try adjusting your filters'
                : 'Anomalies will appear here when detected'}
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Anomaly
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Device
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Detected
                    </th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {anomalies.items.map((anomaly) => (
                    <tr key={anomaly.id} className="hover:bg-gray-50">
                      <td className="px-4 py-4">
                        <div className="flex items-start gap-3">
                          <AlertTriangle
                            className={clsx(
                              'h-5 w-5 mt-0.5',
                              anomaly.severity === 'critical'
                                ? 'text-red-500'
                                : anomaly.severity === 'high'
                                ? 'text-orange-500'
                                : anomaly.severity === 'medium'
                                ? 'text-yellow-500'
                                : 'text-gray-400'
                            )}
                          />
                          <div>
                            <p className="text-sm font-medium text-gray-900">
                              {anomalyTypeLabels[anomaly.anomaly_type]}
                            </p>
                            <p className="text-sm text-gray-500 mt-0.5 line-clamp-2">
                              {anomaly.description}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <Link
                          to={`/devices/${anomaly.device_id}`}
                          className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                        >
                          View Device
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </td>
                      <td className="px-4 py-4">
                        <span
                          className={clsx(
                            'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border',
                            severityColors[anomaly.severity]
                          )}
                        >
                          {anomaly.severity}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <span
                          className={clsx(
                            'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium',
                            statusColors[anomaly.status]
                          )}
                        >
                          {anomaly.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-sm text-gray-500">
                        {formatDate(anomaly.detected_at)}
                      </td>
                      <td className="px-4 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => setSelectedAnomaly(anomaly)}
                            className="p-1.5 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded"
                            title="View Details"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                          {isOperator && anomaly.status === 'active' && (
                            <>
                              <button
                                onClick={() => handleStatusUpdate(anomaly.id, 'reviewed')}
                                className="p-1.5 text-blue-500 hover:text-blue-700 hover:bg-blue-50 rounded"
                                title="Mark Reviewed"
                              >
                                <CheckCircle className="h-4 w-4" />
                              </button>
                              <button
                                onClick={() => handleStatusUpdate(anomaly.id, 'false_positive')}
                                className="p-1.5 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded"
                                title="Mark False Positive"
                              >
                                <XCircle className="h-4 w-4" />
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              onPageChange={setPage}
              totalItems={anomalies.total}
              pageSize={PAGE_SIZE}
            />
          </>
        )}
      </div>

      {/* Detail Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-lg font-semibold text-gray-900">
                    {anomalyTypeLabels[selectedAnomaly.anomaly_type]}
                  </h2>
                  <p className="text-sm text-gray-500 mt-1">
                    Detected {formatDate(selectedAnomaly.detected_at)}
                  </p>
                </div>
                <button
                  onClick={() => setSelectedAnomaly(null)}
                  className="p-2 text-gray-400 hover:text-gray-600"
                >
                  <XCircle className="h-5 w-5" />
                </button>
              </div>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-1">Description</h3>
                <p className="text-sm text-gray-900">{selectedAnomaly.description}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-1">Severity</h3>
                  <span
                    className={clsx(
                      'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border',
                      severityColors[selectedAnomaly.severity]
                    )}
                  >
                    {selectedAnomaly.severity}
                  </span>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-1">Score</h3>
                  <p className="text-sm text-gray-900">{selectedAnomaly.score.toFixed(2)}</p>
                </div>
              </div>
              {Object.keys(selectedAnomaly.details).length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-1">Details</h3>
                  <pre className="text-xs bg-gray-50 p-3 rounded-lg overflow-x-auto">
                    {JSON.stringify(selectedAnomaly.details, null, 2)}
                  </pre>
                </div>
              )}
              {Object.keys(selectedAnomaly.baseline_comparison).length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-1">Baseline Comparison</h3>
                  <pre className="text-xs bg-gray-50 p-3 rounded-lg overflow-x-auto">
                    {JSON.stringify(selectedAnomaly.baseline_comparison, null, 2)}
                  </pre>
                </div>
              )}
              {selectedAnomaly.alert_id && (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-1">Related Alert</h3>
                  <Link
                    to={`/alerts?id=${selectedAnomaly.alert_id}`}
                    className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
                  >
                    View Alert <ExternalLink className="h-3 w-3" />
                  </Link>
                </div>
              )}
            </div>
            {isOperator && selectedAnomaly.status === 'active' && (
              <div className="p-6 border-t border-gray-200 flex justify-end gap-2">
                <button
                  onClick={() => handleStatusUpdate(selectedAnomaly.id, 'false_positive')}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  False Positive
                </button>
                <button
                  onClick={() => handleStatusUpdate(selectedAnomaly.id, 'confirmed')}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
                >
                  Confirm Threat
                </button>
                <button
                  onClick={() => handleStatusUpdate(selectedAnomaly.id, 'reviewed')}
                  className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700"
                >
                  Mark Reviewed
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
