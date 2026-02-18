import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Clock,
  CheckCircle,
  XCircle,
  Play,
  Pause,
  AlertTriangle,
  Brain,
  Search,
  Shield,
  Target,
  Lightbulb,
  ThumbsUp,
  ThumbsDown,
  Zap,
} from 'lucide-react';
import {
  useInvestigation,
  useApproveInvestigationAction,
  useRejectInvestigationAction,
  useExecuteInvestigationActions,
  useRunInvestigation,
} from '../api/hooks';
import type { InvestigationStatus, InvestigationStepType, InvestigationActionStatus, InvestigationActionRiskLevel } from '../types';

const statusConfig: Record<InvestigationStatus, { icon: React.ReactNode; color: string; label: string }> = {
  pending: { icon: <Clock className="h-5 w-5" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Pending' },
  running: { icon: <Play className="h-5 w-5" />, color: 'text-blue-500 bg-blue-100 dark:bg-blue-900', label: 'Running' },
  awaiting_approval: { icon: <Pause className="h-5 w-5" />, color: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900', label: 'Awaiting Approval' },
  completed: { icon: <CheckCircle className="h-5 w-5" />, color: 'text-green-500 bg-green-100 dark:bg-green-900', label: 'Completed' },
  failed: { icon: <XCircle className="h-5 w-5" />, color: 'text-red-500 bg-red-100 dark:bg-red-900', label: 'Failed' },
  cancelled: { icon: <XCircle className="h-5 w-5" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Cancelled' },
};

const stepTypeIcons: Record<InvestigationStepType, React.ReactNode> = {
  gather_context: <Search className="h-5 w-5" />,
  correlate_events: <Target className="h-5 w-5" />,
  check_threat_intel: <Shield className="h-5 w-5" />,
  analyze_baseline: <Brain className="h-5 w-5" />,
  generate_hypothesis: <Lightbulb className="h-5 w-5" />,
  recommend_actions: <Zap className="h-5 w-5" />,
};

const stepTypeLabels: Record<InvestigationStepType, string> = {
  gather_context: 'Gather Context',
  correlate_events: 'Correlate Events',
  check_threat_intel: 'Check Threat Intel',
  analyze_baseline: 'Analyze Baseline',
  generate_hypothesis: 'Generate Hypothesis',
  recommend_actions: 'Recommend Actions',
};

const riskColors: Record<InvestigationActionRiskLevel, string> = {
  low: 'text-green-600 bg-green-100 dark:bg-green-900',
  medium: 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900',
  high: 'text-orange-600 bg-orange-100 dark:bg-orange-900',
  critical: 'text-red-600 bg-red-100 dark:bg-red-900',
};

const actionStatusColors: Record<InvestigationActionStatus, string> = {
  pending: 'text-gray-600 bg-gray-100 dark:bg-gray-700',
  approved: 'text-green-600 bg-green-100 dark:bg-green-900',
  rejected: 'text-red-600 bg-red-100 dark:bg-red-900',
  executed: 'text-blue-600 bg-blue-100 dark:bg-blue-900',
  failed: 'text-red-600 bg-red-100 dark:bg-red-900',
};

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: investigation, isLoading } = useInvestigation(id!);
  const approveAction = useApproveInvestigationAction();
  const rejectAction = useRejectInvestigationAction();
  const executeActions = useExecuteInvestigationActions();
  const runInvestigation = useRunInvestigation();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!investigation) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500 dark:text-gray-400">Investigation not found.</p>
        <Link to="/dashboard/investigations" className="text-blue-600 hover:text-blue-800 mt-2 inline-block">
          Back to Investigations
        </Link>
      </div>
    );
  }

  const config = statusConfig[investigation.status];
  const pendingActions = investigation.actions?.filter(a => a.status === 'pending') || [];
  const approvedActions = investigation.actions?.filter(a => a.status === 'approved') || [];

  const handleApprove = async (actionId: string) => {
    await approveAction.mutateAsync({ investigationId: id!, actionId });
  };

  const handleReject = async (actionId: string) => {
    const reason = prompt('Reason for rejection (optional):');
    await rejectAction.mutateAsync({ investigationId: id!, actionId, reason: reason || undefined });
  };

  const handleExecute = async () => {
    await executeActions.mutateAsync(id!);
  };

  const handleRun = async () => {
    await runInvestigation.mutateAsync(id!);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          to="/dashboard/investigations"
          className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
        >
          <ArrowLeft className="h-5 w-5 text-gray-500" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Investigation Details
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            ID: {investigation.id}
          </p>
        </div>
        <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium ${config.color}`}>
          {config.icon}
          {config.label}
        </span>
        {investigation.status === 'pending' && (
          <button
            onClick={handleRun}
            disabled={runInvestigation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            <Play className="h-4 w-4" />
            {runInvestigation.isPending ? 'Starting...' : 'Run Investigation'}
          </button>
        )}
      </div>

      {/* Summary */}
      {investigation.summary && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Summary</h2>
          <p className="text-gray-600 dark:text-gray-400">{investigation.summary}</p>
        </div>
      )}

      {/* Info Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Priority</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">P{investigation.priority}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Trigger</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white capitalize">{investigation.trigger_source}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Started</p>
          <p className="text-sm font-medium text-gray-900 dark:text-white">
            {investigation.started_at ? new Date(investigation.started_at).toLocaleString() : 'Not started'}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Completed</p>
          <p className="text-sm font-medium text-gray-900 dark:text-white">
            {investigation.completed_at ? new Date(investigation.completed_at).toLocaleString() : '-'}
          </p>
        </div>
      </div>

      {/* Investigation Steps Timeline */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Investigation Steps</h2>

        {investigation.steps && investigation.steps.length > 0 ? (
          <div className="space-y-4">
            {investigation.steps.map((step, index) => (
              <div key={step.id} className="relative">
                {index < investigation.steps!.length - 1 && (
                  <div className="absolute left-6 top-12 w-0.5 h-full bg-gray-200 dark:bg-gray-700" />
                )}
                <div className="flex gap-4">
                  <div className={`flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center ${
                    step.status === 'completed'
                      ? 'bg-green-100 dark:bg-green-900 text-green-600'
                      : step.status === 'running'
                      ? 'bg-blue-100 dark:bg-blue-900 text-blue-600'
                      : step.status === 'failed'
                      ? 'bg-red-100 dark:bg-red-900 text-red-600'
                      : 'bg-gray-100 dark:bg-gray-700 text-gray-500'
                  }`}>
                    {stepTypeIcons[step.step_type]}
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-medium text-gray-900 dark:text-white">
                        {stepTypeLabels[step.step_type]}
                      </h3>
                      <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                        {step.confidence_score != null && (
                          <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">
                            {Math.round(step.confidence_score * 100)}% confidence
                          </span>
                        )}
                        {step.duration_ms != null && (
                          <span>{(step.duration_ms / 1000).toFixed(1)}s</span>
                        )}
                      </div>
                    </div>

                    {/* Chain of Thought / Reasoning */}
                    {step.reasoning && (
                      <div className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg border-l-4 border-blue-500">
                        <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                          {step.reasoning}
                        </p>
                      </div>
                    )}

                    {/* Findings */}
                    {step.findings && Object.keys(step.findings).length > 0 && (
                      <div className="mt-2">
                        <details className="group">
                          <summary className="text-sm text-blue-600 dark:text-blue-400 cursor-pointer hover:underline">
                            View findings
                          </summary>
                          <pre className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 rounded text-xs overflow-x-auto">
                            {JSON.stringify(step.findings, null, 2)}
                          </pre>
                        </details>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 dark:text-gray-400 text-center py-8">
            No investigation steps yet. Run the investigation to begin analysis.
          </p>
        )}
      </div>

      {/* Pending Actions for Approval */}
      {pendingActions.length > 0 && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="h-5 w-5 text-yellow-600" />
            <h2 className="text-lg font-semibold text-yellow-800 dark:text-yellow-200">
              Actions Pending Approval
            </h2>
          </div>
          <div className="space-y-4">
            {pendingActions.map((action) => (
              <div key={action.id} className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-medium text-gray-900 dark:text-white capitalize">
                        {action.action_type.replace(/_/g, ' ')}
                      </h3>
                      <span className={`text-xs px-2 py-0.5 rounded ${riskColors[action.risk_level]}`}>
                        {action.risk_level} risk
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      {action.justification}
                    </p>
                    {action.action_params && (
                      <pre className="mt-2 text-xs bg-gray-50 dark:bg-gray-900 p-2 rounded overflow-x-auto">
                        {JSON.stringify(action.action_params, null, 2)}
                      </pre>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleApprove(action.id)}
                      disabled={approveAction.isPending}
                      className="flex items-center gap-1 px-3 py-1.5 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50"
                    >
                      <ThumbsUp className="h-4 w-4" />
                      Approve
                    </button>
                    <button
                      onClick={() => handleReject(action.id)}
                      disabled={rejectAction.isPending}
                      className="flex items-center gap-1 px-3 py-1.5 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
                    >
                      <ThumbsDown className="h-4 w-4" />
                      Reject
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Execute Approved Actions */}
      {approvedActions.length > 0 && (
        <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-600" />
              <h2 className="text-lg font-semibold text-green-800 dark:text-green-200">
                Approved Actions ({approvedActions.length})
              </h2>
            </div>
            <button
              onClick={handleExecute}
              disabled={executeActions.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50"
            >
              <Zap className="h-4 w-4" />
              {executeActions.isPending ? 'Executing...' : 'Execute All'}
            </button>
          </div>
          <div className="space-y-2">
            {approvedActions.map((action) => (
              <div key={action.id} className="flex items-center gap-3 bg-white dark:bg-gray-800 rounded p-3">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                  {action.action_type.replace(/_/g, ' ')}
                </span>
                <span className={`text-xs px-2 py-0.5 rounded ${riskColors[action.risk_level]}`}>
                  {action.risk_level}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Actions List */}
      {investigation.actions && investigation.actions.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">All Recommended Actions</h2>
          <div className="space-y-3">
            {investigation.actions.map((action) => (
              <div key={action.id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className={`text-xs px-2 py-1 rounded font-medium ${actionStatusColors[action.status]}`}>
                    {action.status}
                  </span>
                  <span className="font-medium text-gray-900 dark:text-white capitalize">
                    {action.action_type.replace(/_/g, ' ')}
                  </span>
                  <span className={`text-xs px-2 py-0.5 rounded ${riskColors[action.risk_level]}`}>
                    {action.risk_level}
                  </span>
                </div>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {new Date(action.created_at).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {investigation.recommendations && Object.keys(investigation.recommendations).length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recommendations</h2>
          <pre className="p-4 bg-gray-50 dark:bg-gray-900 rounded text-sm overflow-x-auto">
            {JSON.stringify(investigation.recommendations, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
