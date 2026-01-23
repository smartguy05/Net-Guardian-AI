import { useState } from 'react';
import { format } from 'date-fns';
import {
  Check,
  CheckCircle2,
  Clock,
  Filter,
  Lightbulb,
  RefreshCw,
  Shield,
  X,
  XCircle,
} from 'lucide-react';
import clsx from 'clsx';
import {
  usePendingSuggestedRules,
  useSuggestedRules,
  useApproveRule,
  useRejectRule,
  useSources,
} from '../api/hooks';
import Pagination from '../components/Pagination';
import type { SuggestedRule, SuggestedRuleStatus } from '../types';

export default function SuggestedRulesPage() {
  const [activeTab, setActiveTab] = useState<'pending' | 'history'>('pending');
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [selectedRule, setSelectedRule] = useState<SuggestedRule | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [enableOnApprove, setEnableOnApprove] = useState(false);

  const { data: sources } = useSources();
  const { data: pendingRules, isLoading: pendingLoading, refetch: refetchPending } =
    usePendingSuggestedRules({
      page,
      page_size: pageSize,
    });
  const { data: allRules, isLoading: allLoading, refetch: refetchAll } = useSuggestedRules({
    source_id: sourceFilter || undefined,
    status: statusFilter || undefined,
    page,
    page_size: pageSize,
  });

  const approveRule = useApproveRule();
  const rejectRule = useRejectRule();

  const rules = activeTab === 'pending' ? pendingRules : allRules;
  const isLoading = activeTab === 'pending' ? pendingLoading : allLoading;
  const refetch = activeTab === 'pending' ? refetchPending : refetchAll;

  const handleApprove = async (rule: SuggestedRule) => {
    await approveRule.mutateAsync({
      ruleId: rule.id,
      request: { enable: enableOnApprove },
    });
    setSelectedRule(null);
    setEnableOnApprove(false);
  };

  const handleReject = async (rule: SuggestedRule) => {
    if (!rejectReason.trim()) return;
    await rejectRule.mutateAsync({
      ruleId: rule.id,
      request: { reason: rejectReason },
    });
    setSelectedRule(null);
    setRejectReason('');
  };

  const getStatusIcon = (status: SuggestedRuleStatus) => {
    switch (status) {
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'approved':
        return <Check className="h-4 w-4 text-blue-500" />;
      case 'implemented':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case 'rejected':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };

  const getStatusLabel = (status: SuggestedRuleStatus) => {
    switch (status) {
      case 'pending':
        return 'Pending Review';
      case 'approved':
        return 'Approved';
      case 'implemented':
        return 'Implemented';
      case 'rejected':
        return 'Rejected';
      default:
        return status;
    }
  };

  const getRuleTypeLabel = (type: string) => {
    switch (type) {
      case 'pattern_match':
        return 'Pattern Match';
      case 'threshold':
        return 'Threshold';
      case 'sequence':
        return 'Sequence';
      default:
        return type;
    }
  };

  const totalPages = rules ? Math.ceil(rules.total / pageSize) : 0;
  const pendingCount = pendingRules?.total ?? 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Suggested Rules
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Review and approve AI-suggested detection rules
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="btn btn-secondary flex items-center gap-2"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-zinc-700">
        <nav className="flex gap-4">
          <button
            onClick={() => {
              setActiveTab('pending');
              setPage(1);
            }}
            className={clsx(
              'py-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'pending'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            Pending Review
            {pendingCount > 0 && (
              <span className="ml-2 bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300 px-2 py-0.5 rounded-full text-xs">
                {pendingCount}
              </span>
            )}
          </button>
          <button
            onClick={() => {
              setActiveTab('history');
              setPage(1);
            }}
            className={clsx(
              'py-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'history'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
            )}
          >
            All Rules
          </button>
        </nav>
      </div>

      {/* Filters (for history tab) */}
      {activeTab === 'history' && (
        <div className="card p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Filters:</span>
            </div>
            <select
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setPage(1);
              }}
              className="input px-3 py-1.5 text-sm"
            >
              <option value="">All Sources</option>
              {sources?.items.map((source) => (
                <option key={source.id} value={source.id}>
                  {source.name}
                </option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="input px-3 py-1.5 text-sm"
            >
              <option value="">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="implemented">Implemented</option>
              <option value="rejected">Rejected</option>
            </select>
          </div>
        </div>
      )}

      {/* Rules List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="card p-8 text-center text-gray-500 dark:text-gray-400">
            Loading suggested rules...
          </div>
        ) : rules?.items.length === 0 ? (
          <div className="card p-8 text-center text-gray-500 dark:text-gray-400">
            <Lightbulb className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p className="text-lg font-medium">
              {activeTab === 'pending'
                ? 'No pending rules to review'
                : 'No suggested rules found'}
            </p>
            <p className="text-sm mt-1">
              {activeTab === 'pending'
                ? 'New rules will appear after semantic analysis detects patterns'
                : 'Try adjusting your filters'}
            </p>
          </div>
        ) : (
          rules?.items.map((rule) => (
            <div
              key={rule.id}
              className={clsx(
                'card p-4 transition-all',
                selectedRule?.id === rule.id && 'ring-2 ring-primary-500'
              )}
            >
              <div className="flex flex-col lg:flex-row lg:items-start gap-4">
                {/* Rule Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
                      <Shield className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-semibold text-gray-900 dark:text-white">
                          {rule.name}
                        </h3>
                        <span
                          className={clsx(
                            'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium',
                            rule.status === 'pending' &&
                              'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
                            rule.status === 'approved' &&
                              'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
                            rule.status === 'implemented' &&
                              'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
                            rule.status === 'rejected' &&
                              'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                          )}
                        >
                          {getStatusIcon(rule.status)}
                          {getStatusLabel(rule.status)}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-zinc-800 text-gray-600 dark:text-gray-400">
                          {getRuleTypeLabel(rule.rule_type)}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                        {rule.description}
                      </p>

                      {/* Expandable Details */}
                      <div className="mt-3 space-y-2 text-sm">
                        <div>
                          <span className="font-medium text-gray-700 dark:text-gray-300">Why suggested:</span>
                          <p className="text-gray-600 dark:text-gray-400">{rule.reason}</p>
                        </div>
                        <div>
                          <span className="font-medium text-gray-700 dark:text-gray-300">Security benefit:</span>
                          <p className="text-gray-600 dark:text-gray-400">{rule.benefit}</p>
                        </div>
                        {rule.source_id && (
                          <div>
                            <span className="font-medium text-gray-700 dark:text-gray-300">Source:</span>
                            <span className="ml-2 text-gray-600 dark:text-gray-400">{rule.source_id}</span>
                          </div>
                        )}
                        <div>
                          <span className="font-medium text-gray-700 dark:text-gray-300">Created:</span>
                          <span className="ml-2 text-gray-600 dark:text-gray-400">
                            {format(new Date(rule.created_at), 'MMM d, yyyy HH:mm')}
                          </span>
                        </div>
                        {rule.rejection_reason && (
                          <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded">
                            <span className="font-medium text-red-700 dark:text-red-300">Rejection reason:</span>
                            <p className="text-red-600 dark:text-red-400">{rule.rejection_reason}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                {rule.status === 'pending' && (
                  <div className="flex lg:flex-col gap-2 lg:w-auto">
                    {selectedRule?.id === rule.id ? (
                      <div className="flex flex-col gap-2 w-full lg:w-64">
                        <label className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={enableOnApprove}
                            onChange={(e) => setEnableOnApprove(e.target.checked)}
                            className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="text-gray-700 dark:text-gray-300">Enable rule immediately</span>
                        </label>
                        <button
                          onClick={() => handleApprove(rule)}
                          disabled={approveRule.isPending}
                          className="btn btn-primary flex items-center justify-center gap-2"
                        >
                          <Check className="h-4 w-4" />
                          Approve
                        </button>
                        <div>
                          <textarea
                            value={rejectReason}
                            onChange={(e) => setRejectReason(e.target.value)}
                            placeholder="Rejection reason..."
                            className="input w-full text-sm"
                            rows={2}
                          />
                          <button
                            onClick={() => handleReject(rule)}
                            disabled={rejectRule.isPending || !rejectReason.trim()}
                            className="btn btn-danger w-full mt-2 flex items-center justify-center gap-2"
                          >
                            <X className="h-4 w-4" />
                            Reject
                          </button>
                        </div>
                        <button
                          onClick={() => {
                            setSelectedRule(null);
                            setRejectReason('');
                            setEnableOnApprove(false);
                          }}
                          className="btn btn-secondary"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setSelectedRule(rule)}
                        className="btn btn-primary flex items-center gap-2"
                      >
                        Review
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {rules && rules.total > pageSize && (
        <div className="flex justify-center">
          <Pagination
            currentPage={page}
            totalPages={totalPages}
            totalItems={rules.total}
            pageSize={pageSize}
            onPageChange={setPage}
          />
        </div>
      )}
    </div>
  );
}
