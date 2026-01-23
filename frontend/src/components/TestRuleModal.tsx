import { useState } from 'react';
import { X, Play, Loader2, CheckCircle, XCircle } from 'lucide-react';
import clsx from 'clsx';
import { useTestRule } from '../api/hooks';
import type { DetectionRule, TestRuleResponse } from '../types';

const SAMPLE_EVENTS = [
  {
    name: 'DNS Query Event',
    event: {
      event_type: 'dns',
      severity: 'info',
      domain: 'example.com',
      source_ip: '192.168.1.100',
      blocked: false,
      parser_type: 'adguard',
    },
  },
  {
    name: 'Blocked DNS Query',
    event: {
      event_type: 'dns',
      severity: 'warning',
      domain: 'malware.example.com',
      source_ip: '192.168.1.50',
      blocked: true,
      parser_type: 'adguard',
    },
  },
  {
    name: 'Firewall Event',
    event: {
      event_type: 'firewall',
      severity: 'warning',
      source_ip: '10.0.0.5',
      dest_ip: '8.8.8.8',
      port: 443,
      protocol: 'TCP',
      parser_type: 'pfsense',
    },
  },
  {
    name: 'Auth Failure',
    event: {
      event_type: 'auth',
      severity: 'error',
      source_ip: '192.168.1.200',
      raw_data: 'Failed login attempt for user admin',
      parser_type: 'syslog',
    },
  },
];

interface TestRuleModalProps {
  rule: DetectionRule;
  onClose: () => void;
}

export default function TestRuleModal({ rule, onClose }: TestRuleModalProps) {
  const [eventJson, setEventJson] = useState(
    JSON.stringify(SAMPLE_EVENTS[0].event, null, 2)
  );
  const [result, setResult] = useState<TestRuleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const testRule = useTestRule();

  const loadSample = (sample: typeof SAMPLE_EVENTS[0]) => {
    setEventJson(JSON.stringify(sample.event, null, 2));
    setResult(null);
    setError(null);
  };

  // Check if conditions are in the new structured format
  const isNewConditionsFormat = (conditions: unknown): conditions is { logic: string; conditions: Array<{ field: string; operator: string; value: unknown }> } => {
    if (!conditions || typeof conditions !== 'object') return false;
    const cond = conditions as Record<string, unknown>;
    return Array.isArray(cond.conditions) && typeof cond.logic === 'string';
  };

  const handleTest = async () => {
    setError(null);
    setResult(null);

    try {
      const event = JSON.parse(eventJson);

      // Check if rule uses the new structured conditions format
      if (!isNewConditionsFormat(rule.conditions)) {
        setError(
          'This rule uses a legacy conditions format. Please edit the rule to update its conditions before testing.'
        );
        return;
      }

      // Get raw conditions from rule
      const rawConditions = rule.conditions.conditions || [];

      // Filter out invalid conditions and validate each one
      const validConditions = rawConditions.filter(
        (c) => c.field && c.field.trim() !== '' && c.operator && c.operator.trim() !== ''
      );

      if (validConditions.length === 0) {
        setError('Rule has no valid conditions to test. Each condition needs a field and operator.');
        return;
      }

      // Ensure each condition has the required structure
      const sanitizedConditions = validConditions.map((c) => ({
        field: c.field.trim(),
        operator: c.operator.trim(),
        value: c.value ?? '',
      }));

      const conditions = {
        logic: rule.conditions.logic || 'and',
        conditions: sanitizedConditions,
      };

      const response = await testRule.mutateAsync({
        conditions,
        event,
      });
      setResult(response);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError('Invalid JSON format');
      } else if (err instanceof Error) {
        // Extract more helpful error message from API response
        const message = err.message || 'Failed to test rule';
        setError(message.includes('422') ? 'Invalid rule conditions. Please check the rule configuration.' : message);
      } else {
        setError('Failed to test rule');
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50 dark:bg-black/70" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative w-full max-w-2xl bg-white dark:bg-zinc-800 rounded-xl shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Test Rule
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {rule.name}
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-4 space-y-4">
            {/* Sample Events */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Load Sample Event
              </label>
              <div className="flex flex-wrap gap-2">
                {SAMPLE_EVENTS.map((sample, idx) => (
                  <button
                    key={idx}
                    onClick={() => loadSample(sample)}
                    className="px-3 py-1 text-xs font-medium bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-zinc-600"
                  >
                    {sample.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Event JSON */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Event Data (JSON)
              </label>
              <textarea
                value={eventJson}
                onChange={(e) => {
                  setEventJson(e.target.value);
                  setResult(null);
                  setError(null);
                }}
                className="input w-full font-mono text-sm"
                rows={8}
                placeholder='{"event_type": "dns", "domain": "example.com"}'
              />
            </div>

            {/* Rule Conditions Preview */}
            <div className="p-3 bg-gray-50 dark:bg-zinc-700/50 rounded-lg">
              <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">
                Rule Conditions {isNewConditionsFormat(rule.conditions) ? `(${rule.conditions.logic.toUpperCase()})` : '(Legacy Format)'}
              </h4>
              <div className="space-y-1">
                {isNewConditionsFormat(rule.conditions) ? (
                  rule.conditions.conditions.map((cond, idx) => (
                    <div key={idx} className="text-sm">
                      <code className="text-primary-600 dark:text-primary-400">{cond.field}</code>
                      <span className="text-gray-500 dark:text-gray-400 mx-2">{cond.operator}</span>
                      <code className="text-gray-900 dark:text-white">
                        {typeof cond.value === 'object' ? JSON.stringify(cond.value) : String(cond.value)}
                      </code>
                    </div>
                  ))
                ) : (
                  <div className="text-sm text-warning-600 dark:text-warning-400">
                    <p>This rule uses a legacy conditions format:</p>
                    <pre className="mt-1 p-2 bg-gray-100 dark:bg-zinc-800 rounded text-xs overflow-auto">
                      {JSON.stringify(rule.conditions, null, 2)}
                    </pre>
                    <p className="mt-2 text-gray-600 dark:text-gray-400">
                      Edit the rule to convert to the new format for testing.
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="p-3 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
                <div className="flex items-center gap-2 text-danger-700 dark:text-danger-300">
                  <XCircle className="w-4 h-4" />
                  <span className="text-sm font-medium">{error}</span>
                </div>
              </div>
            )}

            {/* Result */}
            {result && (
              <div
                className={clsx(
                  'p-4 rounded-lg border',
                  result.matches
                    ? 'bg-success-50 dark:bg-success-900/20 border-success-200 dark:border-success-800'
                    : 'bg-gray-50 dark:bg-zinc-700/50 border-gray-200 dark:border-zinc-600'
                )}
              >
                <div className="flex items-center gap-2 mb-3">
                  {result.matches ? (
                    <CheckCircle className="w-5 h-5 text-success-600 dark:text-success-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-gray-400 dark:text-gray-500" />
                  )}
                  <span
                    className={clsx(
                      'font-medium',
                      result.matches
                        ? 'text-success-700 dark:text-success-300'
                        : 'text-gray-700 dark:text-gray-300'
                    )}
                  >
                    {result.matches ? 'Rule would trigger!' : 'Rule would not trigger'}
                  </span>
                </div>

                <div className="space-y-2">
                  <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Condition Results
                  </h4>
                  {result.condition_results.map((cr, idx) => (
                    <div
                      key={idx}
                      className={clsx(
                        'flex items-center justify-between p-2 rounded text-sm',
                        cr.result
                          ? 'bg-success-100 dark:bg-success-900/30'
                          : 'bg-gray-100 dark:bg-zinc-600/50'
                      )}
                    >
                      <div className="flex items-center gap-2">
                        {cr.result ? (
                          <CheckCircle className="w-4 h-4 text-success-600 dark:text-success-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-gray-400" />
                        )}
                        <span>
                          <code className="text-primary-600 dark:text-primary-400">{cr.field}</code>
                          <span className="text-gray-500 dark:text-gray-400 mx-1">{cr.operator}</span>
                          <code>{String(cr.expected)}</code>
                        </span>
                      </div>
                      <div className="text-gray-500 dark:text-gray-400">
                        actual: <code className="text-gray-900 dark:text-white">{cr.actual === null ? 'null' : String(cr.actual)}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 p-4 border-t border-gray-200 dark:border-zinc-700">
            <button onClick={onClose} className="btn-secondary">
              Close
            </button>
            <button
              onClick={handleTest}
              disabled={testRule.isPending || !eventJson.trim()}
              className="btn-primary disabled:opacity-50 inline-flex items-center gap-2"
            >
              {testRule.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              Test Rule
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
