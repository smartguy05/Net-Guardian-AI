import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Skull,
  Globe,
  Clock,
  Activity,
  Brain,
  Shield,
  AlertTriangle,
  Target,
} from 'lucide-react';
import { useAttackers, useAttacker } from '../api/hooks';
import type { SophisticationLevel } from '../types';

const sophisticationColors: Record<SophisticationLevel, string> = {
  script_kiddie: 'text-green-600 bg-green-100 dark:bg-green-900',
  intermediate: 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900',
  advanced: 'text-orange-600 bg-orange-100 dark:bg-orange-900',
  apt: 'text-red-600 bg-red-100 dark:bg-red-900',
};

const sophisticationLabels: Record<SophisticationLevel, string> = {
  script_kiddie: 'Script Kiddie',
  intermediate: 'Intermediate',
  advanced: 'Advanced',
  apt: 'APT',
};

export default function AttackersPage() {
  const [searchParams] = useSearchParams();
  const initialIp = searchParams.get('ip');
  const [selectedIp, setSelectedIp] = useState<string | null>(initialIp);

  const { data: attackers, isLoading } = useAttackers({ limit: 50 });
  const { data: selectedProfile } = useAttacker(selectedIp || '');

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Attacker Profiles</h1>
        <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <Skull className="h-4 w-4" />
          <span>{attackers?.items?.length || 0} known attackers</span>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {(['script_kiddie', 'intermediate', 'advanced', 'apt'] as SophisticationLevel[]).map((level) => {
          const count = attackers?.items?.filter(a => a.sophistication_level === level).length || 0;
          return (
            <div key={level} className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${sophisticationColors[level]}`}>
                  {sophisticationLabels[level]}
                </span>
              </div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white mt-2">{count}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attackers List */}
        <div className="lg:col-span-1 bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <h2 className="font-semibold text-gray-900 dark:text-white">Attackers</h2>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700 max-h-[600px] overflow-y-auto">
            {attackers && attackers.items && attackers.items.length > 0 ? (
              attackers.items.map((attacker) => (
                <button
                  key={attacker.source_ip}
                  onClick={() => {
                    setSelectedIp(attacker.source_ip);
                  }}
                  className={`w-full p-4 text-left hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors ${
                    selectedIp === attacker.source_ip ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg">
                        <Skull className="h-5 w-5 text-red-500" />
                      </div>
                      <div>
                        <p className="font-mono text-sm font-medium text-gray-900 dark:text-white">
                          {attacker.source_ip}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {attacker.total_interactions} interactions
                        </p>
                      </div>
                    </div>
                    {attacker.sophistication_level && (
                      <span className={`text-xs px-2 py-0.5 rounded ${sophisticationColors[attacker.sophistication_level]}`}>
                        {sophisticationLabels[attacker.sophistication_level]}
                      </span>
                    )}
                  </div>
                </button>
              ))
            ) : (
              <div className="text-center py-12">
                <Target className="h-12 w-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                <p className="text-gray-500 dark:text-gray-400">No attackers detected yet.</p>
              </div>
            )}
          </div>
        </div>

        {/* Profile Detail */}
        <div className="lg:col-span-2 space-y-4">
          {selectedProfile ? (
            <>
              {/* Profile Header */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-red-100 dark:bg-red-900 rounded-lg">
                      <Skull className="h-8 w-8 text-red-600" />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-gray-900 dark:text-white font-mono">
                        {selectedProfile.source_ip}
                      </h2>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        First seen: {new Date(selectedProfile.first_seen).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  {selectedProfile.sophistication_level && (
                    <span className={`px-3 py-1.5 rounded-full text-sm font-medium ${sophisticationColors[selectedProfile.sophistication_level]}`}>
                      {sophisticationLabels[selectedProfile.sophistication_level]}
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                    <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                      <Activity className="h-4 w-4" />
                      <span>Interactions</span>
                    </div>
                    <p className="text-xl font-bold text-gray-900 dark:text-white mt-1">
                      {selectedProfile.total_interactions}
                    </p>
                  </div>
                  <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                    <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                      <Clock className="h-4 w-4" />
                      <span>Last Seen</span>
                    </div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white mt-1">
                      {new Date(selectedProfile.last_seen).toLocaleString()}
                    </p>
                  </div>
                  <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                    <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                      <AlertTriangle className="h-4 w-4" />
                      <span>Likely Intent</span>
                    </div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white mt-1 capitalize">
                      {selectedProfile.likely_intent || 'Unknown'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Attack Patterns */}
              {selectedProfile.attack_patterns && Object.keys(selectedProfile.attack_patterns).length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                    <Shield className="h-5 w-5 text-orange-500" />
                    Attack Patterns
                  </h3>
                  <div className="space-y-3">
                    {Object.entries(selectedProfile.attack_patterns).map(([pattern, count]) => (
                      <div key={pattern} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900 rounded">
                        <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                          {pattern.replace(/_/g, ' ')}
                        </span>
                        <span className="text-sm text-gray-600 dark:text-gray-400">
                          {typeof count === 'number' ? count : JSON.stringify(count)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* LLM Analysis */}
              {selectedProfile.llm_analysis && (
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                    <Brain className="h-5 w-5 text-purple-500" />
                    AI Analysis
                  </h3>
                  <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                    <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {selectedProfile.llm_analysis}
                    </p>
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              {selectedProfile.recommended_actions && Object.keys(selectedProfile.recommended_actions).length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                    <Target className="h-5 w-5 text-blue-500" />
                    Recommended Actions
                  </h3>
                  <pre className="p-4 bg-gray-50 dark:bg-gray-900 rounded text-sm overflow-x-auto">
                    {JSON.stringify(selectedProfile.recommended_actions, null, 2)}
                  </pre>
                </div>
              )}
            </>
          ) : (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-12 text-center">
              <Globe className="h-16 w-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
              <p className="text-gray-500 dark:text-gray-400">
                Select an attacker to view their profile
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
