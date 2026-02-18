import { useState } from 'react';
import { Trophy, Medal, User, Shield } from 'lucide-react';
import { useLeaderboard, useGamificationStats, useLevelsInfo } from '../api/hooks';
import { useAuthStore } from '../stores/auth';

type LeaderboardPeriod = 'weekly' | 'monthly' | 'all_time';

export default function LeaderboardPage() {
  const { user } = useAuthStore();
  const [period, setPeriod] = useState<LeaderboardPeriod>('weekly');

  const { data: leaderboard, isLoading: leaderboardLoading } = useLeaderboard(period, 50);
  const { data: stats } = useGamificationStats();
  const { data: levelsInfo } = useLevelsInfo();

  const getRankIcon = (rank: number) => {
    switch (rank) {
      case 1:
        return <Trophy className="h-6 w-6 text-yellow-500" />;
      case 2:
        return <Medal className="h-6 w-6 text-gray-400" />;
      case 3:
        return <Medal className="h-6 w-6 text-amber-600" />;
      default:
        return <span className="text-lg font-bold text-gray-500 dark:text-gray-400">#{rank}</span>;
    }
  };

  const getLevelTitle = (level: number) => {
    if (!levelsInfo?.levels) return `Level ${level}`;
    const levelInfo = [...levelsInfo.levels].reverse().find(l => level >= l.level);
    return levelInfo?.title || `Level ${level}`;
  };

  if (leaderboardLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  const currentUserEntry = leaderboard?.entries?.find(entry => entry.user_id === user?.id);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Leaderboard</h1>
        <div className="flex gap-2">
          {(['weekly', 'monthly', 'all_time'] as LeaderboardPeriod[]).map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                period === p
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              {p === 'all_time' ? 'All Time' : p.charAt(0).toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Current User Stats */}
      {stats && (
        <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg shadow p-6 text-white">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="bg-white/20 rounded-full p-3">
                <Shield className="h-8 w-8" />
              </div>
              <div>
                <p className="text-sm opacity-75">Your Rank</p>
                <p className="text-3xl font-bold">
                  {currentUserEntry ? `#${currentUserEntry.rank}` : (leaderboard?.user_rank ? `#${leaderboard.user_rank}` : 'Not ranked')}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm opacity-75">{stats.title}</p>
              <p className="text-2xl font-bold">{stats.total_points.toLocaleString()} pts</p>
              <p className="text-sm opacity-75">Level {stats.level}</p>
            </div>
          </div>
        </div>
      )}

      {/* Top 3 Podium */}
      {leaderboard?.entries && leaderboard.entries.length >= 3 && (
        <div className="grid grid-cols-3 gap-4">
          {/* Second Place */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mt-8">
            <div className="flex flex-col items-center">
              <Medal className="h-12 w-12 text-gray-400 mb-2" />
              <div className="bg-gray-100 dark:bg-gray-700 rounded-full w-16 h-16 flex items-center justify-center mb-2">
                <User className="h-8 w-8 text-gray-500" />
              </div>
              <p className="font-semibold text-gray-900 dark:text-white truncate max-w-full">
                {leaderboard.entries[1].username || 'Anonymous'}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {getLevelTitle(leaderboard.entries[1].level)}
              </p>
              <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">
                {leaderboard.entries[1].total_points.toLocaleString()} pts
              </p>
            </div>
          </div>

          {/* First Place */}
          <div className="bg-gradient-to-b from-yellow-50 to-white dark:from-yellow-900/20 dark:to-gray-800 rounded-lg shadow p-4 border-2 border-yellow-400">
            <div className="flex flex-col items-center">
              <Trophy className="h-16 w-16 text-yellow-500 mb-2" />
              <div className="bg-yellow-100 dark:bg-yellow-900/30 rounded-full w-20 h-20 flex items-center justify-center mb-2 border-2 border-yellow-400">
                <User className="h-10 w-10 text-yellow-600" />
              </div>
              <p className="font-bold text-lg text-gray-900 dark:text-white truncate max-w-full">
                {leaderboard.entries[0].username || 'Anonymous'}
              </p>
              <p className="text-sm text-yellow-600 dark:text-yellow-400">
                {getLevelTitle(leaderboard.entries[0].level)}
              </p>
              <p className="text-xl font-bold text-yellow-600 dark:text-yellow-400 mt-1">
                {leaderboard.entries[0].total_points.toLocaleString()} pts
              </p>
            </div>
          </div>

          {/* Third Place */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mt-8">
            <div className="flex flex-col items-center">
              <Medal className="h-12 w-12 text-amber-600 mb-2" />
              <div className="bg-amber-100 dark:bg-amber-900/30 rounded-full w-16 h-16 flex items-center justify-center mb-2">
                <User className="h-8 w-8 text-amber-600" />
              </div>
              <p className="font-semibold text-gray-900 dark:text-white truncate max-w-full">
                {leaderboard.entries[2].username || 'Anonymous'}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {getLevelTitle(leaderboard.entries[2].level)}
              </p>
              <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">
                {leaderboard.entries[2].total_points.toLocaleString()} pts
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Full Leaderboard Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Rank
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                User
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Level
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Points
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Alerts Resolved
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Streak
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {leaderboard?.entries?.map((entry) => (
              <tr
                key={entry.user_id}
                className={`${
                  entry.user_id === user?.id
                    ? 'bg-blue-50 dark:bg-blue-900/20'
                    : 'hover:bg-gray-50 dark:hover:bg-gray-700/50'
                }`}
              >
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center justify-center w-8">
                    {getRankIcon(entry.rank)}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="bg-gray-100 dark:bg-gray-700 rounded-full w-10 h-10 flex items-center justify-center mr-3">
                      <User className="h-5 w-5 text-gray-500" />
                    </div>
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {entry.username || 'Anonymous'}
                        {entry.user_id === user?.id && (
                          <span className="ml-2 text-xs text-blue-600 dark:text-blue-400">(You)</span>
                        )}
                      </p>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      Level {entry.level}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {entry.title}
                    </p>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {entry.total_points.toLocaleString()}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    {entry.alerts_resolved}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    {entry.current_streak} days
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {(!leaderboard?.entries || leaderboard.entries.length === 0) && (
          <div className="text-center py-12">
            <Trophy className="h-12 w-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No leaderboard data yet.</p>
            <p className="text-sm text-gray-400 dark:text-gray-500">
              Start resolving alerts and completing challenges to appear on the leaderboard!
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
