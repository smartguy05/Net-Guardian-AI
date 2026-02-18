import { useState } from 'react';
import { Trophy, Star, Lock, Medal, Target, Flame, Crown, Award } from 'lucide-react';
import { useAchievements, useGamificationStats, useRecentAchievements } from '../api/hooks';
import type { AchievementCategory, AchievementRarity } from '../types';

const rarityColors: Record<AchievementRarity, string> = {
  common: 'text-gray-400 bg-gray-100 dark:bg-gray-700',
  uncommon: 'text-green-500 bg-green-100 dark:bg-green-900',
  rare: 'text-blue-500 bg-blue-100 dark:bg-blue-900',
  legendary: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900',
};

const categoryIcons: Record<AchievementCategory, React.ReactNode> = {
  alerts: <Target className="h-4 w-4" />,
  anomalies: <Flame className="h-4 w-4" />,
  devices: <Medal className="h-4 w-4" />,
  investigations: <Crown className="h-4 w-4" />,
  streaks: <Star className="h-4 w-4" />,
  milestones: <Award className="h-4 w-4" />,
  special: <Trophy className="h-4 w-4" />,
};

export default function AchievementsPage() {
  const [selectedCategory, setSelectedCategory] = useState<AchievementCategory | undefined>();
  const [showHidden, setShowHidden] = useState(false);

  const { data: stats, isLoading: statsLoading } = useGamificationStats();
  const { data: achievements, isLoading: achievementsLoading } = useAchievements({
    category: selectedCategory,
    include_hidden: showHidden,
  });
  const { data: recentAchievements } = useRecentAchievements(5);

  const categories: AchievementCategory[] = ['alerts', 'anomalies', 'devices', 'investigations', 'streaks', 'milestones', 'special'];

  if (statsLoading || achievementsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Achievements</h1>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <input
              type="checkbox"
              checked={showHidden}
              onChange={(e) => setShowHidden(e.target.checked)}
              className="rounded border-gray-300 dark:border-gray-600"
            />
            Show Hidden
          </label>
        </div>
      </div>

      {/* Stats Overview */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Level</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.level}</p>
                <p className="text-sm text-blue-600 dark:text-blue-400">{stats.title}</p>
              </div>
              <Trophy className="h-10 w-10 text-yellow-500" />
            </div>
            <div className="mt-3">
              <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
                <span>{stats.current_xp} XP</span>
                <span>{stats.xp_to_next_level} XP</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-600 rounded-full h-2 transition-all"
                  style={{ width: `${stats.xp_progress_percent}%` }}
                />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Points</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total_points.toLocaleString()}</p>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Current Streak</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.streak.current} days</p>
            <p className="text-xs text-gray-400">Best: {stats.streak.longest} days</p>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Achievements</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {achievements?.unlocked_count || 0} / {achievements?.total || 0}
            </p>
          </div>
        </div>
      )}

      {/* Recent Achievements */}
      {recentAchievements && recentAchievements.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recently Unlocked</h2>
          <div className="flex gap-4 overflow-x-auto pb-2">
            {recentAchievements.map((achievement) => (
              <div
                key={achievement.id}
                className={`flex-shrink-0 p-3 rounded-lg ${rarityColors[achievement.rarity]}`}
              >
                <div className="flex items-center gap-2">
                  <Trophy className="h-5 w-5" />
                  <div>
                    <p className="font-medium">{achievement.name}</p>
                    <p className="text-xs opacity-75">{achievement.points} pts</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Category Filter */}
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={() => setSelectedCategory(undefined)}
          className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
            !selectedCategory
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
          }`}
        >
          All
        </button>
        {categories.map((category) => (
          <button
            key={category}
            onClick={() => setSelectedCategory(category)}
            className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors flex items-center gap-1.5 ${
              selectedCategory === category
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
            }`}
          >
            {categoryIcons[category]}
            {category.charAt(0).toUpperCase() + category.slice(1)}
          </button>
        ))}
      </div>

      {/* Achievements Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {achievements?.items.map((achievement) => (
          <div
            key={achievement.id}
            className={`bg-white dark:bg-gray-800 rounded-lg shadow p-4 ${
              !achievement.unlocked ? 'opacity-60' : ''
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${rarityColors[achievement.rarity]}`}>
                  {achievement.unlocked ? (
                    <Trophy className="h-6 w-6" />
                  ) : (
                    <Lock className="h-6 w-6" />
                  )}
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    {achievement.name}
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {achievement.description}
                  </p>
                </div>
              </div>
              <span className={`text-xs font-medium px-2 py-1 rounded ${rarityColors[achievement.rarity]}`}>
                {achievement.rarity}
              </span>
            </div>
            <div className="mt-3 flex items-center justify-between text-sm">
              <span className="text-gray-500 dark:text-gray-400 flex items-center gap-1">
                {categoryIcons[achievement.category]}
                {achievement.category}
              </span>
              <span className="font-medium text-blue-600 dark:text-blue-400">
                +{achievement.points} pts
              </span>
            </div>
            {achievement.earned_at && (
              <p className="text-xs text-gray-400 mt-2">
                Earned: {new Date(achievement.earned_at).toLocaleDateString()}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
