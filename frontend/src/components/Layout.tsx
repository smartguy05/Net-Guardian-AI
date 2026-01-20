import { useState } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import {
  Shield,
  ShieldOff,
  LayoutDashboard,
  Monitor,
  Activity,
  Bell,
  Database,
  Menu,
  X,
  LogOut,
  User,
  Users,
  AlertTriangle,
  MessageSquare,
  Settings,
  ListFilter,
  Network,
} from 'lucide-react';
import { useAuthStore } from '../stores/auth';
import { useLogout } from '../api/hooks';
import ThemeToggle from './ThemeToggle';
import clsx from 'clsx';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, adminOnly: false },
  { name: 'Devices', href: '/devices', icon: Monitor, adminOnly: false },
  { name: 'Topology', href: '/topology', icon: Network, adminOnly: false },
  { name: 'Events', href: '/events', icon: Activity, adminOnly: false },
  { name: 'Alerts', href: '/alerts', icon: Bell, adminOnly: false },
  { name: 'Anomalies', href: '/anomalies', icon: AlertTriangle, adminOnly: false },
  { name: 'Rules', href: '/rules', icon: ListFilter, adminOnly: false },
  { name: 'Threat Intel', href: '/threat-intel', icon: Shield, adminOnly: false },
  { name: 'Quarantine', href: '/quarantine', icon: ShieldOff, adminOnly: false },
  { name: 'AI Chat', href: '/chat', icon: MessageSquare, adminOnly: false },
  { name: 'Sources', href: '/sources', icon: Database, adminOnly: false },
  { name: 'Users', href: '/users', icon: Users, adminOnly: true },
  { name: 'Settings', href: '/settings', icon: Settings, adminOnly: false },
];

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const user = useAuthStore((state) => state.user);
  const logout = useLogout();

  const handleLogout = () => {
    logout.mutate();
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-zinc-900">
      {/* Mobile sidebar */}
      <div
        className={clsx(
          'fixed inset-0 z-50 lg:hidden',
          sidebarOpen ? 'block' : 'hidden'
        )}
      >
        <div
          className="fixed inset-0 bg-gray-900/50 dark:bg-black/60"
          onClick={() => setSidebarOpen(false)}
        />
        <div className="fixed inset-y-0 left-0 w-64 bg-white dark:bg-zinc-800 shadow-xl">
          <div className="flex h-16 items-center justify-between px-4">
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary-600" />
              <span className="text-lg font-bold text-gray-900 dark:text-white">NetGuardian</span>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
          <nav className="mt-4 px-2">
            {navigation
              .filter((item) => !item.adminOnly || user?.role === 'admin')
              .map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    onClick={() => setSidebarOpen(false)}
                    className={clsx(
                      'flex items-center gap-3 px-3 py-2 rounded-lg mb-1 text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-700'
                    )}
                  >
                    <item.icon className="h-5 w-5" />
                    {item.name}
                  </Link>
                );
              })}
          </nav>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:flex lg:w-64 lg:flex-col">
        <div className="flex grow flex-col gap-y-5 overflow-y-auto border-r border-gray-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 px-4 pb-4">
          <div className="flex h-16 items-center gap-2">
            <Shield className="h-8 w-8 text-primary-600" />
            <span className="text-lg font-bold text-gray-900 dark:text-white">NetGuardian AI</span>
          </div>
          <nav className="flex flex-1 flex-col">
            <ul className="flex flex-1 flex-col gap-y-1">
              {navigation
                .filter((item) => !item.adminOnly || user?.role === 'admin')
                .map((item) => {
                  const isActive = location.pathname === item.href;
                  return (
                    <li key={item.name}>
                      <Link
                        to={item.href}
                        className={clsx(
                          'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                          isActive
                            ? 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
                            : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-700'
                        )}
                      >
                        <item.icon className="h-5 w-5" />
                        {item.name}
                      </Link>
                    </li>
                  );
                })}
            </ul>
          </nav>

          {/* User section */}
          <div className="border-t border-gray-200 dark:border-zinc-700 pt-4">
            {/* Theme toggle */}
            <div className="flex items-center justify-between px-3 py-2 mb-2">
              <span className="text-sm text-gray-600 dark:text-gray-400">Theme</span>
              <ThemeToggle />
            </div>

            <div className="flex items-center gap-3 px-3 py-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/50">
                <User className="h-5 w-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                  {user?.username}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400 capitalize">{user?.role}</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="flex w-full items-center gap-3 px-3 py-2 mt-2 text-sm font-medium text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700 transition-colors"
            >
              <LogOut className="h-5 w-5" />
              Sign out
            </button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Mobile header */}
        <div className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-gray-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 px-4 lg:hidden">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          >
            <Menu className="h-6 w-6" />
          </button>
          <div className="flex items-center gap-2 flex-1">
            <Shield className="h-7 w-7 text-primary-600" />
            <span className="text-lg font-bold text-gray-900 dark:text-white">NetGuardian</span>
          </div>
          <ThemeToggle />
        </div>

        <main className="p-4 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
