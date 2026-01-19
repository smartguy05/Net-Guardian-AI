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
} from 'lucide-react';
import { useAuthStore } from '../stores/auth';
import { useLogout } from '../api/hooks';
import clsx from 'clsx';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, adminOnly: false },
  { name: 'Devices', href: '/devices', icon: Monitor, adminOnly: false },
  { name: 'Events', href: '/events', icon: Activity, adminOnly: false },
  { name: 'Alerts', href: '/alerts', icon: Bell, adminOnly: false },
  { name: 'Anomalies', href: '/anomalies', icon: AlertTriangle, adminOnly: false },
  { name: 'Quarantine', href: '/quarantine', icon: ShieldOff, adminOnly: false },
  { name: 'AI Chat', href: '/chat', icon: MessageSquare, adminOnly: false },
  { name: 'Sources', href: '/sources', icon: Database, adminOnly: false },
  { name: 'Users', href: '/users', icon: Users, adminOnly: true },
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
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar */}
      <div
        className={clsx(
          'fixed inset-0 z-50 lg:hidden',
          sidebarOpen ? 'block' : 'hidden'
        )}
      >
        <div
          className="fixed inset-0 bg-gray-900/50"
          onClick={() => setSidebarOpen(false)}
        />
        <div className="fixed inset-y-0 left-0 w-64 bg-white shadow-xl">
          <div className="flex h-16 items-center justify-between px-4">
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary-600" />
              <span className="text-lg font-bold text-gray-900">NetGuardian</span>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="p-2 text-gray-500 hover:text-gray-700"
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
                        ? 'bg-primary-50 text-primary-700'
                        : 'text-gray-700 hover:bg-gray-100'
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
        <div className="flex grow flex-col gap-y-5 overflow-y-auto border-r border-gray-200 bg-white px-4 pb-4">
          <div className="flex h-16 items-center gap-2">
            <Shield className="h-8 w-8 text-primary-600" />
            <span className="text-lg font-bold text-gray-900">NetGuardian AI</span>
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
                            ? 'bg-primary-50 text-primary-700'
                            : 'text-gray-700 hover:bg-gray-100'
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
          <div className="border-t border-gray-200 pt-4">
            <div className="flex items-center gap-3 px-3 py-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary-100">
                <User className="h-5 w-5 text-primary-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 truncate">
                  {user?.username}
                </p>
                <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="flex w-full items-center gap-3 px-3 py-2 mt-2 text-sm font-medium text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
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
        <div className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-gray-200 bg-white px-4 lg:hidden">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-2 text-gray-500 hover:text-gray-700"
          >
            <Menu className="h-6 w-6" />
          </button>
          <div className="flex items-center gap-2">
            <Shield className="h-7 w-7 text-primary-600" />
            <span className="text-lg font-bold text-gray-900">NetGuardian</span>
          </div>
        </div>

        <main className="p-4 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
