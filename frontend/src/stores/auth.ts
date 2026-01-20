import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User } from '../types';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  // 2FA state
  pending2FA: boolean;
  pending2FAToken: string | null;
  pending2FAUser: User | null;
  setUser: (user: User) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
  login: (user: User, accessToken: string, refreshToken: string) => void;
  logout: () => void;
  // 2FA methods
  setPending2FA: (pending: boolean, token: string | null, user: User | null) => void;
  clearPending2FA: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      pending2FA: false,
      pending2FAToken: null,
      pending2FAUser: null,

      setUser: (user) => set({ user }),

      setTokens: (accessToken, refreshToken) =>
        set({ accessToken, refreshToken }),

      login: (user, accessToken, refreshToken) =>
        set({
          user,
          accessToken,
          refreshToken,
          isAuthenticated: true,
          pending2FA: false,
          pending2FAToken: null,
          pending2FAUser: null,
        }),

      logout: () =>
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          pending2FA: false,
          pending2FAToken: null,
          pending2FAUser: null,
        }),

      setPending2FA: (pending, token, user) =>
        set({
          pending2FA: pending,
          pending2FAToken: token,
          pending2FAUser: user,
        }),

      clearPending2FA: () =>
        set({
          pending2FA: false,
          pending2FAToken: null,
          pending2FAUser: null,
        }),
    }),
    {
      name: 'netguardian-auth',
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
        // Don't persist 2FA state
      }),
    }
  )
);
