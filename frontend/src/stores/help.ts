import { create } from 'zustand';

interface HelpState {
  isOpen: boolean;
  openHelp: () => void;
  closeHelp: () => void;
  toggleHelp: () => void;
}

export const useHelpStore = create<HelpState>()((set) => ({
  isOpen: false,

  openHelp: () => set({ isOpen: true }),

  closeHelp: () => set({ isOpen: false }),

  toggleHelp: () => set((state) => ({ isOpen: !state.isOpen })),
}));
