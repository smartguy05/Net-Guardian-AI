import { HelpCircle } from 'lucide-react';
import { useHelpStore } from '../stores/help';

export default function HelpButton() {
  const toggleHelp = useHelpStore((state) => state.toggleHelp);

  return (
    <button
      onClick={toggleHelp}
      className="fixed bottom-6 right-6 z-40 flex h-12 w-12 items-center justify-center rounded-full bg-primary-600 text-white shadow-lg transition-all hover:bg-primary-700 hover:scale-105 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-zinc-900"
      aria-label="Open help panel"
      title="Help (press ? to toggle)"
    >
      <HelpCircle className="h-6 w-6" />
    </button>
  );
}
