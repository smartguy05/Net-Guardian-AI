import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { X, Lightbulb, Keyboard } from 'lucide-react';
import { useHelpStore } from '../stores/help';
import { getHelpForPath } from '../content/helpContent';
import clsx from 'clsx';

export default function HelpPanel() {
  const location = useLocation();
  const { isOpen, closeHelp, toggleHelp } = useHelpStore();
  const helpContent = getHelpForPath(location.pathname);

  // Keyboard shortcuts
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Ignore if typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      // Toggle help with "?"
      if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        toggleHelp();
      }

      // Close with Escape
      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        closeHelp();
      }
    }

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, toggleHelp, closeHelp]);

  // Prevent body scroll when panel is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  if (!helpContent) {
    return null;
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className={clsx(
          'fixed inset-0 z-50 bg-black/30 backdrop-blur-sm transition-opacity duration-300',
          isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
        )}
        onClick={closeHelp}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        className={clsx(
          'fixed inset-y-0 right-0 z-50 w-full max-w-md transform bg-white dark:bg-zinc-800 shadow-2xl transition-transform duration-300 ease-out',
          isOpen ? 'translate-x-0' : 'translate-x-full'
        )}
        role="dialog"
        aria-modal="true"
        aria-labelledby="help-panel-title"
      >
        <div className="flex h-full flex-col">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-gray-200 dark:border-zinc-700 px-6 py-4">
            <div>
              <h2
                id="help-panel-title"
                className="text-lg font-semibold text-gray-900 dark:text-white"
              >
                {helpContent.title} Help
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Press <kbd className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-zinc-700 rounded">?</kbd> to toggle
              </p>
            </div>
            <button
              onClick={closeHelp}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700 transition-colors"
              aria-label="Close help panel"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto px-6 py-4">
            {/* Overview */}
            <div className="mb-6">
              <p className="text-gray-600 dark:text-gray-300 leading-relaxed">
                {helpContent.overview}
              </p>
            </div>

            {/* Sections */}
            <div className="space-y-6">
              {helpContent.sections.map((section, index) => (
                <div key={index}>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                    {section.title}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                    {section.description}
                  </p>

                  {/* Tips */}
                  <div className="space-y-2">
                    {section.tips.map((tip, tipIndex) => (
                      <div
                        key={tipIndex}
                        className="flex items-start gap-2 text-sm"
                      >
                        <Lightbulb className="h-4 w-4 text-warning-500 dark:text-warning-400 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-600 dark:text-gray-300">
                          {tip}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Keyboard shortcuts for this section */}
                  {section.shortcuts && section.shortcuts.length > 0 && (
                    <div className="mt-3 p-3 bg-gray-50 dark:bg-zinc-700/50 rounded-lg">
                      <div className="flex items-center gap-2 text-xs font-medium text-gray-700 dark:text-gray-300 mb-2">
                        <Keyboard className="h-3.5 w-3.5" />
                        Keyboard Shortcuts
                      </div>
                      <div className="space-y-1">
                        {section.shortcuts.map((shortcut, shortcutIndex) => (
                          <div
                            key={shortcutIndex}
                            className="flex items-center justify-between text-sm"
                          >
                            <kbd className="px-2 py-0.5 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-600 rounded text-xs font-mono text-gray-700 dark:text-gray-300">
                              {shortcut.key}
                            </kbd>
                            <span className="text-gray-600 dark:text-gray-400 text-xs">
                              {shortcut.action}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Global keyboard shortcuts */}
            {helpContent.shortcuts && helpContent.shortcuts.length > 0 && (
              <div className="mt-6 p-4 bg-primary-50 dark:bg-primary-900/20 rounded-lg border border-primary-100 dark:border-primary-800">
                <div className="flex items-center gap-2 text-sm font-medium text-primary-700 dark:text-primary-400 mb-3">
                  <Keyboard className="h-4 w-4" />
                  Page Shortcuts
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {helpContent.shortcuts.map((shortcut, index) => (
                    <div
                      key={index}
                      className="flex items-center gap-2 text-sm"
                    >
                      <kbd className="px-2 py-0.5 bg-white dark:bg-zinc-800 border border-primary-200 dark:border-primary-700 rounded text-xs font-mono text-primary-700 dark:text-primary-300">
                        {shortcut.key}
                      </kbd>
                      <span className="text-primary-600 dark:text-primary-400 text-xs truncate">
                        {shortcut.action}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-gray-200 dark:border-zinc-700 px-6 py-4">
            <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
              <span>Press <kbd className="px-1 py-0.5 bg-gray-100 dark:bg-zinc-700 rounded">Esc</kbd> to close</span>
              <a
                href="https://github.com/netguardian-ai/netguardian"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary-600 dark:text-primary-400 hover:underline"
              >
                Documentation
              </a>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
