import { useState, useRef, useEffect } from 'react';
import { Tag, X, ChevronDown, Check } from 'lucide-react';
import clsx from 'clsx';

interface TagFilterProps {
  availableTags: string[];
  selectedTags: string[];
  onChange: (tags: string[]) => void;
  tagCounts?: Record<string, number>;
  className?: string;
}

export default function TagFilter({
  availableTags,
  selectedTags,
  onChange,
  tagCounts,
  className,
}: TagFilterProps) {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const toggleTag = (tag: string) => {
    if (selectedTags.includes(tag)) {
      onChange(selectedTags.filter((t) => t !== tag));
    } else {
      onChange([...selectedTags, tag]);
    }
  };

  const clearAll = () => {
    onChange([]);
  };

  return (
    <div ref={containerRef} className={clsx('relative', className)}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={clsx(
          'input flex items-center gap-2 text-left',
          selectedTags.length > 0 && 'border-primary-500 ring-1 ring-primary-500'
        )}
      >
        <Tag className="w-4 h-4 text-gray-400 dark:text-gray-500 flex-shrink-0" />
        <span className="flex-1 truncate">
          {selectedTags.length === 0
            ? 'Filter by tags...'
            : `${selectedTags.length} tag${selectedTags.length > 1 ? 's' : ''} selected`}
        </span>
        <ChevronDown
          className={clsx('w-4 h-4 text-gray-400 dark:text-gray-500 transition-transform', isOpen && 'rotate-180')}
        />
      </button>

      {/* Selected tags chips */}
      {selectedTags.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {selectedTags.map((tag) => (
            <span
              key={tag}
              className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 rounded-full"
            >
              {tag}
              <button
                type="button"
                onClick={() => toggleTag(tag)}
                className="hover:text-primary-900 dark:hover:text-primary-100"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
          <button
            type="button"
            onClick={clearAll}
            className="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          >
            Clear all
          </button>
        </div>
      )}

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute z-20 mt-1 w-full bg-white dark:bg-zinc-800 rounded-lg shadow-lg border border-gray-200 dark:border-zinc-600 max-h-60 overflow-auto">
          {availableTags.length === 0 ? (
            <div className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
              No tags available
            </div>
          ) : (
            <ul className="py-1">
              {availableTags.map((tag) => (
                <li key={tag}>
                  <button
                    type="button"
                    onClick={() => toggleTag(tag)}
                    className={clsx(
                      'w-full px-4 py-2 text-left text-sm flex items-center justify-between hover:bg-gray-100 dark:hover:bg-zinc-700',
                      selectedTags.includes(tag) && 'bg-primary-50 dark:bg-primary-900/20'
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className={clsx(
                          'w-4 h-4 border rounded flex items-center justify-center',
                          selectedTags.includes(tag)
                            ? 'bg-primary-500 border-primary-500'
                            : 'border-gray-300 dark:border-zinc-500'
                        )}
                      >
                        {selectedTags.includes(tag) && (
                          <Check className="w-3 h-3 text-white" />
                        )}
                      </span>
                      <span className="text-gray-900 dark:text-white">{tag}</span>
                    </span>
                    {tagCounts && tagCounts[tag] !== undefined && (
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {tagCounts[tag]}
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
