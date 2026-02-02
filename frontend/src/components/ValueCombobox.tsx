import { useState, useRef, useEffect, useMemo } from 'react';
import { ChevronDown, Loader2 } from 'lucide-react';
import clsx from 'clsx';
import { useFieldValues } from '../api/hooks';

interface ValueComboboxProps {
  fieldName: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}

export default function ValueCombobox({
  fieldName,
  value,
  onChange,
  placeholder = 'Value...',
  className,
}: ValueComboboxProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [inputValue, setInputValue] = useState(value);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Fetch values for this field
  const { data, isLoading } = useFieldValues(fieldName);
  const suggestions = data?.values || [];

  // Filter suggestions based on input
  const filteredSuggestions = useMemo(() => {
    if (!inputValue) return suggestions;
    const lower = inputValue.toLowerCase();
    return suggestions.filter((s) => s.toLowerCase().includes(lower));
  }, [suggestions, inputValue]);

  // Sync input value with external value
  useEffect(() => {
    setInputValue(value);
  }, [value]);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        // Commit the current input value when clicking outside
        if (inputValue !== value) {
          onChange(inputValue);
        }
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [inputValue, value, onChange]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setInputValue(newValue);
    onChange(newValue);
    if (!isOpen) setIsOpen(true);
  };

  const handleSelect = (selectedValue: string) => {
    setInputValue(selectedValue);
    onChange(selectedValue);
    setIsOpen(false);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setIsOpen(false);
    } else if (e.key === 'ArrowDown' && !isOpen) {
      setIsOpen(true);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (isOpen && filteredSuggestions.length > 0) {
        handleSelect(filteredSuggestions[0]);
      }
    }
  };

  const showDropdown = isOpen && (filteredSuggestions.length > 0 || isLoading);

  return (
    <div ref={containerRef} className={clsx('relative', className)}>
      <div className="relative">
        <input
          ref={inputRef}
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          onFocus={() => setIsOpen(true)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          className="input py-1.5 text-sm w-full pr-8"
        />
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <ChevronDown
              className={clsx('w-4 h-4 transition-transform', isOpen && 'rotate-180')}
            />
          )}
        </button>
      </div>

      {showDropdown && (
        <div className="absolute z-30 mt-1 w-full bg-white dark:bg-zinc-800 rounded-lg shadow-lg border border-gray-200 dark:border-zinc-600 max-h-48 overflow-auto">
          {isLoading ? (
            <div className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400 flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading values...
            </div>
          ) : filteredSuggestions.length === 0 ? (
            <div className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
              No matching values found
            </div>
          ) : (
            <ul className="py-1">
              {filteredSuggestions.map((suggestion) => (
                <li key={suggestion}>
                  <button
                    type="button"
                    onClick={() => handleSelect(suggestion)}
                    className={clsx(
                      'w-full px-4 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-zinc-700',
                      suggestion === inputValue && 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                    )}
                  >
                    {suggestion}
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
