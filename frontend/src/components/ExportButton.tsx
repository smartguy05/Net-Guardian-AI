import { useState } from 'react';
import { Download, FileSpreadsheet, FileText, ChevronDown, Loader2 } from 'lucide-react';
import clsx from 'clsx';

interface ExportButtonProps {
  onExportCSV: () => Promise<void>;
  onExportPDF: () => Promise<void>;
  disabled?: boolean;
  className?: string;
}

export default function ExportButton({
  onExportCSV,
  onExportPDF,
  disabled = false,
  className,
}: ExportButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isExporting, setIsExporting] = useState<'csv' | 'pdf' | null>(null);

  const handleExport = async (type: 'csv' | 'pdf') => {
    setIsExporting(type);
    try {
      if (type === 'csv') {
        await onExportCSV();
      } else {
        await onExportPDF();
      }
    } finally {
      setIsExporting(null);
      setIsOpen(false);
    }
  };

  return (
    <div className={clsx('relative', className)}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        disabled={disabled || isExporting !== null}
        className={clsx(
          'btn-secondary inline-flex items-center gap-2',
          disabled && 'opacity-50 cursor-not-allowed'
        )}
      >
        {isExporting ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Download className="w-4 h-4" />
        )}
        Export
        <ChevronDown className={clsx('w-4 h-4 transition-transform', isOpen && 'rotate-180')} />
      </button>

      {isOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
          />

          {/* Dropdown */}
          <div className="absolute right-0 mt-2 w-48 rounded-lg shadow-lg bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-600 z-20">
            <div className="py-1">
              <button
                onClick={() => handleExport('csv')}
                disabled={isExporting !== null}
                className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-3"
              >
                {isExporting === 'csv' ? (
                  <Loader2 className="w-4 h-4 animate-spin text-success-500" />
                ) : (
                  <FileSpreadsheet className="w-4 h-4 text-success-500" />
                )}
                <span>Export as CSV</span>
              </button>
              <button
                onClick={() => handleExport('pdf')}
                disabled={isExporting !== null}
                className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-700 flex items-center gap-3"
              >
                {isExporting === 'pdf' ? (
                  <Loader2 className="w-4 h-4 animate-spin text-danger-500" />
                ) : (
                  <FileText className="w-4 h-4 text-danger-500" />
                )}
                <span>Export as PDF</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
