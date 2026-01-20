import { useState } from 'react';
import { X, Plus, Tag, Loader2, Check } from 'lucide-react';

interface BulkTagModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedCount: number;
  availableTags: string[];
  onApply: (tagsToAdd: string[], tagsToRemove: string[]) => Promise<void>;
}

export default function BulkTagModal({
  isOpen,
  onClose,
  selectedCount,
  availableTags,
  onApply,
}: BulkTagModalProps) {
  const [tagsToAdd, setTagsToAdd] = useState<string[]>([]);
  const [tagsToRemove, setTagsToRemove] = useState<string[]>([]);
  const [newTag, setNewTag] = useState('');
  const [isApplying, setIsApplying] = useState(false);

  if (!isOpen) return null;

  const handleAddTag = (tag: string) => {
    if (!tagsToAdd.includes(tag)) {
      setTagsToAdd([...tagsToAdd, tag]);
      // Remove from tagsToRemove if present
      setTagsToRemove(tagsToRemove.filter((t) => t !== tag));
    }
  };

  const handleRemoveTag = (tag: string) => {
    if (!tagsToRemove.includes(tag)) {
      setTagsToRemove([...tagsToRemove, tag]);
      // Remove from tagsToAdd if present
      setTagsToAdd(tagsToAdd.filter((t) => t !== tag));
    }
  };

  const handleCreateAndAddTag = () => {
    const trimmed = newTag.trim();
    if (trimmed && !tagsToAdd.includes(trimmed)) {
      setTagsToAdd([...tagsToAdd, trimmed]);
      setTagsToRemove(tagsToRemove.filter((t) => t !== trimmed));
      setNewTag('');
    }
  };

  const handleApply = async () => {
    if (tagsToAdd.length === 0 && tagsToRemove.length === 0) return;

    setIsApplying(true);
    try {
      await onApply(tagsToAdd, tagsToRemove);
      onClose();
    } finally {
      setIsApplying(false);
    }
  };

  const handleClose = () => {
    setTagsToAdd([]);
    setTagsToRemove([]);
    setNewTag('');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 dark:bg-black/70"
        onClick={handleClose}
      />

      {/* Modal */}
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative w-full max-w-md bg-white dark:bg-zinc-800 rounded-xl shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                <Tag className="w-5 h-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Bulk Tag Devices
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {selectedCount} device{selectedCount !== 1 ? 's' : ''} selected
                </p>
              </div>
            </div>
            <button
              onClick={handleClose}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-4 space-y-4">
            {/* Add new tag */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Create new tag
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newTag}
                  onChange={(e) => setNewTag(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreateAndAddTag()}
                  placeholder="Enter tag name..."
                  className="input flex-1"
                  maxLength={50}
                />
                <button
                  onClick={handleCreateAndAddTag}
                  disabled={!newTag.trim()}
                  className="btn-secondary disabled:opacity-50"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Tags to add */}
            {tagsToAdd.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-success-700 dark:text-success-400 mb-2">
                  Tags to add
                </label>
                <div className="flex flex-wrap gap-2">
                  {tagsToAdd.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-success-100 dark:bg-success-900/30 text-success-700 dark:text-success-300 rounded-full"
                    >
                      <Plus className="w-3 h-3" />
                      {tag}
                      <button
                        onClick={() => setTagsToAdd(tagsToAdd.filter((t) => t !== tag))}
                        className="hover:text-success-900 dark:hover:text-success-100"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Tags to remove */}
            {tagsToRemove.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-danger-700 dark:text-danger-400 mb-2">
                  Tags to remove
                </label>
                <div className="flex flex-wrap gap-2">
                  {tagsToRemove.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-danger-100 dark:bg-danger-900/30 text-danger-700 dark:text-danger-300 rounded-full line-through"
                    >
                      {tag}
                      <button
                        onClick={() => setTagsToRemove(tagsToRemove.filter((t) => t !== tag))}
                        className="hover:text-danger-900 dark:hover:text-danger-100"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Existing tags */}
            {availableTags.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Existing tags
                </label>
                <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
                  {availableTags
                    .filter((tag) => !tagsToAdd.includes(tag) && !tagsToRemove.includes(tag))
                    .map((tag) => (
                      <div key={tag} className="flex items-center gap-1">
                        <button
                          onClick={() => handleAddTag(tag)}
                          className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300 rounded-l-full hover:bg-success-100 dark:hover:bg-success-900/30 hover:text-success-700 dark:hover:text-success-300"
                          title="Add to selected devices"
                        >
                          <Plus className="w-3 h-3" />
                          {tag}
                        </button>
                        <button
                          onClick={() => handleRemoveTag(tag)}
                          className="px-1.5 py-1 text-sm bg-gray-100 dark:bg-zinc-700 text-gray-500 dark:text-gray-400 rounded-r-full hover:bg-danger-100 dark:hover:bg-danger-900/30 hover:text-danger-700 dark:hover:text-danger-300"
                          title="Remove from selected devices"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 p-4 border-t border-gray-200 dark:border-zinc-700">
            <button
              onClick={handleClose}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              onClick={handleApply}
              disabled={isApplying || (tagsToAdd.length === 0 && tagsToRemove.length === 0)}
              className="btn-primary disabled:opacity-50 inline-flex items-center gap-2"
            >
              {isApplying ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Check className="w-4 h-4" />
              )}
              Apply Changes
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
