import { useCallback, useState } from "react";
import type { Configuration } from "../types";
import { useConfiguration } from "../state";

export interface DraftEditor<T> {
  value: T | null;
  setValue: (value: T | null) => void;
  isEdit: boolean;
  saving: boolean;
  error: unknown;
  setError: (error: unknown) => void;
  /** Enter edit mode with a working copy of `initial`. */
  begin: (initial: T) => void;
  /** Leave edit mode, dropping local changes. */
  cancel: () => void;
  /**
   * Persist the current working copy. `commit` maps the local value to a full
   * configuration; the hook saves the draft, shows the shared notice and exits
   * edit mode, retaining the local value and surfacing the error on failure.
   * `override` is for an action that has already replaced the working copy in
   * the same event: React has not re-rendered yet, so `value` is still stale.
   */
  save: (commit: (value: T) => Configuration, override?: T) => Promise<void>;
}

/**
 * The single draft lifecycle shared by every editor page: local working copy,
 * save-on-commit, the `Черновик vN сохранён` notice, error retention and exit.
 */
export function useDraftEditor<T>(): DraftEditor<T> {
  const { version, saveDraft, setNotice } = useConfiguration();
  const [value, setValue] = useState<T | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const begin = useCallback((initial: T) => {
    setValue(initial);
    setError(null);
  }, []);
  const cancel = useCallback(() => {
    setValue(null);
    setError(null);
  }, []);
  const save = useCallback(
    async (commit: (value: T) => Configuration, override?: T) => {
      const current = override ?? value;
      if (!version || current === null) return;
      setSaving(true);
      setError(null);
      try {
        const saved = await saveDraft(commit(current));
        setNotice(`Черновик v${saved.id} сохранён`);
        setValue(null);
      } catch (err) {
        setError(err);
      } finally {
        setSaving(false);
      }
    },
    [version, value, saveDraft, setNotice],
  );
  return {
    value,
    setValue,
    isEdit: value !== null,
    saving,
    error,
    setError,
    begin,
    cancel,
    save,
  };
}