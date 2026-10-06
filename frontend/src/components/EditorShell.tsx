import { Button } from "@mui/material";
import type { ReactNode } from "react";

/** Save/Cancel footer shared by every editor. */
export function EditorFooter({
  saving,
  valid,
  cancel,
  save,
}: {
  saving: boolean;
  valid: boolean;
  cancel: () => void;
  save: () => void;
}) {
  return (
    <div className="footer-actions">
      <span className="spacer" />
      <Button disabled={saving} onClick={cancel}>
        Отмена
      </Button>
      <Button variant="contained" disabled={saving || !valid} onClick={save}>
        {saving ? "Сохранение…" : "Сохранить"}
      </Button>
    </div>
  );
}

/** Disabled-while-saving wrapper for an editor's form body. */
export function EditorFieldset({
  disabled,
  children,
}: {
  disabled: boolean;
  children: ReactNode;
}) {
  return (
    <fieldset disabled={disabled} style={{ border: 0, padding: 0, minWidth: 0 }}>
      {children}
    </fieldset>
  );
}

/**
 * Switches between read-only `view` and editing `edit`, wrapping the edit
 * branch in a fieldset + footer. `edit` may be a render function so it is only
 * evaluated in edit mode — this prevents a crash when the edit branch
 * dereferences state that is null outside edit mode.
 */
export function EditorShell({
  isEdit,
  saving,
  valid,
  onCancel,
  onSave,
  view,
  edit,
}: {
  isEdit: boolean;
  saving: boolean;
  valid: boolean;
  onCancel: () => void;
  onSave: () => void;
  view: ReactNode;
  edit: ReactNode | (() => ReactNode);
}) {
  if (!isEdit) return <>{view}</>;
  return (
    <>
      <EditorFieldset disabled={saving}>
        {typeof edit === "function" ? edit() : edit}
      </EditorFieldset>
      <EditorFooter saving={saving} valid={valid} cancel={onCancel} save={onSave} />
    </>
  );
}