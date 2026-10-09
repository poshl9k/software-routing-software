import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle } from "@mui/material";
import type { ReactNode } from "react";

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  danger?: boolean;
}

/** MUI Dialog traps focus while open and restores it to the trigger on close. */
export function ConfirmDialog({ open, title, body, confirmLabel, cancelLabel, onConfirm, onCancel, danger = false }: ConfirmDialogProps) {
  return (
    <Dialog open={open} onClose={onCancel} aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-body" maxWidth="sm" fullWidth>
      <DialogTitle id="confirm-dialog-title">{title}</DialogTitle>
      <DialogContent>
        <DialogContentText id="confirm-dialog-body" component="div">{body}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} autoFocus>{cancelLabel}</Button>
        <Button onClick={onConfirm} color={danger ? "error" : "primary"} variant="contained">{confirmLabel}</Button>
      </DialogActions>
    </Dialog>
  );
}
