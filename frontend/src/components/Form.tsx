import type { ReactNode } from "react";

/**
 * One form layout for every editor. Fields are grid items; use `FormWide` for
 * anything that must span the row (lists, nested cards, notes) and
 * `FormActions` for a row of field-level buttons.
 */
export function FormGrid({ children }: { children: ReactNode }) {
  return <div className="form-grid">{children}</div>;
}

/** A grid item that spans the full row. */
export function FormWide({ children }: { children: ReactNode }) {
  return <div className="form-wide">{children}</div>;
}

/** Left-aligned action row (keygen, QR, add/remove) for field-level buttons. */
export function FormActions({ children }: { children: ReactNode }) {
  return <div className="form-actions">{children}</div>;
}