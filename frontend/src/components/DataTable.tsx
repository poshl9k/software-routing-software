import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";
import type { ReactNode } from "react";
import { EmptyState } from "./EmptyState";

/** `null` is a quiet group gap; `{cells, className}` styles one row. */
export type DataTableRow = ReactNode[] | { cells: ReactNode[]; className?: string } | null;

const cellsOf = (row: Exclude<DataTableRow, null>): ReactNode[] =>
  Array.isArray(row) ? row : row.cells;

/** Read-only table. Renders `empty` (or a default) when there are no rows. */
export function DataTable({
  heads,
  rows,
  empty,
}: {
  heads: string[];
  rows: DataTableRow[];
  empty?: ReactNode;
}) {
  return (
    <TableContainer>
      <Table>
        <TableHead>
          <TableRow>
            {heads.map((h) => (
              <TableCell key={h}>{h}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.length ? (
            rows.map((row, i) => row === null ? (
              <TableRow key={i} aria-hidden="true">
                <TableCell colSpan={heads.length} sx={{ p: 0, height: 10, border: 0 }} />
              </TableRow>
            ) : (
              <TableRow key={i} className={Array.isArray(row) ? undefined : row.className}>
                {cellsOf(row).map((cell, j) => (
                  <TableCell key={j}>{cell ?? "—"}</TableCell>
                ))}
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={heads.length} sx={{ py: 0 }}>
                {empty ?? <EmptyState>Нет записей</EmptyState>}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
}