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

/** Read-only table. Renders `empty` (or a default) when there are no rows. */
export function DataTable({
  heads,
  rows,
  empty,
}: {
  heads: string[];
  rows: ReactNode[][];
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
            rows.map((row, i) => (
              <TableRow key={i}>
                {row.map((cell, j) => (
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