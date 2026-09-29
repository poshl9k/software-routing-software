import type { ReactNode } from "react";
import {
  Alert,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { Link } from "react-router-dom";
import { ApiError } from "./api";
export function Badge({
  children,
  tone = "blue",
}: {
  children: ReactNode;
  tone?: "blue" | "green" | "amber" | "red" | "purple";
}) {
  return <span className={`chip ${tone}`}>{children}</span>;
}
export function Card({
  title,
  children,
  to,
  action,
}: {
  title: string;
  children: ReactNode;
  to?: string;
  action?: ReactNode;
}) {
  return (
    <Paper elevation={0} className="card">
      <div className="card-head">
        <Typography component="h2" variant="h2">
          {title}
        </Typography>
        {to && (
          <Button component={Link} to={to} variant="outlined">
            Настроить
          </Button>
        )}
        {action}
      </div>
      {children}
    </Paper>
  );
}
export function DataTable({
  heads,
  rows,
}: {
  heads: string[];
  rows: ReactNode[][];
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
              <TableCell colSpan={heads.length}>Нет записей</TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
export function Todo({
  children = "Демонстрационные данные из макета; API пока отсутствует.",
}: {
  children?: ReactNode;
}) {
  return <Alert severity="info">TODO-API · {children}</Alert>;
}
/** Human-readable date+time for a version timestamp (ISO from the API). */
export function fmtDateTime(iso?: string | null): string {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <Alert severity="error">
      {error instanceof Error ? error.message : "Ошибка"}
      {error instanceof ApiError && (
        <>
          {" "}
          · {error.code}
          {error.status === 401 && (
            <>
              {" "}
              · <Link to="/login">Войти</Link> или{" "}
              <Link to="/onboarding">Первый запуск</Link>
            </>
          )}
          {error.details.length > 0 && (
            <pre>{JSON.stringify(error.details, null, 2)}</pre>
          )}
        </>
      )}
    </Alert>
  );
}
