import { Button, Paper, Typography } from "@mui/material";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/** Titled section surface, optional "настроить" link and header action. */
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