import { Alert } from "@mui/material";
import { Link } from "react-router-dom";
import { ApiError } from "../api";

/** Inline error surface for a handled async failure. */
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