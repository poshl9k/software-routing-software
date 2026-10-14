import type { DiffResponse } from "../types";
import { Badge } from "./Badge";
import { InfoNote } from "./InfoNote";

/**
 * Server-generated, redacted diff: never infer consequences from raw paths.
 *
 * The payload is treated as untrusted: a response without `summary`/`changes`
 * arrays (a bare `{}`, a proxy error body, a partial write) used to throw
 * `Cannot read properties of undefined`, which unmounted the whole Apply screen.
 * Anything unreadable is reported as an honest state instead.
 */
export function DiffReview({ data }: { data: DiffResponse | null | undefined }) {
  const summary = Array.isArray(data?.summary) ? data.summary : null;
  const changes = Array.isArray(data?.changes) ? data.changes : null;
  if (summary === null && changes === null) {
    return (
      <div>
        <InfoNote severity="warning">
          Сервер не вернул разбор изменений. Обновите состояние и повторите.
        </InfoNote>
      </div>
    );
  }
  const sections = summary ?? [];
  return (
    <div>
      {sections.length === 0 ? (
        <InfoNote>Нет изменений</InfoNote>
      ) : sections.map((section, index) => (
        <section key={`${section.area}-${index}`}>
          <h3>{section.title}</h3>
          <div className="fields">
            <Badge tone="green">+{section.added}</Badge>
            <Badge tone="red">−{section.removed}</Badge>
            <Badge tone="amber">×{section.changed}</Badge>
          </div>
          {(section.consequences ?? []).map((note, i) => (
            <InfoNote key={i} severity="warning">{note}</InfoNote>
          ))}
        </section>
      ))}
      <details>
        <summary>Показать технический diff</summary>
        <pre className="diff">{JSON.stringify(changes ?? [], null, 2)}</pre>
      </details>
    </div>
  );
}
