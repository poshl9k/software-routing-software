import type { DiffResponse } from "../types";
import { Badge } from "./Badge";
import { InfoNote } from "./InfoNote";

/** Server-generated, redacted diff: never infer consequences from raw paths. */
export function DiffReview({ data }: { data: DiffResponse }) {
  return (
    <div>
      {data.summary.length === 0 ? (
        <InfoNote>Нет изменений</InfoNote>
      ) : data.summary.map((section, index) => (
        <section key={`${section.area}-${index}`}>
          <h3>{section.title}</h3>
          <div className="fields">
            <Badge tone="green">+{section.added}</Badge>
            <Badge tone="red">−{section.removed}</Badge>
            <Badge tone="amber">×{section.changed}</Badge>
          </div>
          {section.consequences.map((note, i) => (
            <InfoNote key={i} severity="warning">{note}</InfoNote>
          ))}
        </section>
      ))}
      <details>
        <summary>Показать технический diff</summary>
        <pre className="diff">{JSON.stringify(data.changes, null, 2)}</pre>
      </details>
    </div>
  );
}
