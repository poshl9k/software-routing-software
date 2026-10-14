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

/** Remaining DHCP lease lifetime, in seconds. */
export function fmtRemaining(seconds: number): string {
  if (seconds <= 0) return "истекла";
  const minutes = Math.floor(seconds / 60);
  if (minutes === 0) return "менее минуты";
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  if (hours === 0) return `${minutes} мин`;
  return `${hours} ч${remainder ? ` ${remainder} мин` : ""}`;
}