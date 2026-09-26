export interface Preferences {
  safe: boolean;
  timeout: number;
}
const defaults: Preferences = { safe: false, timeout: 180 };
export function readPreferences(): Preferences {
  try {
    const value = JSON.parse(
      localStorage.getItem("vs-router.preferences") ?? "null",
    ) as Partial<Preferences> | null;
    return value &&
      typeof value.safe === "boolean" &&
      Number.isInteger(value.timeout) &&
      value.timeout! >= 60 &&
      value.timeout! <= 600
      ? (value as Preferences)
      : defaults;
  } catch {
    return defaults;
  }
}
export function savePreferences(value: Preferences) {
  try {
    localStorage.setItem("vs-router.preferences", JSON.stringify(value));
  } catch {
    /* Browser storage may be disabled; active form still works. */
  }
}
