/** Human-facing title for a declared source/group, falling back to its tag. */
export function displayTitle(item: { name: string; label?: string | null }): string {
  return item.label?.trim() || item.name;
}

/**
 * Title followed by the technical tag (when they differ). Used everywhere a
 * rule-set source or group is shown: wizard cards, source table, group chips.
 */
/** Group title followed by its technical tag. */
export function displayPair(item: { name: string; label?: string | null }): string {
  const title = displayTitle(item);
  return title === item.name ? item.name : `${title} · ${item.name}`;
}


export type LabeledPreset = { name: string; rule_sets: readonly { tag: string }[] };

/** Human title for a declared source: explicit label, else the catalog preset name. */
export function sourceDisplayTitle(
  source: { name: string; label?: string | null },
  presets: readonly LabeledPreset[] = [],
): string {
  const explicit = source.label?.trim();
  if (explicit) return explicit;
  const preset = presets.find((item) => item.rule_sets.some((set) => set.tag === source.name));
  return preset?.name || source.name;
}

/** Source title followed by its technical tag, used in chips and tables. */
export function sourceDisplayPair(
  source: { name: string; label?: string | null },
  presets: readonly LabeledPreset[] = [],
): string {
  const title = sourceDisplayTitle(source, presets);
  return title === source.name ? source.name : `${title} · ${source.name}`;
}
