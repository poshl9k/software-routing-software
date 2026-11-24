/** Human-facing title for a declared source/group, falling back to its tag. */
export function displayTitle(item: { name: string; label?: string | null }): string {
  return item.label?.trim() || item.name;
}

/**
 * Title followed by the technical tag (when they differ). Used everywhere a
 * rule-set source or group is shown: wizard cards, source table, group chips.
 */
export function displayPair(item: { name: string; label?: string | null }): string {
  const title = displayTitle(item);
  return title === item.name ? item.name : `${title} · ${item.name}`;
}
