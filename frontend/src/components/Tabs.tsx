import { Tab, Tabs } from "@mui/material";

/** Index-driven tab strip used by the composite service screens. */
export function PageTabs({
  values,
  value,
  change,
}: {
  values: string[];
  value: number;
  change: (n: number) => void;
}) {
  return (
    <Tabs
      value={value}
      onChange={(_, n: number) => change(n)}
      variant="scrollable"
    >
      {values.map((v) => (
        <Tab key={v} label={v} />
      ))}
    </Tabs>
  );
}

/**
 * Value-driven tab strip: the active tab is a route/state key (a string), not
 * an index. Used by screens whose tab lives in the URL or in string state.
 */
export function ValueTabs<T extends string>({
  tabs,
  value,
  change,
}: {
  tabs: readonly { value: T; label: string }[];
  value: T;
  change: (v: T) => void;
}) {
  return (
    <Tabs value={value} onChange={(_, v: T) => change(v)} variant="scrollable">
      {tabs.map((t) => (
        <Tab key={t.value} value={t.value} label={t.label} />
      ))}
    </Tabs>
  );
}