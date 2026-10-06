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