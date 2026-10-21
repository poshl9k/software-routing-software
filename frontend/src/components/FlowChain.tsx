import { Fragment } from "react";
import { Box } from "@mui/material";
import { Badge, type Tone } from "./Badge";
import { Icon } from "./Icon";

/** Static, wrapping description of a flow; never an interactive chip group. */
export function FlowChain({ label, items }: {
  label: string;
  items: readonly { text: string; tone?: Tone }[];
}) {
  return <Box role="group" aria-label={label} className="flow-chain"
    sx={{ "& .MuiChip-root": { height: "auto", minHeight: 28 },
      "& .MuiChip-label": { whiteSpace: "normal", overflowWrap: "anywhere", py: 0.5 } }}>
    {items.map((item, index) => <Fragment key={`${index}-${item.text}`}>
      {index > 0 && <Icon name="arrowRight" />}
      <Badge tone={item.tone}>{item.text}</Badge>
    </Fragment>)}
  </Box>;
}
