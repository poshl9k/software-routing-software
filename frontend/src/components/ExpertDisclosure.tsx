import { Accordion, AccordionDetails, AccordionSummary, Typography } from "@mui/material";
import type { ReactNode } from "react";
import { tokens } from "../theme";

export interface ExpertDisclosureProps {
  children: ReactNode;
  defaultExpanded?: boolean;
  /** Replaces the generic summary label when the disclosure names a concrete group. */
  title?: ReactNode;
  /** Stable accessible name for tests and screen readers. */
  ariaLabel?: string;
}

/** Native MUI accordion preserves keyboard and focus semantics when collapsed. */
export function ExpertDisclosure({ children, defaultExpanded = false, title, ariaLabel }: ExpertDisclosureProps) {
  return (
    <Accordion defaultExpanded={defaultExpanded} disableGutters sx={{ bgcolor: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: "none", "&:before": { display: "none" } }}>
      <AccordionSummary aria-label={ariaLabel}>
        <Typography>{title ?? "Показать дополнительные настройки"}</Typography>
      </AccordionSummary>
      <AccordionDetails>{children}</AccordionDetails>
    </Accordion>
  );
}
