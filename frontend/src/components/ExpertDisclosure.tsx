import { Accordion, AccordionDetails, AccordionSummary, Typography } from "@mui/material";
import type { ReactNode } from "react";
import { tokens } from "../theme";

export interface ExpertDisclosureProps {
  children: ReactNode;
  defaultExpanded?: boolean;
}

/** Native MUI accordion preserves keyboard and focus semantics when collapsed. */
export function ExpertDisclosure({ children, defaultExpanded = false }: ExpertDisclosureProps) {
  return (
    <Accordion defaultExpanded={defaultExpanded} disableGutters sx={{ bgcolor: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: "none", "&:before": { display: "none" } }}>
      <AccordionSummary>
        <Typography>Показать дополнительные настройки</Typography>
      </AccordionSummary>
      <AccordionDetails>{children}</AccordionDetails>
    </Accordion>
  );
}
