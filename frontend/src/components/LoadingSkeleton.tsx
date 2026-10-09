import { Box, Skeleton } from "@mui/material";
import { tokens } from "../theme";

export interface LoadingSkeletonProps {
  height?: number;
  width?: number | string;
}

/** A card-sized loading surface, not an empty-state message. */
export function LoadingSkeleton({ height = 160, width = "100%" }: LoadingSkeletonProps) {
  return (
    <Box role="status" aria-label="Загрузка" sx={{ width, p: 2, bgcolor: tokens.surface, border: `1px solid ${tokens.border}`, borderRadius: 2 }}>
      <Skeleton variant="text" width="45%" />
      <Skeleton variant="rounded" height={Math.max(48, height - 56)} sx={{ mt: 1 }} />
    </Box>
  );
}
