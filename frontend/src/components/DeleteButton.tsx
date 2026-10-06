import { IconButton, Tooltip } from "@mui/material";
import { Icon } from "./Icon";

/** Consistent icon-only delete action for rows and cards. */
export function DeleteButton({
  label,
  onClick,
  disabled = false,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <Tooltip title={label}>
      <span>
        <IconButton
          size="small"
          color="error"
          aria-label={label}
          disabled={disabled}
          onClick={onClick}
        >
          <Icon name="trash" fontSize="small" />
        </IconButton>
      </span>
    </Tooltip>
  );
}