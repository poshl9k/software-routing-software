import { SvgIcon, type SvgIconProps } from "@mui/material";
import type { ReactElement } from "react";

/**
 * Inline-SVG icon set (stroke, 24×24, `currentColor`). Deliberately dependency
 * free — replaces the ad-hoc unicode glyphs and emoji previously used in the
 * sidebar and dashboard.
 */
const paths: Record<string, ReactElement> = {
  overview: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </>
  ),
  network: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18" />
    </>
  ),
  dhcp: <path d="M7 4v13M4 14l3 3 3-3M17 20V7M14 10l3-3 3 3" />,
  dns: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4" />
    </>
  ),
  routes: <path d="M12 3v18M5 8h11l3 3-3 3H5z" />,
  routing: <path d="M16 3h5v5M4 20 21 3M21 16v5h-5M15 15l6 6M4 4l5 5" />,
  tunnels: (
    <>
      <path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  proxy: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="1" />
      <rect x="3" y="13" width="18" height="7" rx="1" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>
  ),
  firewall: (
    <>
      <path d="M4 6h16v12H4z" />
      <path d="M4 10h16M4 14h16M9 6v4M15 10v4M9 14v4" />
    </>
  ),
  ssh: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </>
  ),
  events: <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />,
  apply: (
    <>
      <path d="M4 6h16M4 12h16M4 18h16" />
      <circle cx="9" cy="6" r="2" />
      <circle cx="15" cy="12" r="2" />
      <circle cx="7" cy="18" r="2" />
    </>
  ),
  maintenance: (
    <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 0 0 5.4-5.4l-2.3 2.3-2-2z" />
  ),
  logout: <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />,
  trash: (
    <path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13" />
  ),
};

export type IconName = keyof typeof paths;

export function Icon({
  name,
  ...props
}: { name: IconName } & SvgIconProps) {
  return (
    <SvgIcon
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      fontSize="small"
      {...props}
    >
      {paths[name]}
    </SvgIcon>
  );
}