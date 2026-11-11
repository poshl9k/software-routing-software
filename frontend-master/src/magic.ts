/** Remove a proof from the URL before rendering or issuing any request. */
function take(name: string): string | null {
  if (window.location.pathname !== "/login" || !window.location.hash.startsWith("#")) return null;
  const value = new URLSearchParams(window.location.hash.slice(1)).get(name) ?? "";
  if (!value) return null;
  window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
  return value;
}

/** One-shot proof minted by the bot for a single sign-in. */
export function takeMagicProof(): string | null {
  return take("token");
}

/** Stable account link: works repeatedly until the user rotates it. */
export function takePortalLink(): string | null {
  return take("link");
}
