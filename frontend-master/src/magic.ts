/** Remove one-time proof before rendering or issuing any request. */
export function takeMagicProof(): string | null {
  if (window.location.pathname !== "/login" || !window.location.hash.startsWith("#token=")) return null;
  const proof = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
  window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
  return proof;
}