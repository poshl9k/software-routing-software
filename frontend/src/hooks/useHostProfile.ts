import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { queryKeys } from "../query";

/** One source for product identity and screen capabilities, never a guessed profile. */
export function useHostProfile() {
  const query = useQuery({ queryKey: queryKeys.hostProfile(), queryFn: api.hostProfile });
  // A failed refetch must not present cached identity as a successfully read fact.
  return { ...query, data: query.isSuccess ? query.data : undefined };
}
