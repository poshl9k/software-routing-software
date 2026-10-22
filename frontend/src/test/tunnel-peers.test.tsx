import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { Tunnels } from "../pages/ConnectionEditors";
import { emptyConfiguration } from "../fixtures";
import { RouterProvider } from "../state";
import type { Configuration, Peer, Tunnel } from "../types";

const phone: Peer = {
  name: "phone", public_key: "phone-public", private_key: { redacted: true },
  preshared_key: { redacted: true }, allowed_ips: ["10.66.66.2/32"],
};
const laptop: Peer = { ...phone, name: "laptop", public_key: "laptop-public", private_key: null, preshared_key: null };
const server: Tunnel = {
  name: "vpn", interface: "tun0", role: "server", protocol: "awg",
  private_key: { redacted: true }, listen_port: 51820, peers: [phone, laptop],
  endpoint: "vpn.example.org:51820", server_public_key: null, allowed_ips: [], keepalive: 25,
  obfuscation: { Jc: 4, S1: 1, S2: 2, H1: 3, H2: 4, H3: 5, H4: 6, Jmin: 35 },
  preshared_key: null, header_protection_key: { redacted: true },
  random_trailers: true, disable_cookies: false, open_port: true,
};
const config = (tunnels: Tunnel[] = [server]): Configuration => ({ ...emptyConfiguration, tunnels });
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
type Extra = (path: string, init?: RequestInit) => Response | Promise<Response>;
async function mount(configuration = config(), extra: Extra = () => json({})) {
  const fetch = vi.fn((path: string, init?: RequestInit) => {
    if (path === "/api/versions") return Promise.resolve(json([{ id: 1, status: "confirmed", configuration }]));
    if (path === "/api/status/services") return Promise.resolve(json({ generated_at: "2026-01-01T00:00:00Z", services: [] }));
    if (path === "/api/draft") return Promise.resolve(json({ id: 2, status: "draft", configuration: JSON.parse(String(init?.body)) }));
    return Promise.resolve(extra(path, init));
  });
  vi.stubGlobal("fetch", fetch);
  render(<RouterProvider><Tunnels /></RouterProvider>);
  await waitFor(() => expect(screen.getByRole("button", { name: /Добавить туннель/ })).toBeEnabled());
  return fetch;
}
const calls = (fetch: ReturnType<typeof vi.fn>, path: string) => fetch.mock.calls.filter(([url]) => url === path);
const saved = (fetch: ReturnType<typeof vi.fn>) => JSON.parse(String(calls(fetch, "/api/draft")[0]?.[1]?.body)) as Configuration;
async function openServer() {
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const editor = await screen.findByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Сервер" });
  expect(editor.querySelector("input, select, textarea")).toBeNull();
  expect(within(editor).queryByRole("tab", { name: "Пиры" })).not.toBeInTheDocument();
  await userEvent.click(within(editor).getByRole("button", { name: "Изменить" }));
  return editor;
}
/** Opens a client tunnel from the default "Клиенты" tab and enters edit mode. */
async function openClient() {
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const editor = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  await userEvent.click(within(editor).getByRole("button", { name: "Изменить" }));
  return editor;
}
async function openPeers() {
  const editor = await openServer();
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  return editor;
}
function peerRow(editor: HTMLElement, name: string) {
  return within(editor).getByRole("row", { name: new RegExp(name) });
}
const fill = (dialog: HTMLElement, label: string, value: string) =>
  fireEvent.change(within(dialog).getByLabelText(label), { target: { value } });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
async function blobText(blob: Blob): Promise<string> {
  // Which Blob the app hands over depends on the environment: jsdom's Blob has no
  // text(), while Node's Blob is refused by jsdom's FileReader ("parameter 1 is
  // not of type 'Blob'"), and which one wins varies with the Node build — that is
  // how this test passed locally and failed on CI. Neither path is wrong; try both.
  if (typeof blob.text === "function") return blob.text();
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

it("criterion_1_server_tabs_client_has_no_strip", async () => {
  await mount();
  const editor = await openServer();
  expect(within(editor).getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Туннель", "Пиры"]);
  expect(within(editor).getByRole("tab", { name: "Туннель" })).toHaveAttribute("aria-selected", "true");
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  expect(within(editor).getByRole("tab", { name: "Пиры" })).toHaveAttribute("aria-selected", "true");
  await userEvent.click(within(editor).getByRole("button", { name: "Отмена" }));
  // Fresh provider: the client keeps the whole form, without a tab strip.
  // The separate test below mounts it with a fresh QueryClient.
});

it("criterion_1_client_editor_is_one_full_form", async () => {
  const fetch = await mount(config([{ ...server, role: "client", peers: [], endpoint: "remote.example:51820", server_public_key: "remote" }]));
  const editor = await openClient();
  expect(within(editor).queryByRole("tab")).not.toBeInTheDocument();
  for (const label of ["Имя туннеля", "Endpoint", "AllowedIPs", "Keepalive, с", "Публичный ключ сервера", "Preshared key", "Приватный ключ"])
    expect(within(editor).getByLabelText(label)).toBeVisible();
  expect(within(editor).queryByRole("button", { name: "+ Добавить пира" })).not.toBeInTheDocument();
  expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(0);
});

it("criterion_2_tunnel_fields_notes_and_draft_summary_are_preserved", async () => {
  const fetch = await mount();
  const editor = await openServer();
  for (const label of ["Имя туннеля", "Интерфейс", "Роль", "Протокол", "Адрес туннеля", "Публичный ключ", "Порт", "Публичный адрес (endpoint)", "Приватный ключ"])
    expect(within(editor).getByLabelText(label)).toBeVisible();
  expect(within(editor).getByText(/Устройство создаётся автоматически/)).toBeVisible();
  expect(within(editor).getByText(/Сохранение создаёт только черновик/)).toBeVisible();
  expect(within(editor).getByRole("switch", { name: "Открыть порт на WAN" })).toBeChecked();
  expect(within(editor).queryByRole("checkbox", { name: "Использовать туннель как маршрут по умолчанию" })).not.toBeInTheDocument();
  expect(within(editor).queryByLabelText("Имя пира")).not.toBeInTheDocument();
  await userEvent.click(within(editor).getByText("Показать дополнительные настройки"));
  for (const label of ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey"])
    expect(within(editor).getByLabelText(label)).toBeVisible();
  expect(within(editor).getByRole("switch", { name: "RandomTrailers" })).toBeChecked();
  expect(within(editor).getByRole("switch", { name: "DisableCookies" })).not.toBeChecked();
  fill(editor, "Порт", "51821");
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  expect(within(editor).getByLabelText("Порт")).not.toBeVisible();
  await userEvent.click(within(editor).getByRole("tab", { name: "Туннель" }));
  expect(within(editor).getByLabelText("Порт")).toHaveValue(51821);
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0]).toMatchObject({ listen_port: 51821, peers: [phone, laptop], private_key: { redacted: true } });
});

it("criterion_2_client_awg_fields_and_notes_survive_one_outer_save", async () => {
  const client = { ...server, role: "client" as const, peers: [], endpoint: "remote.example:51820", server_public_key: "remote", allowed_ips: ["0.0.0.0/0"], preshared_key: { redacted: true } as const };
  const fetch = await mount(config([client]));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const view = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  await userEvent.click(within(view).getByRole("button", { name: "Изменить" }));
  const editor = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  expect(within(editor).getByText(/AllowedIPs ≠ маршрут/)).toBeVisible();
  expect(within(editor).getByLabelText("Роль")).toHaveValue("клиент");
  expect(within(editor).getByLabelText("Preshared key")).toHaveValue("");
  expect(within(editor).getByLabelText("Приватный ключ")).toHaveValue("");
  await userEvent.click(within(editor).getByText("Показать дополнительные настройки"));
  fill(editor, "Jmin", "40");
  fill(editor, "I1", "<r 2><b 0xaa>");
  await userEvent.click(within(editor).getByRole("switch", { name: "DisableCookies" }));
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0]).toMatchObject({ role: "client", peers: [],
    allowed_ips: ["0.0.0.0/0"], preshared_key: { redacted: true }, private_key: { redacted: true },
    obfuscation: { ...server.obfuscation, Jmin: 40, I1: "<r 2><b 0xaa>" }, disable_cookies: true });
});

it("criterion_3_read_only_table_has_ordered_rows_actions_and_one_empty_state", async () => {
  await mount();
  const editor = await openPeers();
  const table = within(editor).getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((head) => head.textContent)).toEqual(["Имя", "Активность", "Действия"]);
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  expect(within(rows[0]).getByText("phone")).toBeVisible();
  expect(within(rows[1]).getByText("laptop")).toBeVisible();
  for (const row of rows) {
    expect(within(row).queryByRole("textbox")).not.toBeInTheDocument();
    for (const name of ["Изменить", "QR", "Экспорт конфигурации"])
      expect(within(row).getByRole("button", { name })).toBeVisible();
  }
});

it("criterion_3_empty_peers_table_states_absence_once", async () => {
  await mount(config([{ ...server, peers: [] }]));
  const editor = await openPeers();
  expect(within(editor).getAllByText("Пиров нет.")).toHaveLength(1);
  expect(within(editor).getAllByRole("button", { name: "+ Добавить пира" })).toHaveLength(1);
  expect(within(editor).getByRole("table")).toBeVisible();
});

it("criterion_4_keygen_adds_one_local_peer_and_allows_immediate_naming", async () => {
  const fetch = await mount(config([{ ...server, peers: [] }]), (path) =>
    path === "/api/keygen/peer-keypair" ? json({ public_key: "new-public", private_key: "new-private" }) : json({}));
  const editor = await openPeers();
  await userEvent.click(within(editor).getByRole("button", { name: "+ Добавить пира" }));
  await waitFor(() => expect(calls(fetch, "/api/keygen/peer-keypair")).toHaveLength(1));
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  const peer = await screen.findByRole("dialog", { name: "Пир: Новый пир" });
  expect(within(peer).getByLabelText("Публичный ключ пира")).toHaveValue("new-public");
  expect(within(peer).getByLabelText("Приватный ключ пира (входит в клиентский конфиг)")).toHaveValue("new-private");
  fill(peer, "Имя пира", "tablet");
  await userEvent.click(within(peer).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: /Пир:/ })).not.toBeInTheDocument());
  expect(within(editor).getByText("tablet")).toBeVisible();
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0].peers).toEqual([{
    name: "tablet", public_key: "new-public", private_key: { plaintext: "new-private" },
    preshared_key: null, allowed_ips: ["10.66.66.2/32"],
  }]);
});

it("criterion_4_double_add_does_not_duplicate_or_lose_a_pending_keypair", async () => {
  const pending = deferred<Response>();
  const fetch = await mount(config([{ ...server, peers: [] }]), (path) =>
    path === "/api/keygen/peer-keypair" ? pending.promise : json({}));
  const editor = await openPeers();
  const add = within(editor).getByRole("button", { name: "+ Добавить пира" });
  fireEvent.click(add);
  fireEvent.click(add);
  expect(calls(fetch, "/api/keygen/peer-keypair")).toHaveLength(1);
  await act(async () => { pending.resolve(json({ public_key: "once", private_key: "secret" })); });
  expect(await screen.findByRole("dialog", { name: "Пир: Новый пир" })).toBeVisible();
  expect(within(editor).getAllByRole("row", { hidden: true })).toHaveLength(2);
});

it("criterion_5_qr_is_png_blob_with_download_cleanup_and_disabled_for_new_tunnels", async () => {
  const objectURL = vi.fn(() => "blob:peer-qr");
  const revoke = vi.fn();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: objectURL });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
  const fetch = await mount(config([server]), (path) => path.endsWith("/qr")
    ? new Response("PNG payload", { headers: { "Content-Type": "image/png" } }) : json({}));
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "QR" }));
  const qr = await screen.findByRole("dialog", { name: /QR-код пира phone/ });
  expect(within(qr).getByRole("img", { name: /QR-код пира phone/ })).toHaveAttribute("src", "blob:peer-qr");
  expect(within(qr).getByRole("link", { name: "Скачать PNG" })).toHaveAttribute("download", "phone.png");
  expect(objectURL).toHaveBeenCalledWith(expect.objectContaining({ type: "image/png" }));
  expect(fetch).toHaveBeenCalledWith("/api/tunnels/vpn/peer/phone/qr", expect.objectContaining({ credentials: "include" }));
  await userEvent.click(within(qr).getByRole("button", { name: "Закрыть" }));
  expect(revoke).toHaveBeenCalledWith("blob:peer-qr");
});

it("criterion_5_qr_failure_is_visible_in_outer_editor", async () => {
  await mount(config([server]), (path) => path.endsWith("/qr") ? json({ code: "qr.failed", message: "QR недоступен" }, 503) : json({}));
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "QR" }));
  expect(await within(editor).findByText(/QR недоступен/)).toBeVisible();
  expect(screen.queryByRole("img", { name: /QR-код пира/ })).not.toBeInTheDocument();
});

it("criterion_6_conf_export_encodes_names_downloads_body_and_releases_url", async () => {
  const named = { ...server, name: "vpn / офис", peers: [{ ...phone, name: "телефон / 1" }] };
  const create = vi.fn((_blob: Blob) => "blob:peer-conf");
  const revoke = vi.fn();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toBe("vpn / офис-телефон / 1.conf");
    expect(this.href).toBe("blob:peer-conf");
  });
  const fetch = await mount(config([named]), (path) => path.endsWith("/conf")
    ? new Response("[Interface]\nPrivateKey = client-key\n[Peer]\nPublicKey = server-key\n", { headers: { "Content-Type": "text/plain" } }) : json({}));
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const view = screen.getByRole("dialog", { name: /Туннель: vpn \/ офис/ });
  await userEvent.click(within(view).getByRole("button", { name: "Изменить" }));
  const editor = screen.getByRole("dialog", { name: /Туннель: vpn \/ офис/ });
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  await userEvent.click(within(peerRow(editor, "телефон / 1")).getByRole("button", { name: "Экспорт конфигурации" }));
  await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
  expect(fetch).toHaveBeenCalledWith(`/api/tunnels/${encodeURIComponent(named.name)}/peer/${encodeURIComponent(named.peers[0].name)}/conf`, expect.objectContaining({ credentials: "include" }));
  const [blob] = create.mock.calls[0];
  // Deliberately not `expect.any(Blob)`: that compares constructor identity, and
  // under jsdom the Blob's realm depends on the Node build — it passed locally and
  // failed on CI. What matters is that a Blob carrying the config was handed over.
  expect(Object.prototype.toString.call(blob)).toBe("[object Blob]");
  expect(await blobText(blob)).toContain("PrivateKey = client-key");
  expect(revoke).toHaveBeenCalledWith("blob:peer-conf");
  click.mockRestore();
});

it("criterion_6_conf_error_remains_visible_in_tunnel_dialog", async () => {
  const fetch = await mount(config([server]), (path) => path.endsWith("/conf")
    ? json({ code: "conf.failed", message: "Экспорт недоступен" }, 503) : json({}));
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Экспорт конфигурации" }));
  expect(await within(editor).findByText(/Экспорт недоступен/)).toBeVisible();
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
});

it("criterion_5_criterion_6_new_tunnel_disables_qr_and_conf_without_requests", async () => {
  const fetch = await mount(config([]), (path) => path === "/api/keygen/tunnel"
    ? json({ public_key: "server-public", private_key: "server-private", obfuscation: server.obfuscation })
    : path === "/api/keygen/peer-keypair" ? json({ public_key: "peer-public", private_key: "peer-private" }) : json({}));
  await userEvent.click(screen.getByRole("button", { name: "+ Добавить туннель" }));
  await userEvent.click(screen.getByRole("button", { name: "Поднять сервер" }));
  await userEvent.click(screen.getByRole("button", { name: "Продолжить" }));
  const editor = await screen.findByRole("dialog", { name: /Туннель:/ });
  fill(editor, "Имя туннеля", "fresh");
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  await userEvent.click(within(editor).getByRole("button", { name: "+ Добавить пира" }));
  const peer = await screen.findByRole("dialog", { name: "Пир: Новый пир" });
  fill(peer, "Имя пира", "newpeer");
  await userEvent.click(within(peer).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: /Пир:/ })).not.toBeInTheDocument());
  const row = peerRow(editor, "newpeer");
  expect(within(row).getByRole("button", { name: "QR" })).toBeDisabled();
  expect(within(row).getByRole("button", { name: "Экспорт конфигурации" })).toBeDisabled();
  expect(fetch.mock.calls.filter(([path]) => /\/peer\/.*\/(qr|conf)$/.test(path))).toHaveLength(0);
});

it("criterion_7_nested_cancel_discards_changes_nested_save_only_updates_outer_draft_outer_cancel_discards", async () => {
  const fetch = await mount();
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Изменить" }));
  let peer = screen.getByRole("dialog", { name: "Пир: phone" });
  for (const label of ["Имя пира", "Публичный ключ пира", "AllowedIPs пира", "Preshared key", "Приватный ключ пира (входит в клиентский конфиг)"])
    expect(within(peer).getByLabelText(label)).toBeVisible();
  expect(within(peer).getByLabelText("Preshared key")).toHaveValue("");
  fill(peer, "AllowedIPs пира", "10.9.0.2/32");
  await userEvent.click(within(peer).getByRole("button", { name: "Отмена" }));
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Изменить" }));
  peer = screen.getByRole("dialog", { name: "Пир: phone" });
  expect(within(peer).getByLabelText("AllowedIPs пира")).toHaveValue("10.66.66.2/32");
  fill(peer, "AllowedIPs пира", "10.9.0.2/32");
  await userEvent.click(within(peer).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Пир: phone" })).not.toBeInTheDocument());
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  await userEvent.click(within(editor).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  const reopened = await openPeers();
  await userEvent.click(within(peerRow(reopened, "phone")).getByRole("button", { name: "Изменить" }));
  expect(within(screen.getByRole("dialog", { name: "Пир: phone" })).getByLabelText("AllowedIPs пира")).toHaveValue("10.66.66.2/32");
});

it("criterion_7_nested_save_preserves_other_peers_and_redacted_secrets_on_outer_save", async () => {
  const fetch = await mount();
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Изменить" }));
  const peer = screen.getByRole("dialog", { name: "Пир: phone" });
  fill(peer, "AllowedIPs пира", "10.9.0.2/32");
  await userEvent.click(within(peer).getByRole("button", { name: "Сохранить" }));
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0].peers).toEqual([{ ...phone, allowed_ips: ["10.9.0.2/32"] }, laptop]);
});

it("criterion_7_peer_keygen_and_psk_replace_only_selected_peer_on_nested_save", async () => {
  const fetch = await mount(config(), (path) => path === "/api/keygen/peer-keypair"
    ? json({ public_key: "replacement-public", private_key: "replacement-private" })
    : path === "/api/keygen/peer" ? json({ preshared_key: "replacement-psk" }) : json({}));
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Изменить" }));
  const peer = screen.getByRole("dialog", { name: "Пир: phone" });
  await userEvent.click(within(peer).getByRole("button", { name: "Сгенерировать ключи пира" }));
  await waitFor(() => expect(within(peer).getByLabelText("Публичный ключ пира")).toHaveValue("replacement-public"));
  expect(within(peer).getByLabelText("Приватный ключ пира (входит в клиентский конфиг)")).toHaveValue("replacement-private");
  await userEvent.click(within(peer).getByRole("button", { name: "Сгенерировать PSK" }));
  await waitFor(() => expect(within(peer).getByLabelText("Preshared key")).toHaveValue("replacement-psk"));
  expect(fetch).toHaveBeenCalledWith("/api/keygen/peer", expect.objectContaining({ method: "POST", body: "{}" }));
  await userEvent.click(within(peer).getByRole("button", { name: "Сохранить" }));
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0].peers).toEqual([
    { ...phone, public_key: "replacement-public", private_key: { plaintext: "replacement-private" }, preshared_key: { plaintext: "replacement-psk" } },
    laptop,
  ]);
});

it("criterion_7_late_keygen_after_cancel_never_modifies_next_peer", async () => {
  const pending = deferred<Response>();
  const fetch = await mount(config(), (path) => path === "/api/keygen/peer-keypair" ? pending.promise : json({}));
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Изменить" }));
  const first = screen.getByRole("dialog", { name: "Пир: phone" });
  await userEvent.click(within(first).getByRole("button", { name: "Сгенерировать ключи пира" }));
  await userEvent.click(within(first).getByRole("button", { name: "Отмена" }));
  await userEvent.click(within(peerRow(editor, "laptop")).getByRole("button", { name: "Изменить" }));
  const second = screen.getByRole("dialog", { name: "Пир: laptop" });
  await act(async () => { pending.resolve(json({ public_key: "late-key", private_key: "late-secret" })); });
  expect(within(second).getByLabelText("Публичный ключ пира")).toHaveValue("laptop-public");
  await userEvent.click(within(second).getByRole("button", { name: "Сохранить" }));
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0].peers).toEqual([phone, laptop]);
});

it("criterion_7_delete_confirmation_only_affects_outer_draft_after_outer_save", async () => {
  const fetch = await mount();
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Изменить" }));
  const peer = screen.getByRole("dialog", { name: "Пир: phone" });
  await userEvent.click(within(peer).getByRole("button", { name: /Удалить пира phone/ }));
  const confirm = screen.getByRole("dialog", { name: /Удалить пира/ });
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  await userEvent.click(within(confirm).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Удалить пира?" })).not.toBeInTheDocument());
  expect(within(peer).getByLabelText("Публичный ключ пира")).toHaveValue("phone-public");
  await userEvent.click(within(peer).getByRole("button", { name: /Удалить пира phone/ }));
  await userEvent.click(within(screen.getByRole("dialog", { name: /Удалить пира/ })).getByRole("button", { name: "Удалить из черновика" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Пир: phone" })).not.toBeInTheDocument());
  expect(within(editor).queryByText("phone")).not.toBeInTheDocument();
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0].peers).toEqual([laptop]);
});

it("criterion_8_no_peer_qr_action_in_page_list_before_opening_editor", async () => {
  const fetch = await mount();
  expect(screen.queryByRole("button", { name: "QR" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "QR-код" })).not.toBeInTheDocument();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(fetch.mock.calls.some(([path]) => path.endsWith("/qr"))).toBe(false);
});

it("criterion_9_activity_query_is_enabled_only_on_open_server_peers_and_forwards_abort_signal", async () => {
  const fetch = await mount(config(), (path) => path === "/api/tunnels/activity" ? json({ vpn: { phone: 0, laptop: 1_700_000_000 } }) : json({}));
  expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(0);
  const editor = await openServer();
  expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(0);
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  await waitFor(() => expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(1));
  expect(calls(fetch, "/api/tunnels/activity")[0][1]).toEqual(expect.objectContaining({ credentials: "include", signal: expect.any(AbortSignal) }));
  expect(within(peerRow(editor, "phone")).getByText("Не подключался")).toBeVisible();
  expect(within(peerRow(editor, "laptop")).getByText(new Date(1_700_000_000 * 1000).toLocaleString("ru-RU"))).toBeVisible();
  await userEvent.click(within(editor).getByRole("tab", { name: "Туннель" }));
  await userEvent.click(within(editor).getByRole("button", { name: "Отмена" }));
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
});

it("criterion_9_polling_stops_on_tunnel_tab_and_after_editor_close", async () => {
  const fetch = await mount(config(), (path) => path === "/api/tunnels/activity"
    ? json({ vpn: { phone: 0 } }) : json({}));
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  try {
    const editor = await openPeers();
    expect(await within(peerRow(editor, "phone")).findByText("Не подключался")).toBeVisible();
    expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(1);
    await userEvent.click(within(editor).getByRole("tab", { name: "Туннель" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(1);
    await userEvent.click(within(editor).getByRole("button", { name: "Отмена" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(1);
  } finally { vi.useRealTimers(); }
});

it("criterion_9_activity_poll_rechecks_after_30000ms_and_failed_refetch_hides_cached_success", async () => {
  let attempt = 0;
  const fetch = await mount(config(), (path) => path === "/api/tunnels/activity"
    ? ++attempt === 1 ? json({ vpn: { phone: 1_700_000_000 } }) : json({ code: "activity.failed", message: "Нет телеметрии" }, 503)
    : json({}));
  const prior = new Date(1_700_000_000 * 1000).toLocaleString("ru-RU");
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  try {
    const editor = await openPeers();
    expect(await within(peerRow(editor, "phone")).findByText(prior)).toBeVisible();
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(calls(fetch, "/api/tunnels/activity")).toHaveLength(2);
    // A failed poll must not reuse its previous timestamp.
    await waitFor(() => expect(within(peerRow(editor, "phone")).getByText("Активность недоступна")).toBeVisible());
    expect(within(editor).queryByText(prior)).not.toBeInTheDocument();
    expect(within(editor).getByRole("table")).toBeVisible();
  } finally { vi.useRealTimers(); }
});

it("criterion_9_activity_null_missing_zero_and_invalid_values_are_honest", async () => {
  await mount(config([{ ...server, peers: [phone, laptop, { ...laptop, name: "missing" }, { ...laptop, name: "invalid" }] }]),
    (path) => path === "/api/tunnels/activity" ? json({ vpn: { phone: null, laptop: 0, invalid: -1 } }) : json({}));
  const editor = await openPeers();
  await within(peerRow(editor, "laptop")).findByText("Не подключался");
  for (const name of ["phone", "missing", "invalid"])
    expect(within(peerRow(editor, name)).getByText("Активность недоступна")).toBeVisible();
});

it("criterion_10_no_fabricated_activity_while_loading_or_after_failed_request", async () => {
  const pending = deferred<Response>();
  const fetch = await mount(config(), (path) => path === "/api/tunnels/activity" ? pending.promise : json({}));
  const editor = await openPeers();
  expect(within(peerRow(editor, "phone")).getByText("Активность недоступна")).toBeVisible();
  expect(within(editor).queryByText("Не подключался")).not.toBeInTheDocument();
  await act(async () => { pending.resolve(json({ code: "activity.failed", message: "Нет телеметрии" }, 503)); });
  await waitFor(() => expect(calls(fetch, "/api/tunnels/activity").length).toBeGreaterThanOrEqual(1));
  expect(within(peerRow(editor, "phone")).getByText("Активность недоступна")).toBeVisible();
  expect(within(editor).getByRole("tab", { name: "Пиры" })).toBeVisible();
});

it("criterion_11_amnezia_export_downloads_the_vpn_document", async () => {
  const create = vi.fn((_blob: Blob) => "blob:peer-vpn");
  const revoke = vi.fn();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toBe("vpn-phone.vpn");
    expect(this.href).toBe("blob:peer-vpn");
  });
  const fetch = await mount(config([server]), (path) => path.endsWith("/amnezia")
    ? new Response("vpn://AAAA", { headers: { "Content-Type": "text/plain; charset=utf-8" } }) : json({}));
  const editor = await openPeers();
  await userEvent.click(within(peerRow(editor, "phone")).getByRole("button", { name: "Для Amnezia" }));
  await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
  expect(fetch).toHaveBeenCalledWith("/api/tunnels/vpn/peer/phone/amnezia", expect.objectContaining({ credentials: "include" }));
  expect(revoke).toHaveBeenCalledWith("blob:peer-vpn");
  click.mockRestore();
});

it("criterion_11_amnezia_export_is_disabled_for_a_wireguard_tunnel", async () => {
  const wireguard: Tunnel = { ...server, protocol: "wg", obfuscation: {} };
  const fetch = await mount(config([wireguard]));
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const view = screen.getByRole("dialog", { name: /Туннель: vpn/ });
  await userEvent.click(within(view).getByRole("button", { name: "Изменить" }));
  const editor = screen.getByRole("dialog", { name: /Туннель: vpn/ });
  await userEvent.click(within(editor).getByRole("tab", { name: "Пиры" }));
  expect(within(peerRow(editor, "phone")).getByRole("button", { name: "Для Amnezia" })).toBeDisabled();
  expect(fetch.mock.calls.filter(([path]) => /\/amnezia$/.test(path as string))).toHaveLength(0);
});

it("criterion_12_a_new_awg_tunnel_takes_the_generated_profile_and_port", async () => {
  const profile = {
    Jc: 5, Jmin: 20, Jmax: 60, S1: 30, S2: 40, S3: 50, S4: 60,
    H1: 11, H2: 22, H3: 33, H4: 44, I1: "<b 0xaabb><r 3>", I5: "<rc 8>",
    ContentPaddingAddition: "10-100", RekeyAfterTime: "100-120", RekeyTimeout: "3-7",
    RejectAfterTime: "150-180", KeepaliveTimeout: "5-15", MaxHandshakeAttempts: "15-20",
  };
  const fetch = await mount(config([]), (path) => path === "/api/keygen/tunnel"
    ? json({ public_key: "server-public", private_key: "server-private", obfuscation: profile,
             header_protection_key: "HPK=", random_trailers: true, disable_cookies: true,
             listen_port: 41234 })
    : json({}));
  await userEvent.click(screen.getByRole("button", { name: "+ Добавить туннель" }));
  const scenario = await screen.findByRole("dialog", { name: "Новый туннель" });
  await userEvent.selectOptions(within(scenario).getByLabelText("Протокол нового туннеля"), "awg");
  await userEvent.click(within(scenario).getByRole("button", { name: "Поднять сервер" }));
  await userEvent.click(within(scenario).getByRole("button", { name: "Продолжить" }));
  const editor = await screen.findByRole("dialog", { name: /Туннель:/ });
  fill(editor, "Имя туннеля", "maxsec");
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  const tunnel = saved(fetch).tunnels[0];
  // The defaults the Amnezia app rates "базовая" are exactly what must not ship.
  expect(tunnel.listen_port).toBe(41234);
  expect(tunnel.random_trailers).toBe(true);
  expect(tunnel.disable_cookies).toBe(true);
  expect(tunnel.header_protection_key).toEqual({ plaintext: "HPK=" });
  expect(tunnel.obfuscation).toEqual(profile);
});

it("client_without_default_route_saves_explicit_false", async () => {
  const client: Tunnel = {
    ...server, role: "client", peers: [], endpoint: "remote.example:51820",
    server_public_key: "remote-public", allowed_ips: ["0.0.0.0/0", "::/0"],
  };
  const fetch = await mount(config([client]));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const view = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  await userEvent.click(within(view).getByRole("button", { name: "Изменить" }));
  const editor = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  expect(within(editor).getByRole("checkbox", { name: "Использовать туннель как маршрут по умолчанию" })).not.toBeChecked();
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0]).toMatchObject({ default_route: false, allowed_ips: ["0.0.0.0/0", "::/0"] });
});

it("client_default_route_is_opt_in_saved_and_reloaded_without_changing_allowed_ips", async () => {
  const client: Tunnel = {
    ...server,
    role: "client",
    peers: [],
    endpoint: "remote.example:51820",
    server_public_key: "remote-public",
    allowed_ips: ["0.0.0.0/0", "::/0"],
    default_route: undefined,
  };
  const fetch = await mount(config([client]));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const view = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  await userEvent.click(within(view).getByRole("button", { name: "Изменить" }));
  let editor = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  const toggle = within(editor).getByRole("checkbox", { name: "Использовать туннель как маршрут по умолчанию" });
  expect(toggle).not.toBeChecked();
  expect(within(editor).queryByText("Весь трафик хоста, включая доступ к панели и SSH, пойдёт через туннель.")).not.toBeInTheDocument();
  await userEvent.click(toggle);
  expect(within(editor).getByText("Весь трафик хоста, включая доступ к панели и SSH, пойдёт через туннель.")).toBeVisible();
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(1));
  expect(saved(fetch).tunnels[0]).toMatchObject({ default_route: true, allowed_ips: ["0.0.0.0/0", "::/0"] });

  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const reopenedView = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  await userEvent.click(within(reopenedView).getByRole("button", { name: "Изменить" }));
  editor = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Клиент" });
  expect(within(editor).getByRole("checkbox", { name: "Использовать туннель как маршрут по умолчанию" })).toBeChecked();
  expect(within(editor).getByText("Весь трафик хоста, включая доступ к панели и SSH, пойдёт через туннель.")).toBeVisible();
  await userEvent.click(within(editor).getByRole("checkbox", { name: "Использовать туннель как маршрут по умолчанию" }));
  expect(within(editor).queryByText("Весь трафик хоста, включая доступ к панели и SSH, пойдёт через туннель.")).not.toBeInTheDocument();
  await userEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls(fetch, "/api/draft")).toHaveLength(2));
  const secondSave = JSON.parse(String(calls(fetch, "/api/draft")[1][1]?.body)) as Configuration;
  expect(secondSave.tunnels[0]).toMatchObject({ default_route: false, allowed_ips: ["0.0.0.0/0", "::/0"] });
});

it("criterion_13_peer_tab_states_that_a_peer_goes_live_without_an_apply", async () => {
  const fetch = await mount();
  const editor = await openPeers();
  expect(within(editor).getByText(/применяются на работающем туннеле сразу при сохранении/)).toBeVisible();
  expect(within(editor).getByText(/только после применения/)).toBeVisible();
  expect(calls(fetch, "/api/draft")).toHaveLength(0);
});
