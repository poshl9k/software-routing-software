import { useRef, useState, type ReactNode } from "react";
import { Button, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";
import { useConfiguration } from "../state";
import type {
  Tunnel,
  Peer,
  CaddySite,
  DDNSUpdate,
  Configuration,
  Interface,
  Secret,
} from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { ErrorNotice } from "../components/ErrorNotice";
import { EditorShell } from "../components/EditorShell";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InlineStatus } from "../components/InlineStatus";
import { InfoNote } from "../components/InfoNote";
import { EmptyState } from "../components/EmptyState";
import { PageTabs } from "../components/Tabs";
import { Field } from "../components/Field";
import { FormActions, FormGrid, FormWide } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { Select, SelectField, InterfaceSelect } from "../components/Select";
import { Toggle } from "../components/Toggle";
import {
  nameValid,
  ifaceNameValid,
  hostValid,
  secretValid,
  portValid,
  addressValid,
  normalize,
} from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { api } from "../api";
import { parseWireGuardConf } from "../tunnelConf";

const ipsValid = (v: string[]) =>
  v.filter((s) => s.trim()).every((s) => addressValid(s.trim()));
const split = (v: string) => v.split(",");
const awgRequired = ["Jc", "S1", "S2", "H1", "H2", "H3", "H4"];
const awgFields = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];
const certificateModeLabels: Record<CaddySite["certificate_mode"], string> = {
  http01: "Авто (HTTP-01)",
  dns01: "Авто (DNS-01)",
  manual: "Ручной",
  passthrough: "TLS passthrough (SNI)",
};

/** First free tunnel device name (tun0, tun1, …), never colliding with a
 * declared interface or a physical host NIC name. */
function nextTunnelInterface(names: Iterable<string>): string {
  const taken = new Set(names);
  let index = 0;
  while (taken.has(`tun${index}`)) index += 1;
  return `tun${index}`;
}

/** Placeholder interface shown in the picker for a device that will be created
 * on save (it does not exist in the configuration yet). */
function pendingInterface(name: string, description: string | null): Interface {
  return {
    name,
    type: "physical",
    zone: "lan",
    description,
    addressing: "static",
    addresses: [],
    parent: null,
    vlan_id: null,
    members: [],
  };
}

/** Names that must keep their interface: referenced by another interface
 * (bridge member / VLAN parent), DHCP, port-forward, DNS, DDNS, SSH, TProxy, or
 * an edited tunnel. */
function referencedInterfaces(configuration: Configuration, tunnels: Tunnel[]): Set<string> {
  const used = new Set<string>();
  for (const iface of configuration.interfaces) {
    if (iface.parent) used.add(iface.parent);
    for (const member of iface.members) used.add(member);
  }
  for (const subnet of configuration.dhcp_subnets) used.add(subnet.interface);
  for (const forward of configuration.port_forwards) used.add(forward.interface);
  for (const name of configuration.dns.interfaces) used.add(name);
  for (const job of configuration.ddns) used.add(job.wan_interface);
  for (const name of configuration.ssh.interfaces) used.add(name);
  for (const name of configuration.ssh.wan_confirmed_interfaces) used.add(name);
  for (const name of configuration.tproxy.ingress_interfaces) used.add(name);
  for (const tunnel of tunnels) if (tunnel.interface) used.add(tunnel.interface);
  return used;
}

/** Tunnel devices the editor owns are named `tun<N>`. */
const AUTO_TUNNEL_NAME = /^tun\d+$/;

// Deterministic pool mirrored from backend vs_router/generators/wireguard.py:
// the Nth tunnel (by name) owns 10.66.<66+N>.0/24; a server is .1, a client .2.
const TUNNEL_SUBNET_BASE = 66;

function tunnelSlot(tunnels: Tunnel[], name: string): number {
  return [...tunnels]
    .map((t) => t.name)
    .sort()
    .indexOf(name);
}

/** The tunnel device's own address (server .1, client .2). */
function tunnelAddress(tunnel: Tunnel, tunnels: Tunnel[]): string {
  const host = tunnel.role === "server" ? 1 : 2;
  return `10.66.${TUNNEL_SUBNET_BASE + tunnelSlot(tunnels, tunnel.name)}.${host}/24`;
}

/** Effective IPv4 network (`a.b.c`) for peer allocation: the declared
 * interface address when set, else the derived tunnel address. */
function tunnelNetwork(
  tunnel: Tunnel,
  interfaces: Interface[],
  tunnels: Tunnel[],
): string | null {
  const declared = interfaces.find((i) => i.name === tunnel.interface)?.addresses[0];
  const match = /^(\d+\.\d+\.\d+)\.\d+\/\d+$/.exec(declared ?? tunnelAddress(tunnel, tunnels));
  return match ? match[1] : null;
}

/** A server peer's automatic /32 (the next free host, .2, .3, … in name order). */
function peerAutoAddress(
  tunnel: Tunnel,
  peer: Peer,
  interfaces: Interface[],
  tunnels: Tunnel[],
): string | null {
  const network = tunnelNetwork(tunnel, interfaces, tunnels);
  if (!network) return null;
  const order = [...tunnel.peers]
    .map((p) => p.name)
    .sort();
  return `${network}.${2 + order.indexOf(peer.name)}/32`;
}

/** Materialize the automatic addresses into the configuration (so the panel
 * shows them and the operator can edit them). Explicit values always win. */
function materializeTunnels(configuration: Configuration, rows: Tunnel[]): Tunnel[] {
  return rows.map((tunnel) => {
    if (tunnel.role !== "server") return tunnel;
    const peers: Peer[] = tunnel.peers.map((peer) => {
      if (peer.allowed_ips.length) return peer;
      const address = peerAutoAddress(tunnel, peer, configuration.interfaces, rows);
      return address ? { ...peer, allowed_ips: [address] } : peer;
    });
    return peers.some((peer, index) => peer !== tunnel.peers[index])
      ? { ...tunnel, peers }
      : tunnel;
  });
}

/** Keep the configuration's tunnel devices in sync with the edited tunnels:
 * create/fill a LAN-zone interface for each tunnel (with its automatic address),
 * and drop an orphaned auto-created device (`tun<N>` no longer owned by a tunnel
 * or referenced anywhere). An operator-declared interface is never removed. */
function reconcileTunnelInterfaces(configuration: Configuration, tunnels: Tunnel[]): Interface[] {
  const referenced = referencedInterfaces(configuration, tunnels);
  const byName = new Map(configuration.interfaces.map((i) => [i.name, i]));
  const result = configuration.interfaces.filter(
    (iface) => !(AUTO_TUNNEL_NAME.test(iface.name) && !referenced.has(iface.name)),
  );
  for (const tunnel of tunnels) {
    if (!tunnel.interface) continue;
    const description = tunnelDescription(tunnel);
    const address = tunnelAddress(tunnel, tunnels);
    const existing = byName.get(tunnel.interface);
    if (!existing) {
      const created = {
        ...pendingInterface(tunnel.interface, description),
        addresses: [address],
      };
      byName.set(tunnel.interface, created);
      result.push(created);
      continue;
    }
    const patch: Partial<Interface> = {};
    if (!existing.description && description) patch.description = description;
    // Fill the tunnel's own address once so it is visible; never for a DHCP
    // interface (addresses there are forbidden).
    if (!existing.addresses.length && existing.addressing === "static") {
      patch.addresses = [address];
    }
    if (Object.keys(patch).length) {
      const updated = { ...existing, ...patch };
      byName.set(tunnel.interface, updated);
      const index = result.indexOf(existing);
      if (index >= 0) result[index] = updated;
    }
  }
  return result;
}

/** Interface description for an auto-created tunnel device (the tunnel name). */
function tunnelDescription(tunnel: Tunnel): string | null {
  const name = tunnel.name.trim().slice(0, 64);
  return name || null;
}
export function SecretField({
  label,
  value,
  change,
  showOriginalHint = true,
}: {
  label: string;
  value: Secret | null;
  change: (s: Secret | null) => void;
  showOriginalHint?: boolean;
}) {
  // An empty replacement restores the original opaque value, without displaying it.
  const [original] = useState(value && !("plaintext" in value) ? value : null);
  return (
    <Field
      label={label}
      type="password"
      autoComplete="new-password"
      value={value && "plaintext" in value ? value.plaintext : ""}
      hint={
        original && showOriginalHint
          ? "(сохранён); пустое поле сохраняет прежний секрет"
          : "Новый секрет"
      }
      onChange={(v) => change(v ? { plaintext: v } : original)}
    />
  );
}
type Row = Tunnel | CaddySite | DDNSUpdate;
interface EditableRow<T> {
  id: number;
  created: boolean;
  row: T;
}
function Collection<T extends Row>({
  kind,
  title,
  addLabel,
  empty,
  create,
  valid,
  form,
  summary,
  clean = (v) => v,
  rowActions,
  configPatch,
  importRow,
}: {
  kind: "tunnels" | "sites" | "ddns";
  title: string;
  addLabel: string;
  empty: (rows: T[]) => T;
  create?: (rows: T[], role: Tunnel["role"], protocol: Tunnel["protocol"]) => Promise<T>;
  valid: (v: T) => boolean;
  clean?: (v: T) => T;
  form: (v: T, patch: (p: Partial<T>) => void, created: boolean, noConfiguration: boolean, setError: (error: unknown) => void, tab: number, importedAddresses: Record<string, string>) => ReactNode;
  summary: (v: T) => ReactNode[];
  rowActions?: (row: T) => ReactNode;
  /** Extra configuration derived from the edited rows (e.g. auto-created
   * tunnel interfaces). Merged into the whole-configuration save. */
  configPatch?: (rows: T[], importedAddresses: Record<string, string>) => Partial<Configuration>;
  importRow?: (text: string, rows: T[]) => { row?: T; error?: string; address?: string };
}) {
  const { configuration: c, version, noConfiguration } = useConfiguration();
  const editor = useDraftEditor<EditableRow<T>[]>();
  const [next, setNext] = useState(0);
  const [creating, setCreating] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importAddresses, setImportAddresses] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState(false);
  const [scenario, setScenario] = useState<"client" | "server" | null>(null);
  const [protocol, setProtocol] = useState<Tunnel["protocol"]>("wg");
  const [selected, setSelected] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<number | null>(null);
  const [tab, setTab] = useState(0);
  const creatingRef = useRef(false);
  const editEpoch = useRef(0);
  const currentEditing = useRef<EditableRow<T>[] | null>(null);
  const collection = c[kind] as T[];
  const editing = editor.value;
  currentEditing.current = editing;
  const isEdit = editor.isEdit;
  const allValid =
    !!editing &&
    editing.every(({ row }) => valid(row)) &&
    new Set(editing.map((v) => v.row.name)).size === editing.length;
  const save = () =>
    editor.save((value) => {
      const rows = value.map((v) => clean(v.row));
      return {
        ...c,
        tunnels: c.tunnels,
        sites: c.sites,
        ddns: c.ddns,
        [kind]: rows,
        ...(configPatch ? configPatch(rows, importAddresses) : {}),
      };
    });
  const add = async (role: Tunnel["role"] = "server", chosenProtocol: Tunnel["protocol"] = "wg") => {
    const initial = editing ?? currentEditing.current;
    if (!initial || creatingRef.current) return;
    const id = Math.max(next, initial.reduce((max, item) => Math.max(max, item.id + 1), 0));
    if (!create) {
      editor.setValue([...initial, { id, created: true, row: empty(initial.map((v) => v.row)) }]);
      setSelected(id);
      setNext(id + 1);
      return;
    }
    creatingRef.current = true;
    setCreating(true);
    const epoch = editEpoch.current;
    try {
      const row = await create(initial.map((v) => v.row), role, chosenProtocol);
      const latest = currentEditing.current;
      if (epoch === editEpoch.current && latest) {
        editor.setValue([...latest, { id, created: true, row }]);
        setSelected(id);
        setTab(0);
        setNext(id + 1);
        setScenario(null);
      }
    } catch (error) {
      if (epoch === editEpoch.current) editor.setError(error);
    } finally {
      creatingRef.current = false;
      setCreating(false);
    }
  };
  const closeImport = () => {
    setImportOpen(false);
    setImportText("");
    setImportError(null);
    setPreview(false);
  };
  const parsedImport = importText.trim() && importRow
    ? importRow(importText, (currentEditing.current ?? collection.map((row, id) => ({ id, created: false, row }))).map(({ row }) => row))
    : null;
  const submitImport = () => {
    if (!importText.trim()) {
      setImportError("Вставьте содержимое .conf");
      return;
    }
    if (!preview) { setPreview(true); return; }
    const rows = currentEditing.current ?? collection.map((row, id) => ({ id, created: false, row }));
    const result = parsedImport;
    if (!result?.row) {
      setImportError(result?.error ?? "Не удалось импортировать .conf");
      return;
    }
    const id = rows.reduce((max, item) => Math.max(max, item.id + 1), 0);
    if (result.address && "interface" in result.row) setImportAddresses((old) => ({ ...old, [String((result.row as Tunnel).interface)]: result.address! }));
    setSelected(id);
    setTab(0);
    if (!isEdit) {
      editEpoch.current += 1;
      editor.begin([...rows, { id, created: true, row: result.row }]);
    } else {
      editor.setValue([...rows, { id, created: true, row: result.row }]);
    }
    setNext(id + 1);
    closeImport();
  };
  return (
    <>
      <ErrorNotice error={editor.error} />
      <Card
        title={title}
        action={
          <div className="toolbar-actions">
            {importRow && (
              <Button disabled={!version} onClick={() => setImportOpen(true)}>
                Импорт .conf
              </Button>
            )}
            {kind === "tunnels" && !isEdit && <Button disabled={!version} onClick={() => setScenario("client")}>{addLabel}</Button>}
            {!isEdit && kind !== "tunnels" && (
              <Button
                disabled={!version}
                onClick={() => {
                  editEpoch.current += 1;
                  editor.begin(collection.map((row, id) => ({ id, created: false, row })));
                  setNext(collection.length);
                }}
              >
                Редактировать
              </Button>
            )}
          </div>
        }
      >
        <EditorShell
          isEdit={isEdit}
          saving={editor.saving}
          valid={!!allValid && !!version && !creating}
          onCancel={() => {
            editEpoch.current += 1;
            editor.cancel();
          }}
          onSave={() => void save()}
          view={kind === "tunnels" ? (
            collection.length ? collection.map((row, id) => {
              const tunnel = row as Tunnel;
              return <Card key={id} title={`${tunnel.name} · ${tunnel.protocol === "wg" ? "WireGuard" : "AmneziaWG"} · ${tunnel.role === "server" ? "Сервер" : "Клиент"}`}
                action={<Button disabled={!version} onClick={() => {
                  editor.begin(collection.map((item, index) => ({ id: index, created: false, row: item })));
                  setNext(collection.length); setSelected(id); setTab(0);
                }}>Открыть</Button>}>
                <p>Интерфейс: {tunnel.interface}</p>
                <p>{tunnel.role === "server" ? `Клиентов: ${tunnel.peers.length}` : `Endpoint: ${tunnel.endpoint ?? "не задан"}`}</p>
                <InlineStatus tone="unknown" text="Состояние недоступно" />
              </Card>;
            }) : <EmptyState title="Туннелей пока нет">Добавьте туннель или импортируйте клиентский .conf.</EmptyState>
          ) : (
            <DataTable
              heads={kind === "sites"
                ? ["Имя", "Hostname", "Upstream", "Сертификат", "Статус"]
                : ["Имя", "Провайдер", "Hostname", "Статус"]}
              rows={collection.map((row) => {
                const cells = summary(row);
                if (rowActions) cells.push(noConfiguration ? null : rowActions(row));
                return cells;
              })}
            />
          )}
          edit={() =>
            editing ? (
              <>
                {kind === "tunnels" && <PageTabs values={((editing.find((v) => v.id === selected)?.row as Tunnel | undefined)?.role === "server")
                  ? ["Общие", "Подключение", "Ключи", "Клиенты", "Дополнительно"]
                  : ["Общие", "Подключение", "Ключи", "Дополнительно"]} value={tab} change={setTab} />}
                {editing.filter(({ id }) => kind !== "tunnels" || id === selected).map(({ id, row, created }) => (
                  <Card
                    key={id}
                    title={row.name || "Новая запись"}
                    action={
                      <DeleteButton
                        label={`Удалить ${row.name || "запись"}`}
                        onClick={() => kind === "tunnels" ? setDeleteTarget(id) : editor.setValue(editing.filter((v) => v.id !== id))}
                      />
                    }
                  >
                    {form(
                      row,
                      (patch) => {
                        const latest = currentEditing.current;
                        if (!latest?.some((v) => v.id === id)) return;
                        const updated = latest.map((v) =>
                          v.id === id
                            ? { ...v, row: { ...v.row, ...patch } }
                            : v,
                        );
                        currentEditing.current = updated;
                        editor.setValue(updated);
                      },
                      created,
                      noConfiguration,
                      editor.setError,
                      tab,
                      importAddresses,
                    )}
                  </Card>
                ))}
                {kind !== "tunnels" && <FormActions>
                  <Button disabled={creating} onClick={() => void add()}>
                    {addLabel}
                  </Button>
                </FormActions>}
                {kind === "tunnels" && (() => {
                  const tunnel = editing.find((item) => item.id === selected)?.row as Tunnel | undefined;
                  if (!tunnel) return <InfoNote>Сохранение удалит выбранный туннель только из черновика. Изменения вступят в силу после применения.</InfoNote>;
                  const address = importAddresses[tunnel.interface] ?? c.interfaces.find((i) => i.name === tunnel.interface)?.addresses[0] ?? tunnelAddress(tunnel, editing.map((v) => v.row as Tunnel));
                  return <InfoNote>При сохранении: {tunnel.name || "новый туннель"} · {tunnel.role === "server" ? "сервер" : "клиент"} · {tunnel.protocol === "awg" ? "AmneziaWG" : "WireGuard"}; интерфейс {tunnel.interface} ({c.interfaces.some((i) => i.name === tunnel.interface) ? "существующий" : "будет создан"}, зона LAN), адрес {address}; WAN UDP-порт {tunnel.role === "server" && tunnel.open_port ? `${tunnel.listen_port} будет открыт после применения` : "не открывается"}. Сохранение создаёт только черновик.</InfoNote>;
                })()}
                {!allValid && (
                  <p role="status">
                    Проверьте обязательные поля, формат значений и уникальность
                    имён.
                  </p>
                )}
              </>
            ) : null
          }
        />
      </Card>
      {kind === "tunnels" && <ConfirmDialog open={deleteTarget !== null} title="Удалить туннель?"
        body="Туннель, его клиенты и автоматически созданный интерфейс будут удалены из черновика. Проверьте зависимости перед применением."
        confirmLabel="Удалить из черновика" cancelLabel="Отмена" danger
        onCancel={() => setDeleteTarget(null)} onConfirm={() => {
          const remaining = (currentEditing.current ?? []).filter((v) => v.id !== deleteTarget);
          currentEditing.current = remaining; editor.setValue(remaining); setSelected(null); setDeleteTarget(null);
        }} />}
      {kind === "tunnels" && <Dialog open={scenario !== null} onClose={() => setScenario(null)} fullWidth aria-labelledby="scenario-title">
        <DialogTitle id="scenario-title">Новый туннель</DialogTitle>
        <DialogContent>
          <FormGrid>
            <FormWide><Button onClick={() => { setScenario(null); setImportOpen(true); }}>Импортировать клиентский .conf</Button></FormWide>
            <Button variant={scenario === "client" ? "contained" : "text"} onClick={() => setScenario("client")}>Подключиться как клиент</Button>
            <Button variant={scenario === "server" ? "contained" : "text"} onClick={() => setScenario("server")}>Поднять сервер</Button>
            <Select label="Протокол нового туннеля" value={protocol} options={[{ value: "wg", label: "WireGuard" }, { value: "awg", label: "AmneziaWG" }]} onChange={(v) => setProtocol(v as Tunnel["protocol"])} />
          </FormGrid>
          <InfoNote>До сохранения ничего не создаётся. Сохранение создаёт только черновик; серверный WAN-порт по умолчанию закрыт.</InfoNote>
        </DialogContent>
        <DialogActions><Button onClick={() => setScenario(null)}>Отмена</Button><Button disabled={creating} onClick={() => {
          if (!isEdit) { const rows = collection.map((row, id) => ({ id, created: false, row })); currentEditing.current = rows; editor.begin(rows); setNext(collection.length); }
          void add(scenario ?? "client", protocol);
        }}>Продолжить</Button></DialogActions>
      </Dialog>}
      {importRow && (
        <Dialog open={importOpen} onClose={closeImport} fullWidth maxWidth="sm" aria-labelledby="tunnel-conf-import-title">
          <DialogTitle id="tunnel-conf-import-title">Импорт .conf</DialogTitle>
          <DialogContent>
            <FormGrid>
              <FormWide>
                <Field label="Содержимое .conf" multiline value={importText}
                  onChange={(text) => { setImportText(text); setImportError(null); setPreview(false); }} />
              </FormWide>
            </FormGrid>
            {preview && parsedImport?.error && <ErrorNotice error={new Error(parsedImport.error)} />}
            {preview && parsedImport?.row && <InfoNote>Распознано: клиент · {(parsedImport.row as Tunnel).protocol === "awg" ? "AmneziaWG" : "WireGuard"}; endpoint {(parsedImport.row as Tunnel).endpoint}; AllowedIPs {(parsedImport.row as Tunnel).allowed_ips.join(", ")}; Address {parsedImport.address ?? "отсутствует — будет назначен автоматически"}; PSK отсутствует. Приватный ключ скрыт. Сохранение создаёт только черновик.</InfoNote>}
            <ErrorNotice error={importError ? new Error(importError) : null} />
          </DialogContent>
          <DialogActions>
            <Button onClick={closeImport}>Отмена</Button>
            <Button onClick={submitImport}>{preview ? "Добавить в черновик" : "Показать распознанные поля"}</Button>
          </DialogActions>
        </Dialog>
      )}
    </>
  );
}
export function Tunnels() {
  const { configuration: c } = useConfiguration();
  const [qr,setQr]=useState<{peer:string;url:string}|null>(null); const [qrError,setQrError]=useState<unknown>(null);
  const showQr=async(tunnel:string,peer:string)=>{setQrError(null);try{const blob=await api.peerQr(tunnel,peer);setQr({peer,url:URL.createObjectURL(blob)});}catch(e){setQrError(e);}};
  const emptyTunnel = (rows: Tunnel[]): Tunnel => ({
    name: "",
    interface: nextTunnelInterface([
      ...c.interfaces.map((i) => i.name),
      ...rows.map((t) => t.interface),
    ]),
    role: "server",
    protocol: "wg",
    private_key: { plaintext: "" },
    listen_port: 51820,
    peers: [],
    endpoint: null,
    server_public_key: null,
    allowed_ips: [],
    keepalive: 25,
    obfuscation: {},
    open_port: true,
  });
  const createTunnel = async (rows: Tunnel[], role: Tunnel["role"], protocol: Tunnel["protocol"]): Promise<Tunnel> => {
    const row = { ...emptyTunnel(rows), role, protocol, listen_port: role === "server" ? 51820 : null, open_port: false };
    if (row.private_key && "plaintext" in row.private_key && row.private_key.plaintext) return row;
    const keys = await api.keygenTunnel(row.protocol);
    if (!keys.private_key?.trim()) throw new Error("Сервер не вернул приватный ключ туннеля");
    return {
      ...row,
      private_key: { plaintext: keys.private_key },
      ...(keys.obfuscation ? { obfuscation: keys.obfuscation } : {}),
    };
  };
  return (
    <>
      {qrError && !qr && <ErrorNotice error={qrError} />}
      <PageHeader>Туннели</PageHeader>
      <Collection<Tunnel>
        kind="tunnels"
        title="Туннели"
        addLabel="+ Добавить туннель"
        rowActions={(row) =>
          row.role === "server" && row.peers.length ? (
            <div key="qr" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {row.peers.map((p) => (
                <Button key={p.name} size="small" variant="text"
                  onClick={() => void showQr(row.name, p.name)}>
                  {p.name}
                </Button>
              ))}
            </div>
          ) : null
        }
        configPatch={(rows, importedAddresses) => ({
          interfaces: reconcileTunnelInterfaces(c, rows).map((iface) => importedAddresses[iface.name] ? { ...iface, addresses: [importedAddresses[iface.name]] } : iface),
          tunnels: materializeTunnels(c, rows),
        })}
        empty={emptyTunnel}
        create={createTunnel}
        importRow={(text, rows) => {
          const result = parseWireGuardConf(text);
          if (result.error) return { error: result.error };
          const addresses = [...text.matchAll(/^\s*Address\s*=\s*([^\r\n#;]+)/gim)].map((match) => match[1].trim());
          if (addresses.length > 1 || (addresses[0] && (addresses[0].includes(",") || !addressValid(addresses[0]))))
            return { error: "Address содержит несколько адресов или имеет неверный формат; импорт без потери адреса невозможен" };
          const taken = new Set(rows.map((row) => row.name));
          let index = 1;
          while (taken.has(`tunnel${index}`)) index += 1;
          return {
            address: addresses[0],
            row: {
              ...emptyTunnel(rows),
              ...result.tunnel,
              name: `tunnel${index}`,
            },
          };
        }}
        valid={(t) =>
          nameValid(t.name) &&
          ifaceNameValid(t.interface) &&
          secretValid(t.private_key) &&
          ipsValid(t.allowed_ips) &&
          Number.isInteger(t.keepalive) &&
          t.keepalive >= 0 &&
          t.keepalive <= 65535 &&
          (t.role === "server"
            ? portValid(t.listen_port ?? 0) &&
              t.peers.every(
                (p) =>
                  nameValid(p.name) &&
                  !!p.public_key.trim() &&
                  ipsValid(p.allowed_ips),
              ) &&
              new Set(t.peers.map((p) => p.name)).size === t.peers.length
            : !!t.endpoint?.trim() && !!t.server_public_key?.trim()) &&
          (t.protocol !== "awg" ||
            (awgRequired.every((k) => Number.isInteger(t.obfuscation[k])) &&
              Object.values(t.obfuscation).every(Number.isInteger)))
        }
        clean={(t) => ({
          ...t,
          allowed_ips: normalize(t.allowed_ips),
          peers: t.peers.map((p) => ({
            ...p,
            allowed_ips: normalize(p.allowed_ips),
          })),
        })}
        summary={(t) => [
          t.name,
          <Badge>{t.role === "server" ? "сервер" : "клиент"}</Badge>,
          t.protocol,
        ]}
        form={(t, patch, created, disabled, setError, tab, importedAddresses) => (
          <FormGrid>
            {tab === 0 && <>
            {created ? (
              <Field
                label="Имя туннеля"
                value={t.name}
                valid={nameValid(t.name)}
                onChange={(name) => patch({ name })}
              />
            ) : (
              <Field
                label="Имя туннеля"
                value={t.name}
                readOnly
                hint="Имя сохраняет привязку секретов"
              />
            )}
            <div>
              <InterfaceSelect
                label="Интерфейс"
                value={t.interface}
                interfaces={(() => {
                  const declared = c.interfaces.some((i) => i.name === t.interface);
                  const free = nextTunnelInterface([
                    ...c.interfaces.map((i) => i.name),
                    t.interface,
                  ]);
                  return [
                    ...c.interfaces,
                    ...(t.interface && !declared
                      ? [pendingInterface(t.interface, tunnelDescription(t) ?? "создастся автоматически")]
                      : []),
                    ...(free === t.interface
                      ? []
                      : [pendingInterface(free, "создать новый интерфейс")]),
                  ];
                })()}
                emptyLabel="Выберите интерфейс"
                error={!t.interface}
                helperText={!t.interface ? "Выберите значение" : undefined}
                onChange={(v) => patch({ interface: v })}
              />
              <p className="sub">
                Устройство создаётся автоматически (зона LAN) и появится на
                странице «Сеть». Не используйте имя физического NIC — выберите
                «создать новый интерфейс».
              </p>
            </div>
            <Field label="Роль" value={t.role === "server" ? "сервер" : "клиент"} readOnly hint="Роль выбирается при создании и затем не меняется" />
            <SelectField
              label="Протокол"
              value={t.protocol}
              options={["wg", "awg"]}
              onChange={(protocol) => {
                patch({ protocol });
                if (protocol === "awg" && awgRequired.some((key) => !Number.isInteger(t.obfuscation[key]))) {
                  void api.keygenTunnel("awg")
                    .then((keys) => {
                      if (awgRequired.some((key) => !Number.isInteger(keys.obfuscation?.[key]))) {
                        throw new Error("Сервер не вернул параметры обфускации AWG");
                      }
                      patch({ obfuscation: { ...keys.obfuscation, ...t.obfuscation } });
                    })
                    .catch(setError);
                }
              }}
            />
            <Field label="Адрес туннеля" value={importedAddresses[t.interface] ?? c.interfaces.find((i) => i.name === t.interface)?.addresses[0] ?? tunnelAddress(t, [...c.tunnels.filter((item) => item.name !== t.name), t])} readOnly hint="Адрес интерфейса; импортированный Address сохраняется при записи черновика" />
            </>}
            {tab === 2 && <>
            <FormWide><InfoNote severity="warning">Повторная генерация ключей разорвёт соединение клиентов. Обновите конфигурации другой стороны.</InfoNote></FormWide>
            {t.role === "client" && <Field label="Публичный ключ сервера" value={t.server_public_key ?? ""} valid={!!t.server_public_key?.trim()} onChange={(server_public_key) => patch({ server_public_key })} />}
            <div>
              <SecretField
                label="Приватный ключ"
                value={t.private_key}
                change={(v) => patch({ private_key: v ?? { plaintext: "" } })}
              />
              <FormActions>
                <Button disabled={disabled} onClick={() => void api.keygenTunnel(t.protocol)
                  .then((keys) => patch({
                    private_key: { plaintext: keys.private_key },
                    ...(t.protocol === "awg" ? { obfuscation: keys.obfuscation ?? {} } : {}),
                  }))
                  .catch(setError)}>Сгенерировать ключи</Button>
              </FormActions>
            </div>
            {t.private_key && !("plaintext" in t.private_key) && (
              <FormWide>
                <p className="sub">Публичный ключ этого туннеля для удалённых клиентов не отображается: он выводится из приватного на хосте при применении.</p>
              </FormWide>
            )}
            </>}
            {tab === 1 && t.role === "server" && <>
                <Field
                  label="Порт"
                  type="number"
                  value={t.listen_port ?? ""}
                  valid={portValid(t.listen_port ?? 0)}
                  onChange={(v) => patch({ listen_port: Number(v) })}
                />
                <Field
                  label="Публичный адрес (endpoint)"
                  value={t.endpoint ?? ""}
                  hint="Домен или IP:порт для клиентов; пусто — адрес WAN, иначе шаблон"
                  onChange={(endpoint) => patch({ endpoint: endpoint || null })}
                />
                <Toggle
                  label="Открыть порт на WAN"
                  value={t.open_port}
                  onChange={(open_port) => patch({ open_port })}
                />
            </>}
            {tab === 3 && t.role === "server" && <>
                {t.peers.map((p, index) => {
                  const update = (v: Partial<typeof p>) =>
                    patch({
                      peers: t.peers.map((r, i) =>
                        i === index ? { ...r, ...v } : r,
                      ),
                    });
                  return (
                    <FormWide key={index}>
                      <Card
                        title={p.name || "Новый пир"}
                        action={
                          <DeleteButton
                            label={`Удалить пира ${p.name || index + 1}`}
                            onClick={() =>
                              patch({
                                peers: t.peers.filter((_, i) => i !== index),
                              })
                            }
                          />
                        }
                      >
                        <FormGrid>
                          {p.preshared_key && "redacted" in p.preshared_key ? (
                            <Field
                              label="Имя пира"
                              value={p.name}
                              readOnly
                              hint="Имя сохраняет привязку секретов"
                            />
                          ) : (
                            <Field
                              label="Имя пира"
                              value={p.name}
                              valid={nameValid(p.name)}
                              onChange={(name) => update({ name })}
                            />
                          )}
                          <Field
                            label="Публичный ключ пира"
                            value={p.public_key}
                            valid={!!p.public_key.trim()}
                            hint={p.private_key ? "Сгенерирован панелью вместе с приватным" : "Введён вручную (клиентский)"}
                            onChange={(public_key) => update({ public_key, private_key: null })}
                          />
                          <Field
                            label="AllowedIPs пира"
                            value={p.allowed_ips.join(",")}
                            valid={ipsValid(p.allowed_ips)}
                            placeholder="10.66.66.2/32"
                            hint="AllowedIPs ≠ маршрут. Пусто — адрес выдастся автоматически (.2, .3, … в подсети туннеля)"
                            onChange={(v) => update({ allowed_ips: split(v) })}
                          />
                          <SecretField label="Preshared key" value={p.preshared_key} showOriginalHint={false} change={(preshared_key) => update({ preshared_key })} />
                          <FormWide>
                            <SecretField label="Приватный ключ пира (входит в клиентский конфиг)" value={p.private_key ?? null} showOriginalHint={false} change={(private_key) => update({ private_key })} />
                          </FormWide>
                          <FormWide>
                            <FormActions>
                              <Button disabled={disabled} onClick={() => void api.keygenPeerKeypair().then((pair) => update({ public_key: pair.public_key, private_key: { plaintext: pair.private_key } })).catch(setError)}>Сгенерировать ключи пира</Button>
                              <Button disabled={disabled} onClick={() => void api.keygenPeer().then((key) => update({ preshared_key: { plaintext: key.preshared_key } })).catch(setError)}>Сгенерировать PSK</Button>
                              <Button onClick={()=>void showQr(t.name,p.name)}>QR-код</Button>
                              <Button disabled>Экспорт пира</Button>
                            </FormActions>
                          </FormWide>
                        </FormGrid>
                      </Card>
                    </FormWide>
                  );
                })}
                <FormActions>
                  <Button
                    onClick={() =>
                      void api.keygenPeerKeypair()
                        .then((pair) =>
                          patch({
                            peers: [
                              ...t.peers,
                              {
                                name: "",
                                public_key: pair.public_key,
                                private_key: { plaintext: pair.private_key },
                                preshared_key: null,
                                allowed_ips: [],
                              },
                            ],
                          }))
                        .catch(setError)
                    }
                  >
                    + Добавить пира
                  </Button>
                </FormActions>
            </>}
            {tab === 1 && t.role === "client" && <>
                <Field
                  label="Endpoint"
                  value={t.endpoint ?? ""}
                  valid={!!t.endpoint?.trim()}
                  onChange={(endpoint) => patch({ endpoint })}
                />
                <Field
                  label="AllowedIPs"
                  value={t.allowed_ips.join(",")}
                  valid={ipsValid(t.allowed_ips)}
                  hint="AllowedIPs ≠ маршрут"
                  onChange={(v) => patch({ allowed_ips: split(v) })}
                />
                <Field
                  label="Keepalive, с"
                  type="number"
                  value={t.keepalive}
                  valid={
                    Number.isInteger(t.keepalive) &&
                    t.keepalive >= 0 &&
                    t.keepalive <= 65535
                  }
                  onChange={(v) => patch({ keepalive: Number(v) })}
                />
            </>}
            {t.protocol === "awg" && tab === (t.role === "server" ? 4 : 3) && (
              <FormWide>
                <Card title="Обфускация">
                  <FormGrid>
                    {awgFields.map((k) => (
                      <Field
                        key={k}
                        label={k}
                        type="number"
                        value={t.obfuscation[k] ?? ""}
                        valid={
                          t.obfuscation[k] === undefined
                            ? !awgRequired.includes(k)
                            : Number.isInteger(t.obfuscation[k])
                        }
                        onChange={(v) => {
                          const obfuscation = { ...t.obfuscation };
                          if (v === "") delete obfuscation[k];
                          else obfuscation[k] = Number(v);
                          patch({ obfuscation });
                        }}
                      />
                    ))}
                  </FormGrid>
                </Card>
              </FormWide>
            )}
          </FormGrid>
        )}
      />
      <Dialog open={!!qr} onClose={()=>{if(qr)URL.revokeObjectURL(qr.url);setQr(null);}}>
        <DialogTitle>QR-код пира {qr?.peer}</DialogTitle><DialogContent>{qrError?<ErrorNotice error={qrError}/>:qr&&<img src={qr.url} alt={`QR-код пира ${qr.peer}`} style={{maxWidth:"100%"}}/>}</DialogContent>
        <DialogActions>{qr&&<Button component="a" href={qr.url} download={`${qr.peer}.png`}>Скачать PNG</Button>}<Button onClick={()=>{if(qr)URL.revokeObjectURL(qr.url);setQr(null);}}>Закрыть</Button></DialogActions>
      </Dialog>
      <p className="sub">Роль после создания не меняется.</p>
    </>
  );
}
export function Sites() {
  const { configuration: c } = useConfiguration();
  const addresses = c.interfaces
    .filter((i) => i.zone === "wan")
    .flatMap((i) => i.addresses.map((a) => a.split("/")[0]));
  return (
    <Collection<CaddySite>
      kind="sites"
      title="Входящие сайты"
      addLabel="+ Добавить сайт"
      empty={() => ({
        name: "",
        hostname: "",
        upstream: "",
        certificate_mode: "http01",
        wan_address: addresses[0] ?? null,
        certificate: null,
        private_key: null,
        dns_api_token: null,
      })}
      valid={(s) =>
        nameValid(s.name) &&
        hostValid(s.hostname, true) &&
        !!s.upstream.trim() &&
        (!s.wan_address || addresses.includes(s.wan_address)) &&
        (s.certificate_mode !== "http01" || !!s.wan_address) &&
        (s.certificate_mode !== "manual" ||
          (secretValid(s.certificate) && secretValid(s.private_key))) &&
        (s.certificate_mode !== "dns01" || secretValid(s.dns_api_token))
      }
      summary={(s) => [
        s.name,
        s.hostname,
        s.upstream,
        certificateModeLabels[s.certificate_mode],
        s.certificate_mode === "passthrough" ? "TLS не завершается" : "Статус недоступен",
      ]}
      form={(s, patch, created) => (
        <FormGrid>
          {created ? (
            <Field
              label="Имя сайта"
              value={s.name}
              valid={nameValid(s.name)}
              onChange={(name) => patch({ name })}
            />
          ) : (
            <Field
              label="Имя сайта"
              value={s.name}
              readOnly
              hint="Имя сохраняет привязку секретов"
            />
          )}
          <Field
            label="Hostname сайта"
            value={s.hostname}
            valid={hostValid(s.hostname, true)}
            onChange={(hostname) => patch({ hostname })}
          />
          <Field
            label="Upstream"
            value={s.upstream}
            valid={!!s.upstream.trim()}
            onChange={(upstream) => patch({ upstream })}
          />
          <Select
            label="Режим сертификата"
            value={s.certificate_mode}
            options={Object.entries(certificateModeLabels).map(([value, label]) => ({ value, label }))}
            onChange={(certificate_mode) => patch({ certificate_mode: certificate_mode as CaddySite["certificate_mode"] })}
          />
          <Select
            label="WAN-адрес"
            value={s.wan_address ?? ""}
            placeholder={{ label: "Автоматически" }}
            options={Array.from(
              new Set([
                ...addresses,
                ...(s.wan_address ? [s.wan_address] : []),
              ]),
            ).map((a) => ({ value: a, label: a }))}
            onChange={(v) => patch({ wan_address: v || null })}
          />
          {s.certificate_mode === "manual" && (
            <>
              <SecretField
                label="Сертификат"
                value={s.certificate}
                change={(certificate) => patch({ certificate })}
              />
              <SecretField
                label="Ключ сертификата"
                value={s.private_key}
                change={(private_key) => patch({ private_key })}
              />
            </>
          )}
          {s.certificate_mode === "dns01" && (
            <SecretField
              label="DNS API token (Cloudflare)"
              value={s.dns_api_token}
              change={(dns_api_token) => patch({ dns_api_token })}
            />
          )}
          {s.certificate_mode === "http01" &&
            c.port_forwards.some(
              (p) =>
                p.enabled &&
                [80, 443].includes(p.external_port) &&
                (p.wan_address ??
                  c.interfaces
                    .find((i) => i.name === p.interface)
                    ?.addresses[0]?.split("/")[0]) === s.wan_address,
            ) && (
              <FormWide>
                <p role="status">
                  Конфликт с port forward: HTTP-01 требует свободных портов
                  80/443.
                </p>
              </FormWide>
            )}
        </FormGrid>
      )}
    />
  );
}
export function DDNS() {
  const { configuration: c } = useConfiguration();
  const wan = c.interfaces.filter((i) => i.zone === "wan").map((i) => i.name);
  return (
    <>
      <Collection<DDNSUpdate>
        kind="ddns"
        title="DDNS"
        addLabel="+ Добавить DDNS"
        empty={() => ({
          name: "",
          provider: "cloudflare",
          hostname: "",
          zone: null,
          server: null,
          key_name: null,
          api_token: { plaintext: "" },
          wan_interface: wan[0] ?? "",
        })}
        valid={(d) =>
          nameValid(d.name) &&
          hostValid(d.hostname) &&
          secretValid(d.api_token) &&
          wan.includes(d.wan_interface) &&
          (d.provider === "cloudflare"
            ? !!d.zone?.trim()
            : !!d.server?.trim() && !!d.key_name?.trim())
        }
        summary={(d) => [d.name, d.provider, d.hostname, "Статус недоступен"]}
        form={(d, patch, created) => (
          <FormGrid>
            {created ? (
              <Field
                label="Имя DDNS"
                value={d.name}
                valid={nameValid(d.name)}
                onChange={(name) => patch({ name })}
              />
            ) : (
              <Field
                label="Имя DDNS"
                value={d.name}
                readOnly
                hint="Имя сохраняет привязку секретов"
              />
            )}
            <SelectField
              label="Провайдер"
              value={d.provider}
              options={["cloudflare", "rfc2136"]}
              onChange={(provider) => patch({ provider })}
            />
            <Field
              label="Hostname DDNS"
              value={d.hostname}
              valid={hostValid(d.hostname)}
              onChange={(hostname) => patch({ hostname })}
            />
            {d.provider === "cloudflare" ? (
              <Field
                label="Zone"
                value={d.zone ?? ""}
                valid={!!d.zone?.trim()}
                onChange={(zone) => patch({ zone })}
              />
            ) : (
              <>
                <Field
                  label="Сервер DNS"
                  value={d.server ?? ""}
                  valid={!!d.server?.trim()}
                  onChange={(server) => patch({ server })}
                />
                <Field
                  label="Key name"
                  value={d.key_name ?? ""}
                  valid={!!d.key_name?.trim()}
                  onChange={(key_name) => patch({ key_name })}
                />
              </>
            )}
            <SecretField
              label="API token / TSIG key"
              value={d.api_token}
              change={(v) => patch({ api_token: v ?? { plaintext: "" } })}
            />
            <InterfaceSelect
              label="WAN-интерфейс"
              value={d.wan_interface}
              interfaces={c.interfaces.filter((i) => i.zone === "wan")}
              emptyLabel="Выберите интерфейс"
              error={!d.wan_interface}
              helperText={!d.wan_interface ? "Выберите значение" : undefined}
              onChange={(wan_interface) => patch({ wan_interface })}
            />
          </FormGrid>
        )}
      />
      <p className="sub">
        Статус DDNS агент пока не отдаёт через HTTP API; результат последней
        попытки обновления в панели не отображается.
      </p>
    </>
  );
}