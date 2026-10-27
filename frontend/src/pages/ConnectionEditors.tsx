import { useEffect, useRef, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button, Checkbox, FormControlLabel, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";
import { useConfiguration } from "../state";
import type {
  Tunnel,
  TunnelAvailability,
  Peer,
  Subscriber,
  CaddySite,
  DDNSUpdate,
  Configuration,
  Interface,
  Secret,
  ServiceStatusResponse,
} from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { ErrorNotice } from "../components/ErrorNotice";
import { EditorFooter, EditorShell } from "../components/EditorShell";
import { ValueTabs } from "../components/Tabs";
import { ExpertDisclosure } from "../components/ExpertDisclosure";
import { PageSection } from "../components/PageSection";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InlineStatus } from "../components/InlineStatus";
import { InfoNote } from "../components/InfoNote";
import { EmptyState } from "../components/EmptyState";
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
  ipValid,
  normalize,
} from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { api } from "../api";
import { queryKeys } from "../query";
import { parseWireGuardConf } from "../tunnelConf";

const ipsValid = (v: string[]) =>
  v.filter((s) => s.trim()).every((s) => addressValid(s.trim()));
const split = (v: string) => v.split(",");
const awgNumericKeys = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
  "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
  "KeepaliveTimeout", "MaxHandshakeAttempts"];
const awgSignatureKeys = ["I1", "I2", "I3", "I4", "I5"];
const awgFields = [...awgNumericKeys, ...awgSignatureKeys];
// AWG core parameters every client emits; the rest are optional AWG 3+ additions.
const awgRequired = ["Jc", "S1", "S2", "H1", "H2", "H3", "H4"];
const rangeValue = /^[0-9]{1,10}(-[0-9]{1,10})?$/;
/** A uint32 or an AWG 3+ "min-max" range: keepalive, paddings and timings. */
const numericValue = (v: unknown) =>
  (typeof v === "number" && Number.isInteger(v) && v >= 0) || (typeof v === "string" && rangeValue.test(v));
const awgValueValid = (key: string, v: unknown) =>
  awgSignatureKeys.includes(key) ? typeof v === "string" && v.trim() !== "" : numericValue(v);
const awgInput = (key: string, v: string): number | string => {
  const value = v.trim();
  return awgSignatureKeys.includes(key) || !/^[0-9]+$/.test(value) ? value : Number(value);
};

/** Apply a keygen response to a tunnel: the whole AWG 3+ profile (header
 * protection, signatures, padding, timings, toggles) and a server port that is
 * not the AWG default, not just the key material. */
function keygenPatch(
  keys: Awaited<ReturnType<typeof api.keygenTunnel>>,
  protocol: Tunnel["protocol"],
): Partial<Tunnel> {
  return {
    private_key: { plaintext: keys.private_key },
    ...(protocol === "awg" ? {
      obfuscation: keys.obfuscation ?? {},
      header_protection_key: keys.header_protection_key ? { plaintext: keys.header_protection_key } : null,
      random_trailers: keys.random_trailers ?? false,
      disable_cookies: keys.disable_cookies ?? false,
    } : {}),
    ...(keys.listen_port ? { listen_port: keys.listen_port } : {}),
    ...(keys.mtu ? { mtu: keys.mtu } : {}),
  };
}
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

/** Devices the stored configuration attributes to a tunnel the editor no longer
 * carries: that tunnel was deleted (or moved to another device), so its device
 * leaves with it. */
function removedTunnelDevices(configuration: Configuration, tunnels: Tunnel[]): Set<string> {
  const owned = new Set(tunnels.map((tunnel) => tunnel.interface).filter(Boolean));
  return new Set(configuration.tunnels
    .map((tunnel) => tunnel.interface)
    .filter((name): name is string => !!name && AUTO_TUNNEL_NAME.test(name) && !owned.has(name)));
}

/** Remove a deleted tunnel's device and every object that references it.
 * The stored configuration may only name interfaces that exist (backend
 * validation rejects `route.interface`, `nat.interface`, `dhcp.id_or_interface`,
 * `dns.interface_address_required`, `ssh.interface_binding_required`,
 * `tproxy.ingress_interface`, `tunnel.interface`), so a reference left behind
 * either blocks the save or silently keeps the device alive. */
function dropTunnelDevices(configuration: Configuration, devices: Set<string>): Partial<Configuration> {
  if (!devices.size) return {};
  const gone = (name: string | null) => !!name && devices.has(name);
  return {
    interfaces: configuration.interfaces
      .filter((iface) => !devices.has(iface.name))
      .map((iface) => iface.parent && devices.has(iface.parent)
        ? { ...iface, parent: null }
        : iface.members.some((member) => devices.has(member))
          ? { ...iface, members: iface.members.filter((member) => !devices.has(member)) }
          : iface),
    static_routes: (configuration.static_routes ?? []).filter((route) => !gone(route.interface)),
    dhcp_subnets: configuration.dhcp_subnets.filter((subnet) => !gone(subnet.interface)),
    port_forwards: configuration.port_forwards.filter((forward) => !gone(forward.interface)),
    dns: { ...configuration.dns, interfaces: configuration.dns.interfaces.filter((name) => !devices.has(name)) },
    ddns: configuration.ddns.filter((job) => !gone(job.wan_interface)),
    ssh: { ...configuration.ssh,
      interfaces: configuration.ssh.interfaces.filter((name) => !devices.has(name)),
      wan_confirmed_interfaces: configuration.ssh.wan_confirmed_interfaces.filter((name) => !devices.has(name)) },
    tproxy: { ...configuration.tproxy,
      ingress_interfaces: configuration.tproxy.ingress_interfaces.filter((name) => !devices.has(name)) },
  };
}

/** Keep the configuration's tunnel devices in sync with the edited tunnels:
 * create/fill a LAN-zone interface for each tunnel (with its automatic address),
 * drop a device whose tunnel was deleted together with every reference to it,
 * and drop an orphaned auto-created device (`tun<N>` no longer owned by a tunnel
 * or referenced anywhere). An operator-declared interface is never removed. */
function reconcileTunnelInterfaces(configuration: Configuration, tunnels: Tunnel[]): Partial<Configuration> {
  const cleaned: Configuration = {
    ...configuration,
    ...dropTunnelDevices(configuration, removedTunnelDevices(configuration, tunnels)),
  };
  const referenced = referencedInterfaces(cleaned, tunnels);
  const byName = new Map(cleaned.interfaces.map((i) => [i.name, i]));
  const result = cleaned.interfaces.filter(
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
  return { ...cleaned, interfaces: result };
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
  tunnelStatus,
  tunnelAvailability,
  filter,
  showQr,
  addressOverrides,
}: {
  kind: "tunnels" | "sites" | "ddns";
  title: string;
  addLabel: string;
  empty: (rows: T[]) => T;
  create?: (rows: T[], role: Tunnel["role"], protocol: Tunnel["protocol"]) => Promise<T>;
  valid: (v: T) => boolean;
  clean?: (v: T) => T;
  form: (v: T, patch: (p: Partial<T>) => void, created: boolean, noConfiguration: boolean, setError: (error: unknown) => void, importedAddresses: Record<string, string>, setBusy: (busy: boolean) => void) => ReactNode;
  summary: (v: T) => ReactNode[];
  rowActions?: (row: T) => ReactNode;
  /** Optional list filter (e.g. tunnels split by client/server role). */
  filter?: (rows: T[]) => T[];
  /** Peer QR export; tunnels only (needed by the peers panel outside the edit mode). */
  showQr?: (tunnel: string, peer: string, current: () => boolean) => Promise<void>;
  /** Extra configuration derived from the edited rows (e.g. auto-created
   * tunnel interfaces). Merged into the whole-configuration save. */
  configPatch?: (rows: T[], importedAddresses: Record<string, string>) => Partial<Configuration>;
  importRow?: (text: string, rows: T[]) => { row?: T; error?: string; address?: string };
  tunnelStatus?: ServiceStatusResponse;
  tunnelAvailability?: Record<string, TunnelAvailability>;
  /** Creation-time interface addresses (e.g. the randomised keygen subnet) —
   * they win over the name-derived pool slot until an operator edits them. */
  addressOverrides?: Record<string, string>;
}) {
  const { configuration: c, version, noConfiguration } = useConfiguration();
  const editor = useDraftEditor<EditableRow<T>[]>();
  const [next, setNext] = useState(0);
  const [creating, setCreating] = useState(false);
  const [formBusy, setFormBusy] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importAddresses, setImportAddresses] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState(false);
  const [scenario, setScenario] = useState<"client" | "server" | null>(null);
  const [protocol, setProtocol] = useState<Tunnel["protocol"]>("wg");
  const [selected, setSelected] = useState<number | null>(null);
  const [viewing, setViewing] = useState(true);
  const [dialogTab, setDialogTab] = useState<"tunnel" | "peers">("tunnel");
  const [deleteTarget, setDeleteTarget] = useState<number | null>(null);
  const creatingRef = useRef(false);
  const editEpoch = useRef(0);
  const currentEditing = useRef<EditableRow<T>[] | null>(null);
  const collection = c[kind] as T[];
  const list = filter ? filter(collection) : collection;
  const imported = { ...addressOverrides, ...importAddresses };
  const editing = editor.value;
  currentEditing.current = editing;
  const isEdit = editor.isEdit;
  useEffect(() => {
    if (!isEdit) {
      setSelected(null);
      setViewing(true);
      setDialogTab("tunnel");
    }
  }, [isEdit]);
  useEffect(() => { setDialogTab("tunnel"); }, [selected]);
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
        ...(configPatch ? configPatch(rows, imported) : {}),
      };
    });
  const add = async (role: Tunnel["role"] = "server", chosenProtocol: Tunnel["protocol"] = "wg") => {
    const initial = editing ?? currentEditing.current;
    if (!initial || creatingRef.current) return;
    const id = Math.max(next, initial.reduce((max, item) => Math.max(max, item.id + 1), 0));
    if (!create) {
      editor.setValue([...initial, { id, created: true, row: empty(initial.map((v) => v.row)) }]);
      setSelected(id);
      setViewing(false);
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
        setViewing(false);
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
    setViewing(false);
    if (!isEdit) {
      editEpoch.current += 1;
      editor.begin([...rows, { id, created: true, row: result.row }]);
    } else {
      editor.setValue([...rows, { id, created: true, row: result.row }]);
    }
    setNext(id + 1);
    closeImport();
  };
  const cancel = () => {
    editEpoch.current += 1;
    editor.cancel();
    setSelected(null);
    setViewing(true);
    setDialogTab("tunnel");
  };
  /** Patch the selected tunnel row directly; used by the peers panel outside
   *  the tunnel's edit mode, so peers are managed without entering editing. */
  const patchSelected = (patch: Partial<Tunnel>) => {
    const latest = currentEditing.current;
    if (!latest?.some((v) => v.id === selected)) return;
    const updated = latest.map((v) => v.id === selected ? { ...v, row: { ...v.row, ...(patch as Partial<T>) } } : v);
    currentEditing.current = updated;
    editor.setValue(updated);
  };
  const renderEdit = () => editing ? (
    <>
      {editing.filter(({ id }) => id === selected).map(({ id, row, created }) => (
        kind === "tunnels" ? (
          <div key={id}>
            {form(row, (patch) => {
              const latest = currentEditing.current;
              if (!latest?.some((v) => v.id === id)) return;
              const updated = latest.map((v) => v.id === id ? { ...v, row: { ...v.row, ...patch } } : v);
              currentEditing.current = updated;
              editor.setValue(updated);
            }, created, noConfiguration, editor.setError, imported, setFormBusy)}
          </div>
        ) : (
          <div key={id}>
            {form(row, (patch) => {
              const latest = currentEditing.current;
              if (!latest?.some((v) => v.id === id)) return;
              const updated = latest.map((v) => v.id === id ? { ...v, row: { ...v.row, ...patch } } : v);
              currentEditing.current = updated;
              editor.setValue(updated);
            }, created, noConfiguration, editor.setError, imported, setFormBusy)}
          </div>
        )
      ))}
      {kind === "tunnels" && (() => {
        const tunnel = editing.find((item) => item.id === selected)?.row as Tunnel | undefined;
        if (!tunnel) return <InfoNote>Сохранение удалит выбранный туннель только из черновика. Изменения вступят в силу после применения.</InfoNote>;
        const address = imported[tunnel.interface] ?? c.interfaces.find((i) => i.name === tunnel.interface)?.addresses[0] ?? tunnelAddress(tunnel, editing.map((v) => v.row as Tunnel));
        return <InfoNote>При сохранении: {tunnel.name || "новый туннель"} · {tunnel.role === "server" ? "сервер" : "клиент"} · {tunnel.protocol === "awg" ? "AmneziaWG" : "WireGuard"}; интерфейс {tunnel.interface} ({c.interfaces.some((i) => i.name === tunnel.interface) ? "существующий" : "будет создан"}, зона LAN), адрес {address}; WAN UDP-порт {tunnel.role === "server" && tunnel.open_port ? `${tunnel.listen_port} будет открыт после применения` : "не открывается"}. Сохранение создаёт только черновик.</InfoNote>;
      })()}
      {!allValid && <p role="status">Проверьте обязательные поля, формат значений и уникальность имён.</p>}
    </>
  ) : null;
  const selectedTunnel = kind === "tunnels" ? editing?.find((item) => item.id === selected)?.row as Tunnel | undefined : undefined;
  return (
    <>
      {kind !== "tunnels" && <ErrorNotice error={editor.error} />}
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
            {kind !== "tunnels" && <Button disabled={!version || creating} onClick={() => {
              if (isEdit) { void add(); return; }
              const rows = collection.map((row, id) => ({ id, created: false, row }));
              const id = rows.length;
              editEpoch.current += 1;
              editor.begin([...rows, { id, created: true, row: empty(collection) }]);
              setSelected(id);
              setNext(id + 1);
            }}>{addLabel}</Button>}
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
        {kind === "tunnels" ? (
            list.length ? list.map((row) => {
              const id = collection.indexOf(row);
              const tunnel = row as Tunnel;
              const service = tunnelStatus?.services.find((item) => item.name === `tunnel:${tunnel.interface}`);
              return <Card key={id} title={`${tunnel.name} · ${tunnel.protocol === "wg" ? "WireGuard" : "AmneziaWG"} · ${tunnel.role === "server" ? "Сервер" : "Клиент"}`}
                action={<Button disabled={!version} onClick={() => {
                  editor.begin(collection.map((item, index) => ({ id: index, created: false, row: item })));
                  setNext(collection.length); setSelected(id); setViewing(true);
                }}>Открыть</Button>}>
                <dl className="kv">
                  <dt>Интерфейс</dt><dd>{tunnel.interface}</dd>
                  {tunnel.role === "server"
                    ? <><dt>Пиров</dt><dd>{tunnel.peers.length || "нет пиров"}</dd></>
                    : <><dt>Endpoint</dt><dd>{tunnel.endpoint ?? "не задан"}</dd></>}
                </dl>
                {version?.status === "draft" && <Badge tone="blue">Черновик</Badge>}
                {tunnel.role === "client" && <div>
                  <ClientHandshake status={tunnelAvailability?.[tunnel.name]} />
                </div>}
                {service ? <InlineStatus
                  tone={service.state === "running" ? "green" : service.state === "stopped" ? "amber" : "unknown"}
                  text={`${tunnel.role === "client" ? "Служба: " : ""}${service.state === "running" ? "Работает" : service.state === "stopped" ? "Остановлена" : "Состояние неизвестно"}`}
                  asOf={tunnelStatus?.generated_at}
                /> : <InlineStatus tone="unknown" text="Статус недоступен" />}
              </Card>;
            }) : <EmptyState title="Туннелей пока нет">Добавьте туннель или импортируйте клиентский .conf.</EmptyState>
          ) : (
            <DataTable
                heads={kind === "sites"
                  ? ["Имя", "Hostname", "Upstream", "Сертификат", "Статус"]
                  : ["Имя", "Провайдер", "Hostname", "Статус"]}
                empty={<EmptyState>{kind === "sites" ? "Сайтов нет. Добавьте сайт." : "Доменов DDNS нет. Добавьте домен."}</EmptyState>}
                rows={collection.map((row, id) => {
                  const cells = summary(row);
                  cells[0] = <Button variant="text" disabled={!version} onClick={() => {
                    if (!isEdit) {
                      editEpoch.current += 1;
                      editor.begin(collection.map((item, index) => ({ id: index, created: false, row: item })));
                      setNext(collection.length);
                    }
                    setSelected(id);
                  }}>{row.name}</Button>;
                  if (rowActions) cells.push(noConfiguration ? null : rowActions(row));
                  return cells;
                })}
              />
          )}
      </Card>
      {kind !== "tunnels" && <Dialog open={isEdit && selected !== null} onClose={editor.saving ? undefined : cancel}
        fullWidth maxWidth="md">
        <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>{kind === "sites" ? "Сайт" : "DDNS"}: {editing?.find((item) => item.id === selected)?.row.name || "Новая запись"}</span>
          {editing?.some((item) => item.id === selected) && <DeleteButton
            label={`Удалить ${editing.find((item) => item.id === selected)!.row.name || "запись"}`}
            onClick={() => {
              const remaining = (currentEditing.current ?? []).filter((item) => item.id !== selected);
              currentEditing.current = remaining;
              editor.setValue(remaining);
            }} />}
        </DialogTitle>
        <DialogContent>
          <ErrorNotice error={editor.error} />
          <EditorShell isEdit={isEdit} saving={editor.saving} valid={!!allValid && !!version && !creating && !formBusy}
            onCancel={cancel} onSave={() => void save()} view={null} edit={renderEdit} />
        </DialogContent>
      </Dialog>}
      {kind === "tunnels" && <Dialog open={isEdit && selected !== null} onClose={editor.saving ? undefined : cancel}
        fullWidth maxWidth="md" aria-labelledby="tunnel-editor-title">
        <DialogTitle id="tunnel-editor-title">{selectedTunnel
          ? `Туннель: ${selectedTunnel.name || "Новый туннель"} · ${selectedTunnel.protocol === "wg" ? "WireGuard" : "AmneziaWG"} · ${selectedTunnel.role === "server" ? "Сервер" : "Клиент"}`
          : "Туннель удалён из черновика"}</DialogTitle>
        <DialogContent>
          <ErrorNotice error={editor.error} />
          {selectedTunnel?.role === "server" && <ValueTabs<"tunnel" | "peers">
            tabs={[{ value: "tunnel", label: "Туннель" }, { value: "peers", label: "Пиры" }]}
            value={dialogTab} change={setDialogTab} />}
          {/* Keep the tunnel form mounted so switching tabs cannot replace opaque secret values. */}
          <div hidden={!!selectedTunnel && dialogTab === "peers"}>
            {!viewing && selectedTunnel && <FormActions><DeleteButton label={`Удалить ${selectedTunnel.name || "запись"}`} onClick={() => setDeleteTarget(selected!)} /></FormActions>}
            {viewing && selectedTunnel ? (
              <>
                <div className="toolbar-actions"><Button variant="contained" onClick={() => setViewing(false)}>Изменить</Button></div>
                <dl className="kv">
                  <dt>Имя</dt><dd>{selectedTunnel.name}</dd>
                  <dt>Роль</dt><dd>{selectedTunnel.role === "server" ? "сервер" : "клиент"}</dd>
                  <dt>Протокол</dt><dd>{selectedTunnel.protocol === "wg" ? "WireGuard" : "AmneziaWG"}</dd>
                  <dt>Интерфейс</dt><dd>{selectedTunnel.interface}</dd>
                </dl>
              </>
            ) : (
            <EditorShell isEdit={isEdit} saving={editor.saving} valid={!!allValid && !!version && !creating && !formBusy}
              onCancel={cancel} onSave={() => void save()} view={null} edit={renderEdit} />
            )}
          </div>
          {selectedTunnel?.role === "server" && dialogTab === "peers" && (
            /* Peers live outside the tunnel edit mode: they are viewed and
             * added here, in view mode, with only their own save. */
            <TunnelPeers tunnel={selectedTunnel} subscribers={c.subscribers ?? []}
              patch={patchSelected} created={!!editing?.find((item) => item.id === selected)?.created}
              disabled={noConfiguration} setError={editor.setError} setBusy={setFormBusy} showQr={showQr ?? (() => Promise.resolve())} />
          )}
        </DialogContent>
        {selectedTunnel && (viewing || dialogTab === "peers") && <DialogActions>
          {dialogTab === "peers" && selectedTunnel.role === "server" && (
            <Button variant="contained" disabled={editor.saving || !allValid || !version || creating || formBusy}
              onClick={() => void save()}>Сохранить</Button>
          )}
          <Button onClick={cancel}>Отмена</Button>
        </DialogActions>}
      </Dialog>}
      {kind === "tunnels" && <ConfirmDialog open={deleteTarget !== null} title="Удалить туннель?"
        body="Туннель, его пиры и автоматически созданный интерфейс будут удалены из черновика. Вместе с интерфейсом удаляются ссылки на него: статические маршруты, подсети DHCP, проброс портов, DNS, SSH и вход TProxy."
        confirmLabel="Удалить из черновика" cancelLabel="Отмена" danger
        onCancel={() => setDeleteTarget(null)} onConfirm={() => {
          const remaining = (currentEditing.current ?? []).filter((v) => v.id !== deleteTarget);
          currentEditing.current = remaining; editor.setValue(remaining); setDeleteTarget(null);
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
            {preview && parsedImport?.row && <InfoNote>Распознано: клиент · {(parsedImport.row as Tunnel).protocol === "awg" ? "AmneziaWG" : "WireGuard"}; endpoint {(parsedImport.row as Tunnel).endpoint}; AllowedIPs {(parsedImport.row as Tunnel).allowed_ips.join(", ")}; Address {parsedImport.address ?? "отсутствует — будет назначен автоматически"}; MTU {(parsedImport.row as Tunnel).mtu ?? "умолчание хоста"}; PSK {(parsedImport.row as Tunnel).preshared_key ? "распознан" : "отсутствует"}. Приватный ключ скрыт. Сохранение создаёт только черновик.</InfoNote>}
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
/** A peer edits a private copy; only Save or confirmed deletion touches the outer draft. */
function PeerEditor({ peer, peers, subscribers, disabled, save, remove, cancel }: {
  peer: Peer;
  peers: Peer[];
  subscribers: Subscriber[];
  disabled: boolean;
  save: (peer: Peer) => void;
  remove: () => void;
  cancel: () => void;
}) {
  const [value, setValue] = useState<Peer>(() => ({ ...peer, allowed_ips: [...peer.allowed_ips] }));
  const [error, setError] = useState<unknown>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [generating, setGenerating] = useState(false);
  const active = useRef(true);
  const generatingRef = useRef(false);
  useEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);
  const update = (patch: Partial<Peer>) => setValue((current) => ({ ...current, ...patch }));
  const close = () => { active.current = false; cancel(); };
  const generate = async (kind: "keys" | "psk") => {
    if (generatingRef.current) return;
    generatingRef.current = true;
    setGenerating(true);
    setError(null);
    try {
      const patch: Partial<Peer> = kind === "keys"
        ? await api.keygenPeerKeypair().then((pair) => ({ public_key: pair.public_key, private_key: { plaintext: pair.private_key } }))
        : await api.keygenPeer().then((key) => ({ preshared_key: { plaintext: key.preshared_key } }));
      if (active.current) update(patch);
    } catch (failure) {
      if (active.current) setError(failure);
    } finally {
      generatingRef.current = false;
      if (active.current) setGenerating(false);
    }
  };
  const valid = nameValid(value.name) && !!value.public_key.trim() && ipsValid(value.allowed_ips)
    && !peers.some((item) => item !== peer && item.name === value.name);
  return (
    <Dialog open onClose={close} fullWidth maxWidth="sm" aria-labelledby="peer-editor-title">
      <DialogTitle id="peer-editor-title">Пир: {peer.name || "Новый пир"}</DialogTitle>
      <DialogContent>
        <ErrorNotice error={error} />
        <FormActions><DeleteButton label={`Удалить пира ${peer.name || "Новый пир"}`} onClick={() => setConfirmDelete(true)} /></FormActions>
        <FormGrid>
          {peer.preshared_key && "redacted" in peer.preshared_key ? (
            <Field label="Имя пира" value={value.name} readOnly hint="Имя сохраняет привязку секретов" />
          ) : (
            <Field label="Имя пира" value={value.name} valid={nameValid(value.name)}
              hint="Латиница, цифры, «_»; до 31 символа" onChange={(name) => update({ name })} />
          )}
          <Select label="Абонент" value={value.subscriber ?? ""}
            options={[{ value: "", label: "— без абонента (служебный пир) —" },
              ...subscribers.map((subscriber) => ({ value: subscriber.name,
                label: subscriber.label ? `${subscriber.name} — ${subscriber.label}` : subscriber.name }))]}
            onChange={(subscriber) => update({ subscriber: subscriber || null })} />
          <Field label="Публичный ключ пира" value={value.public_key} valid={!!value.public_key.trim()}
            hint={value.private_key ? "Сгенерирован панелью вместе с приватным" : "Введён вручную (клиентский)"}
            onChange={(public_key) => update({ public_key, private_key: null })} />
          <Field label="AllowedIPs пира" value={value.allowed_ips.join(",")} valid={ipsValid(value.allowed_ips)}
            placeholder="10.66.66.2/32"
            hint="AllowedIPs ≠ маршрут. Пусто — адрес выдастся автоматически (.2, .3, … в подсети туннеля)"
            onChange={(v) => update({ allowed_ips: split(v) })} />
          <SecretField label="Preshared key" value={value.preshared_key} showOriginalHint={false} change={(preshared_key) => update({ preshared_key })} />
          <FormWide><SecretField label="Приватный ключ пира (входит в клиентский конфиг)" value={value.private_key ?? null}
            showOriginalHint={false} change={(private_key) => update({ private_key })} /></FormWide>
          <FormWide><FormActions>
            <Button disabled={disabled || generating} onClick={() => void generate("keys")}>Сгенерировать ключи пира</Button>
            <Button disabled={disabled || generating} onClick={() => void generate("psk")}>Сгенерировать PSK</Button>
          </FormActions></FormWide>
        </FormGrid>
        <EditorFooter saving={false} valid={valid && !generating} cancel={close} save={() => {
          active.current = false;
          save(value);
        }} />
        <ConfirmDialog open={confirmDelete} title="Удалить пира?"
          body="Пир будет удалён из черновика и с работающего туннеля при сохранении; если туннель ещё не применён, удаление произойдёт при применении."
          confirmLabel="Удалить из черновика" cancelLabel="Отмена" danger
          onCancel={() => setConfirmDelete(false)} onConfirm={() => { active.current = false; remove(); }} />
      </DialogContent>
    </Dialog>
  );
}

function peerActivityLabel(seconds: number | null | undefined): string {
  if (seconds === 0) return "Не подключался";
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "Активность недоступна";
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) ? date.toLocaleString("ru-RU") : "Активность недоступна";
}

/** The peers panel of a server tunnel. Mounted inside the edit tabs and directly
 *  in view mode, so peers are added and viewed without entering edit mode. */
function TunnelPeers({ tunnel, subscribers, patch, created, disabled, setError, setBusy, showQr }: {
  tunnel: Tunnel;
  subscribers: Subscriber[];
  patch: (patch: Partial<Tunnel>) => void;
  created: boolean;
  disabled: boolean;
  setError: (error: unknown) => void;
  setBusy: (busy: boolean) => void;
  showQr: (tunnel: string, peer: string, current: () => boolean) => Promise<void>;
}) {
  const [selected, setSelected] = useState<Peer | null>(null);
  const [adding, setAdding] = useState(false);
  const addingRef = useRef(false);
  const active = useRef(true);
  const latest = useRef({ tunnel, patch, setError });
  latest.current = { tunnel, patch, setError };
  useEffect(() => {
    active.current = true;
    return () => { active.current = false; setBusy(false); };
  }, [setBusy]);
  useEffect(() => { setBusy(adding || selected !== null); }, [adding, selected, setBusy]);
  const activity = useQuery({
    queryKey: queryKeys.tunnelActivity(),
    queryFn: ({ signal }) => api.tunnelActivity(signal),
    enabled: true,
    refetchInterval: 30_000,
    // A failed poll must immediately hide the previous successful sample.
    retry: false,
  });
  const replacePeers = (peers: Peer[]) => {
    const current = latest.current;
    latest.current = { ...current, tunnel: { ...current.tunnel, peers } };
    current.patch({ peers });
  };
  const add = async () => {
    if (addingRef.current) return;
    addingRef.current = true;
    setAdding(true);
    setError(null);
    try {
      const pair = await api.keygenPeerKeypair();
      if (!active.current) return;
      const peer: Peer = {
        name: "", public_key: pair.public_key, private_key: { plaintext: pair.private_key },
        preshared_key: null, allowed_ips: [],
      };
      replacePeers([...latest.current.tunnel.peers, peer]);
      setSelected(peer);
    } catch (error) {
      if (active.current) latest.current.setError(error);
    } finally {
      addingRef.current = false;
      if (active.current) setAdding(false);
    }
  };
  const exportPeer = async (peer: Peer, format: "conf" | "amnezia" = "conf") => {
    setError(null);
    try {
      const blob = format === "amnezia"
        ? await api.peerAmnezia(tunnel.name, peer.name)
        : await api.peerConf(tunnel.name, peer.name);
      if (!active.current) return;
      const suffix = format === "amnezia" ? "vpn" : "conf";
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      try {
        anchor.href = url;
        anchor.download = `${tunnel.name}-${peer.name}.${suffix}`;
        document.body.appendChild(anchor);
        anchor.click();
      } finally {
        anchor.remove();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      if (active.current) latest.current.setError(error);
    }
  };
  return (
    <>
      <InfoNote>Добавление и удаление пира применяются на работающем туннеле сразу при сохранении черновика, без общего применения. Изменение ключей или порта самого туннеля вступает в силу только после применения.</InfoNote>
      <FormActions><Button disabled={disabled || adding} onClick={() => void add()}>+ Добавить пира</Button></FormActions>
      <div className="table-wide tunnel-peers-table">
      <DataTable heads={["Имя", "Активность", "Действия"]} empty={<EmptyState>Пиров нет.</EmptyState>}
        rows={tunnel.peers.map((peer) => [
          peer.name || "Новый пир",
          peerActivityLabel(activity.isSuccess ? activity.data?.[tunnel.name]?.[peer.name] : undefined),
          <FormActions>
            <Button disabled={created} onClick={() => {
              setError(null);
              void showQr(tunnel.name, peer.name, () => active.current).catch((error) => {
                if (active.current) latest.current.setError(error);
              });
            }}>QR</Button>
            <Button disabled={created} onClick={() => void exportPeer(peer, "conf")}>Экспорт конфигурации</Button>
            {/* Amnezia's own container format; its app does not import a bare .conf. */}
            <Button disabled={created || tunnel.protocol !== "awg"} onClick={() => void exportPeer(peer, "amnezia")}>Для Amnezia</Button>
            <Button onClick={() => setSelected(peer)}>Изменить</Button>
          </FormActions>,
        ])} />
      </div>
      {selected && <PeerEditor peer={selected} peers={tunnel.peers} subscribers={subscribers} disabled={disabled}
        cancel={() => setSelected(null)} save={(peer) => {
          replacePeers(latest.current.tunnel.peers.map((item) => item === selected ? peer : item));
          setSelected(null);
        }} remove={() => {
          replacePeers(latest.current.tunnel.peers.filter((item) => item !== selected));
          setSelected(null);
        }} />}
    </>
  );
}

function ClientHandshake({ status }: { status?: TunnelAvailability }) {
  const timestamp = status?.last_handshake;
  const dated = typeof timestamp === "number" && Number.isSafeInteger(timestamp) && timestamp > 0 &&
    !Number.isNaN(new Date(timestamp * 1000).getTime());
  if (dated && (status?.state === "recent_handshake" || status?.state === "stale_handshake")) {
    return <InlineStatus tone={status.state === "recent_handshake" ? "green" : "amber"}
      text={`${status.state === "recent_handshake" ? "Недавний handshake" : "Устаревший handshake"}: ${new Date(timestamp * 1000).toLocaleString("ru-RU")}`} />;
  }
  if (status?.state === "never_handshaked" && (timestamp === 0 || timestamp === null))
    return <InlineStatus tone="amber" text="Handshake ещё не было" />;
  return <InlineStatus tone="unknown" text="Handshake: состояние неизвестно" />;
}

export function Tunnels() {
  const { configuration: c } = useConfiguration();
  const [roleTab, setRoleTab] = useState<"clients" | "servers">("clients");
  const availability = useQuery({
    queryKey: queryKeys.tunnelAvailability(),
    queryFn: async ({ signal }) => {
      const result = await api.tunnelAvailability(signal);
      if (!result || typeof result !== "object" || Array.isArray(result))
        throw new Error("Некорректные данные handshake туннелей");
      return result;
    },
    enabled: roleTab === "clients" && c.tunnels.some((t) => t.role === "client"),
    refetchInterval: 30_000,
    retry: false,
  });
  const telemetry = useQuery({
    queryKey: queryKeys.serviceStatus(),
    queryFn: async ({ signal }) => {
      const result = await api.serviceStatus(signal);
      if (!Array.isArray(result.services) || typeof result.generated_at !== "string")
        throw new Error("Некорректный статус служб");
      return result;
    },
    enabled: c.tunnels.length > 0,
    refetchInterval: 30_000,
  });
  const [qr, setQr] = useState<{ peer: string; url: string } | null>(null);
  const qrUrl = useRef<string | null>(null);
  const qrRequest = useRef(0);
  useEffect(() => () => {
    qrRequest.current += 1;
    if (qrUrl.current) URL.revokeObjectURL(qrUrl.current);
    qrUrl.current = null;
  }, []);
  const closeQr = () => {
    qrRequest.current += 1;
    if (qrUrl.current) URL.revokeObjectURL(qrUrl.current);
    qrUrl.current = null;
    setQr(null);
  };
  const showQr = async (tunnel: string, peer: string, current: () => boolean) => {
    const request = ++qrRequest.current;
    const blob = await api.peerQr(tunnel, peer);
    if (request !== qrRequest.current || !current()) return;
    const url = URL.createObjectURL(blob);
    if (qrUrl.current) URL.revokeObjectURL(qrUrl.current);
    qrUrl.current = url;
    setQr({ peer, url });
  };
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
    dns_servers: [],
    keepalive: 25,
    obfuscation: {},
    preshared_key: null,
    header_protection_key: null,
    random_trailers: false,
    disable_cookies: false,
    open_port: true,
    default_route: false,
    mtu: null,
  });
  const [pendingAddresses, setPendingAddresses] = useState<Record<string, string>>({});
  const createTunnel = async (rows: Tunnel[], role: Tunnel["role"], protocol: Tunnel["protocol"]): Promise<Tunnel> => {
    const row = { ...emptyTunnel(rows), role, protocol, listen_port: role === "server" ? 51820 : null, open_port: false };
    if (row.private_key && "plaintext" in row.private_key && row.private_key.plaintext) return row;
    const keys = await api.keygenTunnel(row.protocol);
    if (!keys.private_key?.trim()) throw new Error("Сервер не вернул приватный ключ туннеля");
    const result = { ...row, ...keygenPatch(keys, row.protocol) };
    if (keys.subnet) {
      // The keygen subnet is randomised so two independently managed panels
      // never correlate on the same 10.66.x.0/24 (cross-host tunnel overlap
      // is a silent blackhole). It lands as the device's explicit address and
      // wins over the name-derived pool slot from then on.
      const host = role === "server" ? 1 : 2;
      const address = `${keys.subnet.split("/")[0].replace(/\.0$/, "")}.${host}/24`;
      setPendingAddresses((old) => ({ ...old, [result.interface]: address }));
    }
    return result;
  };
  return (
    <>
      <PageHeader>Туннели</PageHeader>
      <ValueTabs
        value={roleTab}
        change={setRoleTab}
        tabs={[
          { value: "clients", label: "Клиенты" },
          { value: "servers", label: "Серверы" },
        ]}
      />
      {roleTab === "clients" && <>
        <InfoNote>Handshake показывает обмен ключами с VPN-сервером, а не сквозную доступность интернета. Недавний — не старше 180 секунд. Это не URL-test и не указание выбранного участника группы.</InfoNote>
        <ErrorNotice error={availability.error} />
      </>}
      <Collection<Tunnel>
        kind="tunnels"
        showQr={showQr}
        addressOverrides={pendingAddresses}
        filter={(rows) => rows.filter((t) => t.role === (roleTab === "clients" ? "client" : "server"))}
        tunnelStatus={telemetry.isSuccess ? telemetry.data : undefined}
        tunnelAvailability={availability.isSuccess ? availability.data : undefined}
        title="Туннели"
        addLabel="+ Добавить туннель"
        configPatch={(rows, importedAddresses) => {
          const normalizedRows = rows.map((tunnel) => ({
            ...tunnel,
            default_route: tunnel.default_route === true,
          }));
          const patch = reconcileTunnelInterfaces(c, normalizedRows);
          const interfaces = (patch.interfaces ?? c.interfaces)
            .map((iface) => importedAddresses[iface.name] ? { ...iface, addresses: [importedAddresses[iface.name]] } : iface);
          return {
            ...patch,
            interfaces,
            tunnels: materializeTunnels({ ...c, ...patch, interfaces }, normalizedRows),
          };
        }}
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
          (t.dns_servers ?? []).length <= 2 && (t.dns_servers ?? []).every((v) => ipValid(v.trim())) &&
          numericValue(t.keepalive) &&
          (t.mtu == null || (Number.isInteger(t.mtu) && t.mtu >= 576 && t.mtu <= 65535)) &&
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
            (awgRequired.every((k) => awgValueValid(k, t.obfuscation[k])) &&
              Object.entries(t.obfuscation).every(([k, v]) => awgValueValid(k, v))))
        }
        clean={(t) => ({
          ...t,
          allowed_ips: normalize(t.allowed_ips),
          dns_servers: normalize(t.dns_servers ?? []),
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
        form={(t, patch, created, disabled, setError, importedAddresses) => (
          <>
          <PageSection title="Идентификация">
          <FormGrid>
            {created ? (
              <Field
                label="Имя туннеля"
                value={t.name}
                valid={nameValid(t.name)}
                hint="Латиница, цифры, «_»; до 31 символа"
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
            <Field label="Интерфейс" value={t.interface} readOnly />
            <FormWide><p className="sub">Устройство создаётся автоматически (зона LAN) и появится на странице «Сеть». Не используйте имя физического NIC — выберите «создать новый интерфейс».</p></FormWide>
            <Field label="Роль" value={t.role === "server" ? "сервер" : "клиент"} readOnly hint="Роль выбирается при создании и затем не меняется" />
            <Field label="Протокол" value={t.protocol === "wg" ? "WireGuard" : "AmneziaWG"} readOnly />
            <Field label="Адрес туннеля" value={importedAddresses[t.interface] ?? c.interfaces.find((i) => i.name === t.interface)?.addresses[0] ?? tunnelAddress(t, [...c.tunnels.filter((item) => item.name !== t.name), t])} readOnly hint="Адрес интерфейса; импортированный Address сохраняется при записи черновика" />
            <Field label="Публичный ключ" value="Не отображается" readOnly hint="Выводится из приватного ключа на хосте при применении" />
          </FormGrid>
          </PageSection>
          <PageSection title="Подключение"><FormGrid>
            {t.role === "server" && <>
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
                <Field label="DNS для клиентов" value={(t.dns_servers ?? []).join(", ")}
                  valid={(t.dns_servers ?? []).length <= 2 && (t.dns_servers ?? []).every((v) => ipValid(v.trim()))}
                  hint="До двух IP через запятую; пусто — резолвер туннеля"
                  onChange={(v) => patch({ dns_servers: v ? split(v) : [] })} />
                <Toggle
                  label="Открыть порт на WAN"
                  value={t.open_port}
                  onChange={(open_port) => patch({ open_port })}
                />
                <Field
                  label="MTU туннеля"
                  type="number"
                  value={t.mtu ?? ""}
                  valid={t.mtu == null || (Number.isInteger(t.mtu) && t.mtu >= 576 && t.mtu <= 65535)}
                  hint="Пусто — умолчание хоста. Для AmneziaWG рекомендуется 1200: паддинги съедают запас MTU и полные пакеты фрагментируются"
                  onChange={(v) => patch({ mtu: v.trim() === "" ? null : Number(v) })}
                />
            </>}
            {t.role === "client" && <>
                <Field label="Endpoint" value={t.endpoint ?? ""} valid={!!t.endpoint?.trim()} onChange={(endpoint) => patch({ endpoint })} />
                <Field label="AllowedIPs" value={t.allowed_ips.join(",")} valid={ipsValid(t.allowed_ips)} hint="AllowedIPs ≠ маршрут" onChange={(v) => patch({ allowed_ips: split(v) })} />
                <Field label="Keepalive, с" value={String(t.keepalive)} valid={numericValue(t.keepalive)}
                  hint="Секунды или диапазон AWG 3+, например 25-35"
                  onChange={(v) => patch({ keepalive: /^[0-9]+$/.test(v) ? Number(v) : v })} />
                <Field
                  label="MTU туннеля"
                  type="number"
                  value={t.mtu ?? ""}
                  valid={t.mtu == null || (Number.isInteger(t.mtu) && t.mtu >= 576 && t.mtu <= 65535)}
                  hint="Пусто — умолчание хоста. Для AmneziaWG рекомендуется 1200: паддинги съедают запас MTU и полные пакеты фрагментируются"
                  onChange={(v) => patch({ mtu: v.trim() === "" ? null : Number(v) })}
                />
                <FormWide><FormControlLabel label="Использовать туннель как маршрут по умолчанию"
                  control={<Checkbox checked={t.default_route === true}
                    onChange={(_, default_route) => patch({ default_route })} />} /></FormWide>
                {t.default_route === true && <FormWide><InfoNote severity="warning">Весь трафик хоста, включая доступ к панели и SSH, пойдёт через туннель.</InfoNote></FormWide>}
            </>}
          </FormGrid></PageSection>
          <PageSection title="Ключи"><FormGrid>
            <FormWide><InfoNote severity="warning">Повторная генерация ключей разорвёт соединение клиентов. Обновите конфигурации другой стороны.</InfoNote></FormWide>
            {t.role === "client" && <>
              <Field label="Публичный ключ сервера" value={t.server_public_key ?? ""} valid={!!t.server_public_key?.trim()} onChange={(server_public_key) => patch({ server_public_key })} />
              <SecretField label="Preshared key" value={t.preshared_key} showOriginalHint={false} change={(preshared_key) => patch({ preshared_key })} />
            </>}
            <div>
              <SecretField label="Приватный ключ" value={t.private_key} change={(v) => patch({ private_key: v ?? { plaintext: "" } })} />
              <FormActions><Button disabled={disabled} onClick={() => void api.keygenTunnel(t.protocol)
                .then((keys) => patch(keygenPatch(keys, t.protocol)))
                .catch(setError)}>Сгенерировать ключи</Button></FormActions>
            </div>
            {t.private_key && !("plaintext" in t.private_key) && <FormWide><p className="sub">Публичный ключ этого туннеля для удалённых клиентов не отображается: он выводится из приватного на хосте при применении.</p></FormWide>}
          </FormGrid></PageSection>
          <PageSection title="Дополнительно"><ExpertDisclosure>
            {t.protocol === "awg" && (
              <Card title="Обфускация">
                  <FormGrid>
                    {awgFields.map((k) => (
                      <Field
                        key={k}
                        label={k}
                        value={t.obfuscation[k] === undefined ? "" : String(t.obfuscation[k])}
                        hint={awgSignatureKeys.includes(k) ? "Сигнатурный пакет, напр. <r 2><b 0x…>" : "Значение или диапазон, напр. 100-120"}
                        valid={
                          t.obfuscation[k] === undefined
                            ? !awgRequired.includes(k)
                            : awgValueValid(k, t.obfuscation[k])
                        }
                        onChange={(v) => {
                          const obfuscation = { ...t.obfuscation };
                          if (v.trim() === "") delete obfuscation[k];
                          else obfuscation[k] = awgInput(k, v);
                          patch({ obfuscation });
                        }}
                      />
                    ))}
                    <FormWide>
                      <SecretField label="HeaderProtectionKey" value={t.header_protection_key} showOriginalHint={false} change={(header_protection_key) => patch({ header_protection_key })} />
                    </FormWide>
                    <Toggle label="RandomTrailers" value={t.random_trailers} onChange={(random_trailers) => patch({ random_trailers })} />
                    <Toggle label="DisableCookies" value={t.disable_cookies} onChange={(disable_cookies) => patch({ disable_cookies })} />
                  </FormGrid>
                </Card>
            )}
          </ExpertDisclosure></PageSection>
          </>
        )}
      />
      <Dialog open={!!qr} onClose={closeQr} aria-labelledby="peer-qr-title">
        <DialogTitle id="peer-qr-title">QR-код пира {qr?.peer}</DialogTitle>
        <DialogContent>{qr && <img src={qr.url} alt={`QR-код пира ${qr.peer}`} style={{ maxWidth: "100%" }} />}</DialogContent>
        <DialogActions>
          {qr && <Button component="a" href={qr.url} download={`${qr.peer}.png`}>Скачать PNG</Button>}
          <Button onClick={closeQr}>Закрыть</Button>
        </DialogActions>
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
    <>
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
        <>
        <PageSection title="Идентификация"><FormGrid>
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
        </FormGrid></PageSection>
        <PageSection title="Подключение"><FormGrid>
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
        </FormGrid></PageSection>
        <PageSection title="Сертификат"><FormGrid>
          <Select
            label="Режим сертификата"
            value={s.certificate_mode}
            options={Object.entries(certificateModeLabels).map(([value, label]) => ({ value, label }))}
            onChange={(certificate_mode) => patch({ certificate_mode: certificate_mode as CaddySite["certificate_mode"] })}
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
        </FormGrid></PageSection>
        </>
      )}
    />
    <p className="sub">
      Состояние сертификата на устройстве панель пока не читает: колонка «Статус» показывает только известное ей — выпуск произойдёт при применении.
    </p>
    </>
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
        addLabel="+ Добавить домен"
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
          <>
          <PageSection title="Идентификация"><FormGrid>
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
          </FormGrid></PageSection>
          <PageSection title="Подключение"><FormGrid>
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
            <InterfaceSelect
              label="WAN-интерфейс"
              value={d.wan_interface}
              interfaces={c.interfaces.filter((i) => i.zone === "wan")}
              emptyLabel="Выберите интерфейс"
              error={!d.wan_interface}
              helperText={!d.wan_interface ? "Выберите значение" : undefined}
              onChange={(wan_interface) => patch({ wan_interface })}
            />
          </FormGrid></PageSection>
          <PageSection title="Секрет"><FormGrid>
            <SecretField
              label="API token / TSIG key"
              value={d.api_token}
              change={(v) => patch({ api_token: v ?? { plaintext: "" } })}
            />
          </FormGrid></PageSection>
          </>
        )}
      />
      <p className="sub">
        Статус DDNS агент пока не отдаёт через HTTP API; результат последней
        попытки обновления в панели не отображается.
      </p>
    </>
  );
}
