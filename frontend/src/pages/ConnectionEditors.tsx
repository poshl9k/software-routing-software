import { useState, type ReactNode } from "react";
import { Button, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";
import { useConfiguration } from "../state";
import type { Tunnel, CaddySite, DDNSUpdate, Configuration, Interface, Secret } from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { ErrorNotice } from "../components/ErrorNotice";
import { EditorShell } from "../components/EditorShell";
import { Field } from "../components/Field";
import { FormActions, FormGrid, FormWide } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { Select, SelectField, InterfaceSelect } from "../components/Select";
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

const ipsValid = (v: string[]) =>
  v.filter((s) => s.trim()).every((s) => addressValid(s.trim()));
const split = (v: string) => v.split(",");
const awgRequired = ["Jc", "S1", "S2", "H1", "H2", "H3", "H4"];
const awgFields = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];

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

/** Auto-create a LAN-zone interface for every tunnel device that is not yet
 * declared, so a tunnel never reuses (and breaks) a physical NIC's name.
 * Traffic from the tunnel then lands in the LAN zone by default. The tunnel
 * name is stored as the interface description so the Network page shows which
 * tunnel owns the device. */
function withTunnelInterfaces(interfaces: Interface[], rows: Tunnel[]): Interface[] {
  const result = [...interfaces];
  const byName = new Map(result.map((i) => [i.name, i]));
  for (const tunnel of rows) {
    if (!tunnel.interface) continue;
    const description = tunnelDescription(tunnel);
    const existing = byName.get(tunnel.interface);
    if (!existing) {
      const created = pendingInterface(tunnel.interface, description);
      byName.set(tunnel.interface, created);
      result.push(created);
    } else if (!existing.description && description) {
      // Fill an empty description with the owning tunnel's name; an operator-set
      // description on the Network page is left untouched.
      const updated = { ...existing, description };
      byName.set(tunnel.interface, updated);
      result[result.indexOf(existing)] = updated;
    }
  }
  return result;
}

/** Interface description for an auto-created tunnel device (the tunnel name). */
function tunnelDescription(tunnel: Tunnel): string | null {
  const name = tunnel.name.trim().slice(0, 64);
  return name || null;
}
function SecretField({
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
  valid,
  form,
  summary,
  clean = (v) => v,
  rowActions,
  configPatch,
}: {
  kind: "tunnels" | "sites" | "ddns";
  title: string;
  addLabel: string;
  empty: (rows: T[]) => T;
  valid: (v: T) => boolean;
  clean?: (v: T) => T;
  form: (v: T, patch: (p: Partial<T>) => void, created: boolean, noConfiguration: boolean) => ReactNode;
  summary: (v: T) => ReactNode[];
  rowActions?: (row: T) => ReactNode;
  /** Extra configuration derived from the edited rows (e.g. auto-created
   * tunnel interfaces). Merged into the whole-configuration save. */
  configPatch?: (rows: T[]) => Partial<Configuration>;
}) {
  const { configuration: c, version, noConfiguration } = useConfiguration();
  const editor = useDraftEditor<EditableRow<T>[]>();
  const [next, setNext] = useState(0);
  const collection = c[kind] as T[];
  const editing = editor.value;
  const isEdit = editor.isEdit;
  const allValid =
    !!editing &&
    editing.every(({ row }) => valid(row)) &&
    new Set(editing.map((v) => v.row.name)).size === editing.length;
  const save = () =>
    editor.save((value) => {
      const rows = value.map((v) => v.row);
      return {
        ...c,
        tunnels: c.tunnels,
        sites: c.sites,
        ddns: c.ddns,
        [kind]: rows.map((v) => clean(v)),
        ...(configPatch ? configPatch(rows) : {}),
      };
    });
  return (
    <>
      <ErrorNotice error={editor.error} />
      <Card
        title={title}
        action={
          !isEdit && (
            <Button
              disabled={!version}
              onClick={() => {
                editor.begin(collection.map((row, id) => ({ id, created: false, row })));
                setNext(collection.length);
              }}
            >
              Редактировать
            </Button>
          )
        }
      >
        <EditorShell
          isEdit={isEdit}
          saving={editor.saving}
          valid={!!allValid && !!version}
          onCancel={editor.cancel}
          onSave={() => void save()}
          view={
            <DataTable
              heads={
                kind === "tunnels"
                  ? ["Имя", "Роль", "Протокол", "Статус", "QR"]
                  : kind === "sites"
                    ? ["Имя", "Hostname", "Upstream", "Сертификат", "Статус"]
                    : ["Имя", "Провайдер", "Hostname", "Статус"]
              }
              rows={collection.map((row) => {
                const cells = summary(row);
                if (rowActions && !noConfiguration) {
                  const actions = rowActions(row);
                  if (actions) cells.push(actions);
                }
                return cells;
              })}
            />
          }
          edit={() =>
            editing ? (
              <>
                {editing.map(({ id, row, created }) => (
                  <Card
                    key={id}
                    title={row.name || "Новая запись"}
                    action={
                      <DeleteButton
                        label={`Удалить ${row.name || "запись"}`}
                        onClick={() =>
                          editor.setValue(editing.filter((v) => v.id !== id))
                        }
                      />
                    }
                  >
                    {form(
                      row,
                      (patch) =>
                        editor.setValue(
                          editing.map((v) =>
                            v.id === id
                              ? { ...v, row: { ...v.row, ...patch } }
                              : v,
                          ),
                        ),
                      created,
                      noConfiguration,
                    )}
                  </Card>
                ))}
                <FormActions>
                  <Button
                    onClick={() => {
                      editor.setValue([
                        ...editing,
                        { id: next, created: true, row: empty(editing.map((v) => v.row)) },
                      ]);
                      setNext(next + 1);
                    }}
                  >
                    {addLabel}
                  </Button>
                </FormActions>
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
    </>
  );
}
export function Tunnels() {
  const { configuration: c } = useConfiguration();
  const [qr,setQr]=useState<{peer:string;url:string}|null>(null); const [qrError,setQrError]=useState<unknown>(null);
  const showQr=async(tunnel:string,peer:string)=>{setQrError(null);try{const blob=await api.peerQr(tunnel,peer);setQr({peer,url:URL.createObjectURL(blob)});}catch(e){setQrError(e);}};
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
        configPatch={(rows) => ({
          interfaces: withTunnelInterfaces(c.interfaces, rows),
        })}
        empty={(rows) => ({
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
        })}
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
          "—",
        ]}
        form={(t, patch, created, disabled) => (
          <FormGrid>
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
            {created ? (
              <SelectField
                label="Роль"
                value={t.role}
                options={["server", "client"]}
                onChange={(role) =>
                  patch({
                    role,
                    peers: [],
                    endpoint: null,
                    server_public_key: null,
                    listen_port: role === "server" ? 51820 : null,
                  })
                }
              />
            ) : (
              <Field
                label="Роль"
                value={t.role === "server" ? "сервер" : "клиент"}
                readOnly
              />
            )}
            <SelectField
              label="Протокол"
              value={t.protocol}
              options={["wg", "awg"]}
              onChange={(protocol) => patch({ protocol })}
            />
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
                  .catch((e) => { setQrError(e); })}>Сгенерировать ключи</Button>
              </FormActions>
            </div>
            {t.private_key && !("plaintext" in t.private_key) && (
              <FormWide>
                <p className="sub">Публичный ключ этого туннеля для удалённых клиентов не отображается: он выводится из приватного на хосте при применении.</p>
              </FormWide>
            )}
            {t.role === "server" ? (
              <>
                <Field
                  label="Порт"
                  type="number"
                  value={t.listen_port ?? ""}
                  valid={portValid(t.listen_port ?? 0)}
                  onChange={(v) => patch({ listen_port: Number(v) })}
                />
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
                            onChange={(v) => update({ allowed_ips: split(v) })}
                          />
                          <SecretField label="Preshared key" value={p.preshared_key} showOriginalHint={false} change={(preshared_key) => update({ preshared_key })} />
                          <FormWide>
                            <SecretField label="Приватный ключ пира (входит в клиентский конфиг)" value={p.private_key ?? null} showOriginalHint={false} change={(private_key) => update({ private_key })} />
                          </FormWide>
                          <FormWide>
                            <FormActions>
                              <Button disabled={disabled} onClick={() => void api.keygenPeerKeypair().then((pair) => update({ public_key: pair.public_key, private_key: { plaintext: pair.private_key } })).catch((e) => setQrError(e))}>Сгенерировать ключи пира</Button>
                              <Button disabled={disabled} onClick={() => void api.keygenPeer().then((key) => update({ preshared_key: { plaintext: key.preshared_key } })).catch((e) => setQrError(e))}>Сгенерировать PSK</Button>
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
                        .catch((e) => setQrError(e))
                    }
                  >
                    + Добавить пира
                  </Button>
                </FormActions>
              </>
            ) : (
              <>
                <Field
                  label="Endpoint"
                  value={t.endpoint ?? ""}
                  valid={!!t.endpoint?.trim()}
                  onChange={(endpoint) => patch({ endpoint })}
                />
                <Field
                  label="Публичный ключ сервера"
                  value={t.server_public_key ?? ""}
                  valid={!!t.server_public_key?.trim()}
                  onChange={(server_public_key) => patch({ server_public_key })}
                />
                <Field
                  label="AllowedIPs"
                  value={t.allowed_ips.join(",")}
                  valid={ipsValid(t.allowed_ips)}
                  onChange={(v) => patch({ allowed_ips: split(v) })}
                />
                <Field
                  label="Keepalive"
                  type="number"
                  value={t.keepalive}
                  valid={
                    Number.isInteger(t.keepalive) &&
                    t.keepalive >= 0 &&
                    t.keepalive <= 65535
                  }
                  onChange={(v) => patch({ keepalive: Number(v) })}
                />
              </>
            )}
            {t.protocol === "awg" && (
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
      <p className="sub">
        AllowedIPs ≠ маршрут. Роль после создания не меняется.
      </p>
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
        s.certificate_mode,
        s.certificate_mode === "passthrough" ? "TLS не завершается" : "—",
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
          <SelectField
            label="Режим сертификата"
            value={s.certificate_mode}
            options={["http01", "dns01", "manual", "passthrough"]}
            onChange={(certificate_mode) => patch({ certificate_mode })}
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
        summary={(d) => [d.name, d.provider, d.hostname, "—"]}
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