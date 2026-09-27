import { useState, type ReactNode } from "react";
import { Button, TextField, Typography, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";
import { useConfiguration } from "../state";
import type { Tunnel, CaddySite, DDNSUpdate, Secret } from "../types";
import { Badge, Card, DataTable, ErrorNotice } from "../ui";
import { api } from "../api";
import {
  Field,
  SelectField,
  EditorFooter,
  nameValid,
  portValid,
  addressValid,
} from "../editor";

const interfaceValid = (v: string) => /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(v);
const hostValid = (v: string, wildcard = false) =>
  (wildcard ? /^[a-zA-Z0-9*.-]+$/ : /^[a-zA-Z0-9.-]+$/).test(v);
const secretValid = (v: Secret | null) =>
  !!v && (!("plaintext" in v) || !!v.plaintext.trim());
const ipsValid = (v: string[]) =>
  v.filter((s) => s.trim()).every((s) => addressValid(s.trim()));
const split = (v: string) => v.split(",");
const normalize = (v: string[]) => v.map((s) => s.trim()).filter(Boolean);
const awgRequired = ["Jc", "S1", "S2", "H1", "H2", "H3", "H4"];
const awgFields = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];
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
    <TextField
      size="small"
      label={label}
      type="password"
      autoComplete="new-password"
      value={value && "plaintext" in value ? value.plaintext : ""}
      helperText={
        original && showOriginalHint
          ? "(сохранён); пустое поле сохраняет прежний секрет"
          : "Новый секрет"
      }
      onChange={(e) =>
        change(e.target.value ? { plaintext: e.target.value } : original)
      }
    />
  );
}
type Row = Tunnel | CaddySite | DDNSUpdate;
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
}: {
  kind: "tunnels" | "sites" | "ddns";
  title: string;
  addLabel: string;
  empty: () => T;
  valid: (v: T) => boolean;
  clean?: (v: T) => T;
  form: (v: T, patch: (p: Partial<T>) => void, created: boolean, demo: boolean) => ReactNode;
  summary: (v: T) => ReactNode[];
  rowActions?: (row: T) => ReactNode;
}) {
  const { configuration: c, version, saveDraft, demo } = useConfiguration();
  const [editing, setEditing] = useState<
    { id: number; created: boolean; row: T }[] | null
  >(null);
  const [next, setNext] = useState(0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const rows = c[kind] as T[];
  const allValid =
    !!editing &&
    editing.every(({ row }) => valid(row)) &&
    new Set(editing.map((v) => v.row.name)).size === editing.length;
  async function save() {
    if (!version || !editing || !allValid) return;
    setSaving(true);
    setError(null);
    try {
      await saveDraft({
        ...c,
        tunnels: c.tunnels,
        sites: c.sites,
        ddns: c.ddns,
        [kind]: editing.map((v) => clean(v.row)),
      });
      setEditing(null);
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  }
  return (
    <>
      <ErrorNotice error={error} />
      <Card
        title={title}
        action={
          !editing && (
            <Button
              disabled={!version}
              onClick={() => {
                setEditing(
                  rows.map((row, id) => ({ id, created: false, row })),
                );
                setNext(rows.length);
                setError(null);
              }}
            >
              Редактировать
            </Button>
          )
        }
      >
        {!editing ? (
          <DataTable
            heads={
              kind === "tunnels"
                ? ["Имя", "Роль", "Протокол", "Статус", "QR"]
                : kind === "sites"
                  ? ["Имя", "Hostname", "Upstream", "Сертификат", "Статус"]
                  : ["Имя", "Провайдер", "Hostname", "Статус"]
            }
            rows={rows.map((row) => {
              const cells = summary(row);
              if (rowActions && !demo) {
                const actions = rowActions(row);
                if (actions) cells.push(actions);
              }
              return cells;
            })}
          />
        ) : (
          <>
            <fieldset
              disabled={saving}
              style={{ border: 0, padding: 0, minWidth: 0 }}
            >
              {editing.map(({ id, row, created }) => (
                <Card key={id} title={row.name || "Новая запись"}>
                  {form(
                    row,
                    (patch) =>
                      setEditing(
                        editing.map((v) =>
                          v.id === id
                            ? { ...v, row: { ...v.row, ...patch } }
                            : v,
                        ),
                      ),
                    created,
                    demo,
                  )}
                  <Button
                    color="error"
                    onClick={() =>
                      setEditing(editing.filter((v) => v.id !== id))
                    }
                  >
                    Удалить
                  </Button>
                </Card>
              ))}
              <Button
                onClick={() => {
                  setEditing([
                    ...editing,
                    { id: next, created: true, row: empty() },
                  ]);
                  setNext(next + 1);
                }}
              >
                {addLabel}
              </Button>
            </fieldset>
            {!allValid && (
              <p role="status">
                Проверьте обязательные поля, формат значений и уникальность
                имён.
              </p>
            )}
            <EditorFooter
              saving={saving}
              valid={allValid && !!version}
              save={() => void save()}
              cancel={() => {
                setEditing(null);
                setError(null);
              }}
            />
          </>
        )}
      </Card>
    </>
  );
}
export function Tunnels() {
  const [qr,setQr]=useState<{peer:string;url:string}|null>(null); const [qrError,setQrError]=useState<unknown>(null);
  const showQr=async(tunnel:string,peer:string)=>{setQrError(null);try{const blob=await api.peerQr(tunnel,peer);setQr({peer,url:URL.createObjectURL(blob)});}catch(e){setQrError(e);}};
  return (
    <>
      {qrError && !qr && <ErrorNotice error={qrError} />}
      <Typography component="h1" variant="h1" className="page-title">
        Туннели
      </Typography>
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
        empty={() => ({
          name: "",
          interface: "",
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
          interfaceValid(t.interface) &&
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
          "TODO-API · handshake и трафик",
        ]}
        form={(t, patch, created, demo) => (
          <>
            {created ? (
              <Field
                label="Имя туннеля"
                value={t.name}
                valid={nameValid(t.name)}
                onChange={(name) => patch({ name })}
              />
            ) : (
              <TextField
                label="Имя туннеля"
                value={t.name}
                slotProps={{ input: { readOnly: true } }}
                helperText="Имя сохраняет привязку секретов"
              />
            )}
            <Field
              label="Интерфейс"
              value={t.interface}
              valid={interfaceValid(t.interface)}
              onChange={(v) => patch({ interface: v })}
            />
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
              <TextField
                label="Роль"
                value={t.role === "server" ? "сервер" : "клиент"}
                slotProps={{ input: { readOnly: true } }}
              />
            )}
            <SelectField
              label="Протокол"
              value={t.protocol}
              options={["wg", "awg"]}
              onChange={(protocol) => patch({ protocol })}
            />
            <SecretField
              label="Приватный ключ"
              value={t.private_key}
              change={(v) => patch({ private_key: v ?? { plaintext: "" } })}
            />
            <Button disabled={demo} onClick={() => void api.keygenTunnel(t.protocol)
              .then((keys) => patch({
                private_key: { plaintext: keys.private_key },
                ...(t.protocol === "awg" ? { obfuscation: keys.obfuscation ?? {} } : {}),
              }))
              .catch((e) => { setQrError(e); })}>Сгенерировать ключи</Button>
            {t.private_key && !("plaintext" in t.private_key) && (
              <p className="sub">Публичный ключ этого туннеля для удалённых клиентов не отображается: он выводится из приватного на хосте при применении.</p>
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
                    <Card key={index} title="Пир">
                      {p.preshared_key && "redacted" in p.preshared_key ? (
                        <TextField
                          label="Имя пира"
                          value={p.name}
                          slotProps={{ input: { readOnly: true } }}
                          helperText="Имя сохраняет привязку секретов"
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
                      <SecretField label="Приватный ключ пира (входит в клиентский конфиг)" value={p.private_key ?? null} showOriginalHint={false} change={(private_key) => update({ private_key })} />
                      <Button disabled={demo} onClick={() => void api.keygenPeerKeypair().then((pair) => update({ public_key: pair.public_key, private_key: { plaintext: pair.private_key } })).catch((e) => setQrError(e))}>Сгенерировать ключи пира</Button>
                      <Button disabled={demo} onClick={() => void api.keygenPeer().then((key) => update({ preshared_key: { plaintext: key.preshared_key } })).catch((e) => setQrError(e))}>Сгенерировать PSK</Button>
                      <Button onClick={()=>void showQr(t.name,p.name)}>QR-код</Button>
                      <Button disabled>Экспорт пира · TODO-API-EXPORT</Button>
                      <Button
                        onClick={() =>
                          patch({
                            peers: t.peers.filter((_, i) => i !== index),
                          })
                        }
                      >
                        Удалить пира
                      </Button>
                    </Card>
                  );
                })}
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
              <Card title="Обфускация">
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
              </Card>
            )}
          </>
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
        s.certificate_mode === "passthrough"
          ? "TLS не завершается · TODO-API"
          : "TODO-API",
      ]}
      form={(s, patch, created) => (
        <>
          {created ? (
            <Field
              label="Имя сайта"
              value={s.name}
              valid={nameValid(s.name)}
              onChange={(name) => patch({ name })}
            />
          ) : (
            <TextField
              label="Имя сайта"
              value={s.name}
              slotProps={{ input: { readOnly: true } }}
              helperText="Имя сохраняет привязку секретов"
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
          <TextField
            select
            label="WAN-адрес"
            value={s.wan_address ?? ""}
            SelectProps={{ native: true }}
            onChange={(e) => patch({ wan_address: e.target.value || null })}
          >
            <option value="">Автоматически</option>
            {Array.from(
              new Set([
                ...addresses,
                ...(s.wan_address ? [s.wan_address] : []),
              ]),
            ).map((a) => (
              <option key={a}>{a}</option>
            ))}
          </TextField>
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
              <p role="status">
                Конфликт с port forward: HTTP-01 требует свободных портов
                80/443.
              </p>
            )}
        </>
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
        summary={(d) => [d.name, d.provider, d.hostname, "TODO-API статус"]}
        form={(d, patch, created) => (
          <>
            {created ? (
              <Field
                label="Имя DDNS"
                value={d.name}
                valid={nameValid(d.name)}
                onChange={(name) => patch({ name })}
              />
            ) : (
              <TextField
                label="Имя DDNS"
                value={d.name}
                slotProps={{ input: { readOnly: true } }}
                helperText="Имя сохраняет привязку секретов"
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
            <SelectField
              label="WAN-интерфейс"
              value={d.wan_interface}
              options={wan}
              onChange={(wan_interface) => patch({ wan_interface })}
            />
          </>
        )}
      />
      <p className="sub">
        TODO-API статус: агент записывает name, provider, hostname, status
        (ok/failed), error в /run/vs-router/ddns-status.json; HTTP API пока
        недоступен.
      </p>
    </>
  );
}
