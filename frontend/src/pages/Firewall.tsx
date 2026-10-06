import { useState } from "react";
import { Alert, Button } from "@mui/material";
import { useConfiguration } from "../state";
import { api } from "../api";
import type { ImportPreview } from "../types";
import type { Configuration, FirewallRule, Alias } from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { ValueTabs } from "../components/Tabs";
import { ErrorNotice } from "../components/ErrorNotice";
import { PageHeader } from "../components/PageHeader";
import { Field } from "../components/Field";
import { Select, SelectField, InterfaceSelect } from "../components/Select";
import { Toggle } from "../components/Toggle";
import { EditorFooter, EditorFieldset } from "../components/EditorShell";
import {
  nameValid,
  endpointValid,
  ipValid,
  portValid,
  addressElementValid,
  portElementValid,
} from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";

type Editable = Pick<
  Configuration,
  | "firewall_rules"
  | "port_forwards"
  | "outbound_nat"
  | "outbound_nat_mode"
  | "aliases"
>;
const protocols: FirewallRule["protocol"][] = [
  "any",
  "tcp",
  "udp",
  "icmp",
  "ipv6-icmp",
];
const uniqueName = (name: string, rows: { name: string }[]) =>
  nameValid(name) && rows.filter((r) => r.name === name).length === 1;
const aliasValid = (a: Alias, aliases: Alias[]) =>
  uniqueName(a.name, aliases) &&
  a.elements
    .filter(Boolean)
    .every(a.type === "address" ? addressElementValid : portElementValid) &&
  a.includes.filter(Boolean).every(nameValid);

export default function Firewall() {
  const {
    configuration: c,
    version,
    saveDraft,
    error: apiError,
    draftDirty,
  } = useConfiguration();
  const editor = useDraftEditor<Editable>();
  const [exportFormat,setExportFormat]=useState<"json"|"txt"|"csv">("json"); const [importText,setImportText]=useState(""); const [preview,setPreview]=useState<ImportPreview|null>(null); const [importMode,setImportMode]=useState<"replace"|"skip">("skip");
  const downloadAliases=async()=>{editor.setError(null);try{const blob=await api.exportAliases(exportFormat,null);const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`aliases.${exportFormat}`;a.click();URL.revokeObjectURL(url);}catch(e){editor.setError(e);}};
  const previewAliases=async(data:string)=>{editor.setError(null);try{let body:{aliases:Alias[]}|{data:string}={data};try{const parsed=JSON.parse(data);const imported=Array.isArray(parsed)?parsed:parsed?.aliases;if(Array.isArray(imported))body={aliases:imported as Alias[]};}catch{/* TXT/CSV input */}setPreview(await api.previewAliases(body));}catch(e){editor.setError(e);}};
  const importAliases=async()=>{if(!preview)return;editor.setError(null);try{await api.importAliases(preview.aliases,importMode);const aliases=importMode==="replace"?preview.aliases:[...c.aliases,...preview.aliases.filter(a=>!c.aliases.some(x=>x.name===a.name))];await saveDraft({...c,aliases});editor.setValue(editor.value?{...editor.value,aliases}:null);setPreview(null);}catch(e){editor.setError(e);}};
  const [tab, setTab] = useState("wan");
  const rows: Editable = editor.value ?? c;
  const isEditMode = editor.isEdit;
  const patch = (value: Partial<Editable>) => editor.setValue({ ...rows, ...value });
  const zones = [
    ...new Set([
      "wan",
      "lan",
      "router",
      ...c.interfaces.flatMap((i) => (i.zone ? [i.zone] : [])),
      ...rows.firewall_rules.map((r) => r.ingress_zone),
    ]),
  ];
  const zone = zones.includes(tab);
  const wan = c.interfaces.filter((i) => i.zone === "wan").map((i) => i.name);
  const rules = rows.firewall_rules
    .map((r, index) => ({ ...r, index }))
    .filter((r) => r.ingress_zone === tab)
    .sort((a, b) => a.order - b.order);
  const updateRule = (index: number, value: Partial<FirewallRule>) =>
    patch({
      firewall_rules: rows.firewall_rules.map((r, i) =>
        i === index ? { ...r, ...value } : r,
      ),
    });
  const setZoneRules = (ordered: FirewallRule[]) =>
    patch({
      firewall_rules: [
        ...rows.firewall_rules.filter((r) => r.ingress_zone !== tab),
        ...ordered.map((r, order) => ({ ...r, order })),
      ],
    });
  const reorder = (index: number, delta: number) => {
    const ordered = rules.map(({ index: _index, ...r }) => r);
    [ordered[index], ordered[index + delta]] = [
      ordered[index + delta],
      ordered[index],
    ];
    setZoneRules(ordered);
  };
  const allValid =
    rows.firewall_rules.every(
      (r) =>
        uniqueName(r.name, rows.firewall_rules) &&
        endpointValid(r.src) &&
        endpointValid(r.dst),
    ) &&
    rows.port_forwards.every(
      (p) =>
        uniqueName(p.name, rows.port_forwards) &&
        wan.includes(p.interface) &&
        portValid(p.external_port) &&
        portValid(p.target_port) &&
        ipValid(p.target) &&
        (!p.wan_address || ipValid(p.wan_address)),
    ) &&
    rows.outbound_nat.every(
      (n) =>
        uniqueName(n.name, rows.outbound_nat) &&
        nameValid(n.egress_zone) &&
        endpointValid(n.src) &&
        endpointValid(n.dst) &&
        (n.translation === "primary" || ipValid(n.translation)),
    ) &&
    rows.aliases.every((a) => aliasValid(a, rows.aliases));
  const save = async () => {
    if (!allValid) return;
    await editor.save((value) => ({
      ...c,
      ...value,
      aliases: value.aliases.map((a) => ({
        ...a,
        elements: a.elements.filter(Boolean),
        includes: a.includes.filter(Boolean),
      })),
    }));
  };
  const remove = (fn: () => void, label: string) => (
    <DeleteButton label={label} onClick={fn} />
  );
  return (
    <>
      <PageHeader>Firewall</PageHeader>
      <ErrorNotice error={editor.error ?? apiError} />
      {!isEditMode && (
        <div className="toolbar-actions">
          <Button
            disabled={!version}
            onClick={() => {
              editor.begin({
                firewall_rules: c.firewall_rules,
                port_forwards: c.port_forwards,
                outbound_nat: [...c.outbound_nat].sort(
                  (a, b) => a.order - b.order,
                ),
                outbound_nat_mode: c.outbound_nat_mode,
                aliases: c.aliases,
              });
            }}
          >
            Редактировать
          </Button>
        </div>
      )}
      <ValueTabs
        value={tab}
        change={setTab}
        tabs={[...zones, "Port Forward", "Outbound NAT", "Псевдонимы"].map((z) => ({
          value: z,
          label: z,
        }))}
      />
      <EditorFieldset disabled={editor.saving}>
        {zone && (
          <Card title={`Правила зоны ${tab}`}>
            <DataTable
              heads={[
                "Порядок",
                "Имя",
                "Протокол",
                "Источник",
                "Назначение",
                "Действие",
                "Включено",
                "Лог",
                "Порт",
                "",
              ]}
              rows={rules.map((r, position) =>
                isEditMode
                  ? [
                      <>
                        <span>{r.order}</span>
                        <Button
                          aria-label={`Вверх ${r.name}`}
                          disabled={position === 0}
                          onClick={() => reorder(position, -1)}
                        >
                          ↑
                        </Button>
                        <Button
                          aria-label={`Вниз ${r.name}`}
                          disabled={position === rules.length - 1}
                          onClick={() => reorder(position, 1)}
                        >
                          ↓
                        </Button>
                      </>,
                      <Field
                        ariaLabel="Имя правила"
                        value={r.name}
                        valid={uniqueName(r.name, rows.firewall_rules)}
                        hint="Латиница, цифры, _; до 31 символа; уникальное имя"
                        onChange={(name) => updateRule(r.index, { name })}
                      />,
                      <SelectField
                        ariaLabel="Протокол"
                        value={r.protocol}
                        options={protocols}
                        onChange={(protocol) =>
                          updateRule(r.index, { protocol })
                        }
                      />,
                      <Field
                        ariaLabel="Источник"
                        value={r.src}
                        valid={endpointValid(r.src)}
                        hint="any, IP/CIDR, @алиас, zone:lan"
                        onChange={(src) => updateRule(r.index, { src })}
                      />,
                      <Field
                        ariaLabel="Назначение"
                        value={r.dst}
                        valid={endpointValid(r.dst)}
                        hint="any, IP/CIDR, @алиас, zone:lan"
                        onChange={(dst) => updateRule(r.index, { dst })}
                      />,
                      <SelectField
                        ariaLabel="Действие"
                        value={r.action}
                        options={["pass", "block", "reject"]}
                        onChange={(action) => updateRule(r.index, { action })}
                      />,
                      <Toggle
                        label="Включено"
                        value={r.enabled}
                        onChange={(enabled) => updateRule(r.index, { enabled })}
                      />,
                      <Toggle
                        label="Лог"
                        value={r.log}
                        onChange={(log) => updateRule(r.index, { log })}
                      />,
                      <Field
                        ariaLabel="Порт / @алиас"
                        value={r.destination_ports ?? ""}
                        onChange={(destination_ports) =>
                          updateRule(r.index, {
                            destination_ports: destination_ports || null,
                          })
                        }
                      />,
                      remove(
                        () =>
                          setZoneRules(
                            rules
                              .filter((rule) => rule.index !== r.index)
                              .map(({ index: _index, ...rule }) => rule),
                          ),
                        `Удалить правило ${r.name || `#${r.index + 1}`}`,
                      ),
                    ]
                  : [
                      r.order,
                      r.name,
                      r.protocol,
                      r.src,
                      r.dst,
                      <Badge tone={r.action === "pass" ? "green" : "red"}>
                        {r.action}
                      </Badge>,
                      r.enabled ? "да" : "нет",
                      r.log ? "●" : "—",
                      r.destination_ports,
                      "—",
                    ],
              )}
            />
            {isEditMode && (
              <Button
                onClick={() =>
                  patch({
                    firewall_rules: [
                      ...rows.firewall_rules,
                      {
                        name: "",
                        ingress_zone: tab,
                        protocol: "any",
                        src: "any",
                        dst: "any",
                        destination_ports: null,
                        action: "block",
                        order: Math.max(-1, ...rules.map((r) => r.order)) + 1,
                        enabled: true,
                        log: false,
                        counters: { states: 0, packets: 0, bytes: 0 },
                      },
                    ],
                  })
                }
              >
                + Добавить правило
              </Button>
            )}
            <p className="sub">
              First match wins. В конце набора — неявный default deny. Pass
              разрешает, block блокирует, reject отклоняет с ответом.
            </p>
            <Badge>
              Anti-lockout: доступ к панели с lan —{" "}
              {c.anti_lockout ? "вкл" : "выкл"}
            </Badge>
          </Card>
        )}
        {(zone || tab === "Port Forward") && (
          <Card title="Port Forward">
            <DataTable
              heads={[
                "Имя",
                "Интерфейс",
                "Протокол",
                "Внешний порт",
                "Цель",
                "Порт цели",
                "WAN-адрес",
                "",
              ]}
              rows={rows.port_forwards.map((p, index) => {
                const update = (v: Partial<typeof p>) =>
                  patch({
                    port_forwards: rows.port_forwards.map((row, i) =>
                      i === index ? { ...row, ...v } : row,
                    ),
                  });
                return isEditMode
                  ? [
                      <Field
                        ariaLabel="Имя Port Forward"
                        value={p.name}
                        valid={uniqueName(p.name, rows.port_forwards)}
                        onChange={(name) => update({ name })}
                      />,
                      <InterfaceSelect
                        ariaLabel="WAN-интерфейс"
                        value={p.interface}
                        interfaces={c.interfaces.filter((i) => i.zone === "wan")}
                        emptyLabel="Выберите интерфейс"
                        error={!p.interface}
                        helperText={!p.interface ? "Выберите значение" : undefined}
                        onChange={(value) => update({ interface: value })}
                      />,
                      <SelectField
                        ariaLabel="Протокол"
                        value={p.protocol}
                        options={["tcp", "udp"]}
                        onChange={(protocol) => update({ protocol })}
                      />,
                      <Field
                        ariaLabel="Внешний порт"
                        type="number"
                        value={p.external_port}
                        valid={portValid(p.external_port)}
                        onChange={(v) => update({ external_port: Number(v) })}
                      />,
                      <Field
                        ariaLabel="Цель"
                        value={p.target}
                        valid={ipValid(p.target)}
                        onChange={(target) => update({ target })}
                      />,
                      <Field
                        ariaLabel="Порт цели"
                        type="number"
                        value={p.target_port}
                        valid={portValid(p.target_port)}
                        onChange={(v) => update({ target_port: Number(v) })}
                      />,
                      <Field
                        ariaLabel="WAN-адрес (опционально)"
                        value={p.wan_address ?? ""}
                        valid={!p.wan_address || ipValid(p.wan_address)}
                        onChange={(v) => update({ wan_address: v || null })}
                      />,
                      <>
                        <Toggle
                          label="Включено"
                          value={p.enabled}
                          onChange={(enabled) => update({ enabled })}
                        />
                        {remove(
                          () =>
                            patch({
                              port_forwards: rows.port_forwards.filter(
                                (_, i) => i !== index,
                              ),
                            }),
                          `Удалить перенаправление портов ${p.name || `#${index + 1}`}`,
                        )}
                      </>,
                    ]
                  : [
                      p.name,
                      p.interface,
                      p.protocol,
                      p.external_port,
                      p.target,
                      p.target_port,
                      p.wan_address ?? "основной",
                      <Badge>авто{!p.enabled && " · выкл"}</Badge>,
                    ];
              })}
            />
            {isEditMode && (
              <Button
                onClick={() =>
                  patch({
                    port_forwards: [
                      ...rows.port_forwards,
                      {
                        name: "",
                        interface: wan[0] ?? "",
                        protocol: "tcp",
                        external_port: 80,
                        target: "",
                        target_port: 80,
                        wan_address: null,
                        enabled: true,
                      },
                    ],
                  })
                }
              >
                + Добавить Port Forward
              </Button>
            )}
            <p className="sub">
              Port forward приоритетнее локальных сервисов роутера на том же
              порту. FW-правило создаётся автоматически.
            </p>
          </Card>
        )}
        {(zone || tab === "Outbound NAT") && (
          <Card title="Outbound NAT">
            {isEditMode ? (
              <SelectField
                label="Режим NAT"
                value={rows.outbound_nat_mode}
                options={["automatic", "hybrid", "manual", "disabled"]}
                onChange={(outbound_nat_mode) => patch({ outbound_nat_mode })}
              />
            ) : (
              <Badge>{rows.outbound_nat_mode}</Badge>
            )}
            <DataTable
              heads={[
                "Имя",
                "Зона выхода",
                "Источник",
                "Назначение",
                "Протокол",
                "Translation",
                "Do not NAT",
                "",
              ]}
              rows={rows.outbound_nat.map((n, index) => {
                const update = (v: Partial<typeof n>) =>
                  patch({
                    outbound_nat: rows.outbound_nat.map((row, i) =>
                      i === index ? { ...row, ...v } : row,
                    ),
                  });
                return isEditMode
                  ? [
                      <Field
                        ariaLabel="Имя NAT"
                        value={n.name}
                        valid={uniqueName(n.name, rows.outbound_nat)}
                        onChange={(name) => update({ name })}
                      />,
                      <Field
                        ariaLabel="Зона выхода"
                        value={n.egress_zone}
                        valid={nameValid(n.egress_zone)}
                        onChange={(egress_zone) => update({ egress_zone })}
                      />,
                      <Field
                        ariaLabel="Источник NAT"
                        value={n.src}
                        valid={endpointValid(n.src)}
                        hint="any, IP/CIDR, @алиас, zone:lan"
                        onChange={(src) => update({ src })}
                      />,
                      <Field
                        ariaLabel="Назначение NAT"
                        value={n.dst}
                        valid={endpointValid(n.dst)}
                        hint="any, IP/CIDR, @алиас, zone:lan"
                        onChange={(dst) => update({ dst })}
                      />,
                      <SelectField
                        ariaLabel="Протокол NAT"
                        value={n.protocol}
                        options={["any", "tcp", "udp", "icmp"]}
                        onChange={(protocol) => update({ protocol })}
                      />,
                      <Field
                        ariaLabel="Translation"
                        value={n.translation}
                        valid={
                          n.translation === "primary" || ipValid(n.translation)
                        }
                        hint="primary или IP-адрес"
                        onChange={(translation) => update({ translation })}
                      />,
                      <Toggle
                        label="Do not NAT"
                        value={n.do_not_nat}
                        onChange={(do_not_nat) => update({ do_not_nat })}
                      />,
                      remove(
                        () =>
                          patch({
                            outbound_nat: rows.outbound_nat.filter(
                              (_, i) => i !== index,
                            ),
                          }),
                        `Удалить правило NAT ${n.name || `#${index + 1}`}`,
                      ),
                    ]
                  : [
                      n.name,
                      n.egress_zone,
                      n.src,
                      n.dst,
                      n.protocol,
                      n.translation,
                      n.do_not_nat ? "да" : "нет",
                      "",
                    ];
              })}
            />
            {isEditMode && (
              <Button
                onClick={() =>
                  patch({
                    outbound_nat: [
                      ...rows.outbound_nat,
                      {
                        name: "",
                        egress_zone: "wan",
                        src: "any",
                        dst: "any",
                        protocol: "any",
                        translation: "primary",
                        do_not_nat: false,
                        order:
                          Math.max(
                            -1,
                            ...rows.outbound_nat.map((n) => n.order),
                          ) + 1,
                      },
                    ],
                  })
                }
              >
                + Добавить NAT
              </Button>
            )}
            <p className="sub">
              First match wins. Путь выбирает таблица маршрутизации.
            </p>
          </Card>
        )}
        {(zone || tab === "Псевдонимы") && (
          <Card title="Псевдонимы (алиасы)">
            <div className="footer-actions"><Select label="Формат экспорта" value={exportFormat} options={[{value:"json",label:"JSON"},{value:"txt",label:"TXT"},{value:"csv",label:"CSV"}]} onChange={v=>setExportFormat(v as "json"|"txt"|"csv")}/><Button onClick={()=>void downloadAliases()}>Экспорт</Button></div>
            <div className="footer-actions"><Button component="label">Выбрать файл<input hidden type="file" accept=".json,.txt,.csv,text/plain,application/json" onChange={e=>{const file=e.target.files?.[0];if(file)void file.text().then(text=>{setImportText(text);void previewAliases(text);});}}/></Button><Field label="Данные для импорта (TXT/CSV)" multiline value={importText} onChange={setImportText}/><Button onClick={()=>void previewAliases(importText)}>Предпросмотр</Button></div>
            {preview&&<><DataTable heads={["Строка","Ошибка"]} rows={preview.errors.map(x=>[x.line,x.message])}/><DataTable heads={["Имя","Тип","Элементы","Includes"]} rows={preview.aliases.map(a=>[a.name,a.type,a.elements.join(", "),a.includes.join(", ")])}/><div className="footer-actions"><Select label="Режим импорта" value={importMode} options={[{value:"replace",label:"Заменить"},{value:"skip",label:"Пропустить совпадения"}]} onChange={v=>setImportMode(v as "replace"|"skip")}/><Button disabled={!preview.ok||preview.errors.length>0} onClick={()=>void importAliases()}>Импортировать и сохранить</Button></div>{!preview.ok&&<Alert severity="warning">Исправьте ошибки импорта перед продолжением.</Alert>}</>}
            <DataTable
              heads={["Имя", "Тип", "Содержимое", "Вложение", ""]}
              rows={rows.aliases.map((a, index) => {
                const update = (v: Partial<Alias>) =>
                  patch({
                    aliases: rows.aliases.map((row, i) =>
                      i === index ? { ...row, ...v } : row,
                    ),
                  });
                return isEditMode
                  ? [
                      <Field
                        ariaLabel="Имя алиаса"
                        value={a.name}
                        valid={uniqueName(a.name, rows.aliases)}
                        hint="Латиница, цифры, _; до 31 символа; уникальное имя"
                        onChange={(name) => update({ name })}
                      />,
                      <SelectField
                        ariaLabel="Тип алиаса"
                        value={a.type}
                        options={["address", "port"]}
                        onChange={(type) => update({ type })}
                      />,
                      <Field
                        ariaLabel="Элементы (построчно)"
                        multiline
                        value={a.elements.join("\n")}
                        valid={a.elements
                          .filter(Boolean)
                          .every(
                            a.type === "address"
                              ? addressElementValid
                              : portElementValid,
                          )}
                        hint={
                          a.type === "address"
                            ? "IP, CIDR или IP-IP"
                            : "tcp/80, udp/53, tcp/1000-2000"
                        }
                        onChange={(v) => update({ elements: v.split("\n") })}
                      />,
                      <Field
                        ariaLabel="Includes (построчно)"
                        multiline
                        value={a.includes.join("\n")}
                        valid={a.includes.filter(Boolean).every(nameValid)}
                        onChange={(v) => update({ includes: v.split("\n") })}
                      />,
                      remove(
                        () =>
                          patch({
                            aliases: rows.aliases.filter((_, i) => i !== index),
                          }),
                        `Удалить псевдоним ${a.name || `#${index + 1}`}`,
                      ),
                    ]
                  : [
                      a.name,
                      a.type,
                      a.elements.join(", "),
                      a.includes.join(", "),
                      "",
                    ];
              })}
            />
            {isEditMode && (
              <Button
                onClick={() =>
                  patch({
                    aliases: [
                      ...rows.aliases,
                      { name: "", type: "address", elements: [], includes: [] },
                    ],
                  })
                }
              >
                + Добавить алиас
              </Button>
            )}
          </Card>
        )}
      </EditorFieldset>
      {isEditMode && (
        <EditorFooter
          saving={editor.saving}
          valid={allValid && !!version}
          cancel={editor.cancel}
          save={() => void save()}
        />
      )}
      {draftDirty && version?.status === "draft" && (
        <p className="sub">
          Черновик изменён и ожидает применения (экран «Применение»).
        </p>
      )}
    </>
  );
}