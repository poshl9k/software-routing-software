import { useState } from "react";
import { Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Typography } from "@mui/material";
import type { HostInterface, Interface } from "../types";
import { Field } from "./Field";
import { Select } from "./Select";
import { FormGrid, FormWide } from "./Form";
import { InfoNote } from "./InfoNote";
import { WizardProgress } from "./WizardProgress";
import { addressValid, ifaceNameValid } from "./validators";

type Scenario = "dhcp" | "static" | "vlan" | "bridge";
type Choice = { scenario: Scenario; port: string; members: string[]; vlanId: string; name: string; description: string; address: string; zone: string };
const initial = (): Choice => ({ scenario: "dhcp", port: "", members: [], vlanId: "", name: "", description: "", address: "", zone: "wan" });
const scenarioLabels: Record<Scenario, string> = { dhcp: "Получать IP автоматически (DHCP)", static: "Статический IP", vlan: "VLAN", bridge: "Мост" };
const roleLabels: Record<string, string> = { wan: "Интернет (WAN)", lan: "Домашняя сеть (LAN)", "": "Не назначен" };
const steps = ["Сценарий", "Порты и адрес", "Роль", "Проверка"];

export function QuickConnectDialog({ open, onClose, onAdd, ports, existing, loading, unavailable }: {
  open: boolean;
  onClose: () => void;
  onAdd: (entry: Interface, references: string[]) => void;
  ports: HostInterface[];
  existing: Interface[];
  loading: boolean;
  unavailable: boolean;
}) {
  const [step, setStep] = useState(0);
  const [choice, setChoice] = useState<Choice>(initial);
  const set = (patch: Partial<Choice>) => setChoice((old) => ({ ...old, ...patch }));
  const close = () => { onClose(); setStep(0); setChoice(initial()); };
  const used = new Set(existing.map((i) => i.name));
  const physical = ports.filter((p) => p.kind === "physical");
  const availableParents = physical.filter((p) => !existing.some((i) => i.name === p.name && i.addressing === "dhcp"));
  const free = physical.filter((p) => !used.has(p.name));
  const bridgePorts = physical.filter((p) => {
    const row = existing.find((i) => i.name === p.name);
    return (!row || row.type === "physical" && !row.zone && row.addressing === "static" && !row.addresses.length) && !existing.some((i) => i.members.includes(p.name));
  });
  const isVirtual = choice.scenario === "vlan" || choice.scenario === "bridge";
  const type: Interface["type"] = choice.scenario === "bridge" ? "bridge" : choice.scenario === "vlan" ? "vlan" : "physical";
  const systemName = isVirtual ? choice.name.trim() : choice.port;
  const vlanId = Number(choice.vlanId);
  const needsAddress = choice.scenario !== "dhcp";
  const addressValidNow = !choice.address.trim() || (choice.address.includes("/") && addressValid(choice.address.trim()));
  const selectionValid = (
    (isVirtual ? ifaceNameValid(systemName) && !used.has(systemName) && !ports.some((p) => p.name === systemName) : free.some((p) => p.name === choice.port)) &&
    (choice.scenario === "bridge" ? choice.members.length >= 2 && choice.members.every((m) => bridgePorts.some((p) => p.name === m)) :
      (choice.scenario === "vlan" ? availableParents.some((p) => p.name === choice.port) && Number.isInteger(vlanId) && vlanId >= 1 && vlanId <= 4094 && !existing.some((i) => i.type === "vlan" && i.parent === choice.port && i.vlan_id === vlanId) : true)) &&
    addressValidNow && !existing.some((i) => i.addresses.some((a) => a.trim().toLowerCase() === choice.address.trim().toLowerCase() && !!choice.address.trim())) && (choice.scenario !== "static" || !!choice.address.trim())
  );
  const nextAllowed = step === 0 || step === 1 && selectionValid || step === 2 && (choice.scenario !== "dhcp" || !!choice.zone);
  const portOptions = (choice.scenario === "vlan" ? availableParents : free).map((p) => ({
    value: p.name, label: `${p.name} · MAC ${p.mac || "неизвестен"} · ${p.operstate === "UP" ? "подключён" : p.operstate === "DOWN" ? "отключён" : p.operstate}`,
  }));
  const add = () => {
    if (step !== 3 || !selectionValid || (choice.scenario === "dhcp" && !choice.zone)) return;
    const references = choice.scenario === "vlan" ? [choice.port] : choice.scenario === "bridge" ? choice.members : [];
    onAdd({ name: systemName, type, zone: choice.zone || null, description: choice.description.trim() || null,
      addressing: choice.scenario === "dhcp" ? "dhcp" : "static", addresses: needsAddress && choice.address.trim() ? [choice.address.trim()] : [],
      parent: choice.scenario === "vlan" ? choice.port : null, vlan_id: choice.scenario === "vlan" ? vlanId : null,
      members: choice.scenario === "bridge" ? choice.members : [] }, references);
    close();
  };
  return <Dialog open={open} onClose={close} aria-labelledby="quick-connect-title" maxWidth="sm" fullWidth>
    <DialogTitle id="quick-connect-title">Быстро подключить</DialogTitle>
    <DialogContent>
      <WizardProgress steps={steps} current={step} />
      {step === 0 && <Select label="Сценарий подключения" value={choice.scenario} options={(Object.keys(scenarioLabels) as Scenario[]).map((value) => ({ value, label: scenarioLabels[value] }))} onChange={(v) => setChoice({ ...initial(), scenario: v as Scenario, zone: v === "dhcp" ? "wan" : "lan" })} />}
      {step === 1 && <FormGrid>
        {choice.scenario !== "bridge" && <Select label={choice.scenario === "vlan" ? "Родительский порт" : "Физический порт"} value={choice.port} placeholder={{ label: "— выберите порт —" }} options={portOptions} onChange={(port) => set({ port })} />}
        {choice.scenario === "bridge" && <FormWide><Typography variant="body2">Порты моста (не менее двух)</Typography>{bridgePorts.map((p) => <FormControlLabel key={p.name} control={<Checkbox checked={choice.members.includes(p.name)} onChange={(_, checked) => set({ members: checked ? [...choice.members, p.name] : choice.members.filter((m) => m !== p.name) })} />} label={`${p.name} · MAC ${p.mac || "неизвестен"} · ${p.operstate === "UP" ? "подключён" : p.operstate === "DOWN" ? "отключён" : p.operstate}`} />)}</FormWide>}
        {isVirtual && <Field label="Системное имя" value={choice.name} valid={!choice.name || ifaceNameValid(systemName) && !used.has(systemName) && !ports.some((p) => p.name === systemName)} hint="Уникальное имя интерфейса в системе" onChange={(name) => set({ name })} />}
        <Field label="Дружественное имя" value={choice.description} maxLength={64} onChange={(description) => set({ description })} />
        {choice.scenario === "vlan" && <Field label="VLAN ID" type="number" value={choice.vlanId} inputProps={{ min: 1, max: 4094 }} valid={!choice.vlanId || Number.isInteger(vlanId) && vlanId >= 1 && vlanId <= 4094 && !existing.some((i) => i.type === "vlan" && i.parent === choice.port && i.vlan_id === vlanId)} onChange={(vlanId) => set({ vlanId })} />}
        {needsAddress && <Field label="Адрес (CIDR)" value={choice.address} placeholder="192.168.10.1/24" valid={addressValidNow} hint={choice.scenario === "static" ? "Укажите адрес в формате IP/маска" : "Необязательно; без адреса интерфейс остаётся без IP"} onChange={(address) => set({ address })} />}
        {(loading || unavailable || !physical.length || !free.length && choice.scenario !== "vlan") && <FormWide><InfoNote>{loading ? "Загрузка портов хоста…" : unavailable ? "Порты хоста недоступны. Подключение невозможно." : "Нет доступных физических портов."}</InfoNote></FormWide>}
      </FormGrid>}
      {step === 2 && <Select label="Роль интерфейса" value={choice.zone} placeholder={{ label: roleLabels[""] }} options={[{ value: "wan", label: roleLabels.wan }, { value: "lan", label: roleLabels.lan }]} onChange={(zone) => set({ zone })} />}
      {step === 3 && <FormGrid>
        <Field label="Название" value={choice.description.trim() || "Без названия"} readOnly />
        <Field label="Системное имя" value={systemName} readOnly />
        <Field label="Тип" value={type === "physical" ? "Физический" : type === "vlan" ? "VLAN" : "Мост"} readOnly />
        <Field label="Роль" value={roleLabels[choice.zone]} readOnly />
        <Field label="Адресация" value={choice.scenario === "dhcp" ? "DHCP" : choice.address.trim() || "Без IP-адреса"} readOnly />
        {choice.scenario === "vlan" && <Field label="Родитель и VLAN ID" value={`${choice.port} · ${choice.vlanId}`} readOnly />}
        {choice.scenario === "bridge" && <Field label="Участники" value={choice.members.join(", ")} readOnly />}
        <FormWide><InfoNote>Интерфейс будет добавлен только в локальный черновик. Сохранение и применение — отдельные действия.</InfoNote></FormWide>
      </FormGrid>}
    </DialogContent>
    <DialogActions>
      <Button onClick={close}>Отмена</Button>
      {step > 0 && <Button onClick={() => setStep(step - 1)}>Назад</Button>}
      {step < 3 ? <Button disabled={!nextAllowed} onClick={() => setStep(step + 1)}>Далее</Button> : <Button variant="contained" onClick={add}>Добавить в черновик</Button>}
    </DialogActions>
  </Dialog>;
}
