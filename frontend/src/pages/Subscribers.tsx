import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useQueries } from "@tanstack/react-query";
import {
  Button, Checkbox, Dialog, DialogContent, DialogTitle, FormControlLabel,
  Stack, Typography,
} from "@mui/material";
import { api, portalAdminApi } from "../api";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { FormGrid } from "../components/Form";
import { InfoNote } from "../components/InfoNote";
import { PageHeader } from "../components/PageHeader";
import { Select } from "../components/Select";
import { ValueTabs } from "../components/Tabs";
import { nameValid } from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { queryKeys } from "../query";
import { useConfiguration } from "../state";
import { tokens } from "../theme";
import type { Peer, Subscriber } from "../types";

/** Бейдж подписки в строке абонента: один факт — один бейдж. */
function subscriptionBadge(sub: { status: string; expires_at: string } | null) {
  if (!sub) return { tone: "blue" as const, text: "Нет подписки" };
  const days = Math.ceil((new Date(sub.expires_at).getTime() - Date.now()) / 86_400_000);
  if (sub.status === "expired" || days < 0) return { tone: "red" as const, text: "Подписка истекла" };
  if (days <= 7) return { tone: "amber" as const, text: `Истекает через ${days} дн.` };
  return { tone: "green" as const, text: "Активна" };
}

type TariffDraft = { id: number | null; name: string; device_limit: string; term_days: string; price_amount: string };

const positive = (v: string) => Number.isInteger(Number(v)) && Number(v) >= 1;

/** Полное имя портала. Первым — резерв portal.<ip>.nip.io: он работает без DNS
 * (nip.io); производный portal.<custom> требует ручной DNS-записи, поэтому
 * панели хватает резерва для работающей ссылки (ADR-0032, порядок как в
 * management.portal_names). */
function portalHost(record: { custom_hostname: string | null; address: string } | null | undefined) {
  if (!record) return null;
  if (record.custom_hostname) return `portal.${record.custom_hostname}`;
  if (typeof record.address === "string" && record.address) {
    return `portal.${record.address.split("/")[0]}.nip.io`;
  }
  return null;
}

/** Устройство абонента — пир туннеля, привязанный к нему по имени. */
function subscriberDevice(name: string, tunnels: { name: string; peers: Peer[] }[]) {
  return tunnels.flatMap((tunnel) =>
    tunnel.peers.filter((peer) => peer.subscriber === name)
      .map((peer) => ({ tunnel: tunnel.name, peer })));
}

const dnsModeLabel = (mode: Peer["dns_mode"]) =>
  mode === "panel" ? "Панель" : mode === "own" ? "Собственный" : "—";

/** Аватар-инициал абонента: цвет из токенов темы, без новых примитивов. */
function SubscriberAvatar({ name }: { name: string }) {
  return (
    <Typography
      aria-hidden
      sx={{
        flex: "0 0 auto", width: 30, height: 30, borderRadius: "50%",
        display: "flex", alignItems: "center", justifyContent: "center",
        backgroundColor: tokens.purpleSoft, color: tokens.purple,
        fontSize: 13, fontWeight: 600, textTransform: "uppercase",
      }}
    >
      {name.slice(0, 1)}
    </Typography>
  );
}

type CardTab = "overview" | "devices" | "subscription" | "manage";

export default function Subscribers() {
  const { configuration, version, user, error, refresh, setNotice } = useConfiguration();
  const queryClient = useQueryClient();
  const admin = user?.role === "admin";

  // ----- Абоненты (конфигурация) -----
  const editor = useDraftEditor<Subscriber>();
  const [originalName, setOriginalName] = useState<string | null>(null);
  const [deleteName, setDeleteName] = useState<string | null>(null);
  const subscribers = configuration.subscribers ?? [];
  const referenced = originalName !== null && subscriberDevice(originalName, configuration.tunnels).length > 0;
  const duplicate = !!editor.value && subscribers.some((row) =>
    row.name === editor.value?.name && row.name !== originalName);
  const valid = !!editor.value && nameValid(editor.value.name) && !duplicate;
  const close = () => { editor.cancel(); setOriginalName(null); };
  const save = async () => {
    if (!valid || !admin) return;
    await editor.save((value) => ({ ...configuration,
      subscribers: originalName === null ? [...subscribers, value] :
        subscribers.map((item) => item.name === originalName ? value : item),
    }));
  };
  const removeSubscriber = useMutation({
    mutationFn: (name: string) => portalAdminApi.deleteSubscriber(name),
    onSuccess: async (_result, name) => {
      // Серверный каскад уже убрал абонента, его пиров и правила из черновика.
      await refresh();
      setNotice(`Абонент ${name} удалён вместе с устройствами`);
      setDeleteName(null);
    },
  });

  // ----- Тарифы (БД портала; серверное состояние — TanStack Query) -----
  const hostRecord = useQuery({ queryKey: queryKeys.hostManagement(), queryFn: api.hostManagement, enabled: admin });
  const tariffs = useQuery({
    queryKey: queryKeys.portalTariffs(),
    queryFn: portalAdminApi.listTariffs,
    enabled: admin,
  });
  const tariffList = Array.isArray(tariffs.data) ? tariffs.data : [];
  const tariffOptions = tariffList.map((t) => ({ value: String(t.id), label: t.name }));
  const [tariffDraft, setTariffDraft] = useState<TariffDraft | null>(null);
  const tariffValid = !!tariffDraft && tariffDraft.name.trim().length > 0
    && positive(tariffDraft.device_limit) && positive(tariffDraft.term_days)
    && (tariffDraft.price_amount === "" || Number(tariffDraft.price_amount) >= 0);
  const saveTariff = useMutation({
    mutationFn: () => {
      if (!tariffDraft) throw new Error("no draft");
      const body = {
        name: tariffDraft.name.trim(),
        device_limit: Number(tariffDraft.device_limit),
        term_days: Number(tariffDraft.term_days),
        ...(tariffDraft.price_amount === "" ? {} : { price_amount: Number(tariffDraft.price_amount) }),
      };
      return tariffDraft.id === null ? portalAdminApi.createTariff(body)
        : portalAdminApi.updateTariff(tariffDraft.id, body);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.portalTariffs() });
      setNotice("Тариф сохранён");
      setTariffDraft(null);
    },
  });
  const [deleteTariffId, setDeleteTariffId] = useState<number | null>(null);
  const removeTariff = useMutation({
    mutationFn: (id: number) => portalAdminApi.deleteTariff(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.portalTariffs() });
      setNotice("Тариф удалён");
      setDeleteTariffId(null);
    },
    onError: () => setDeleteTariffId(null),
  });

  // ----- Подписки абонентов (для бейджа; нет сводного эндпоинта — по одному) -----
  const subscriptionQueries = useQueries({
    queries: subscribers.map((row) => ({
      queryKey: queryKeys.portalSubscription(row.name),
      queryFn: () => portalAdminApi.readSubscription(row.name),
      enabled: admin,
      retry: false,
    })),
  });
  const subscriptionOf = (index: number) => subscriptionQueries[index]?.data ?? null;

  // ----- Карточка абонента (модалка с вкладками) -----
  const [subTariff, setSubTariff] = useState("");
  const [cardFor, setCardFor] = useState<string | null>(null);
  const [cardTab, setCardTab] = useState<CardTab>("overview");
  const openCard = (name: string, tab: CardTab = "overview") => {
    setCardFor(name);
    setCardTab(tab);
    const sub = subscriptionOf(subscribers.findIndex((row) => row.name === name));
    setSubTariff(sub?.tariff_id != null ? String(sub.tariff_id) : "");
  };

  // ----- Приглашение -----
  const [inviteFor, setInviteFor] = useState<string | null>(null);
  const [inviteTariff, setInviteTariff] = useState("");
  const [inviteActivate, setInviteActivate] = useState(false);
  const [inviteResult, setInviteResult] = useState<{ link: string; password?: string; token: string } | null>(null);
  const openInvite = (name: string) => {
    setInviteFor(name);
    setInviteTariff(tariffOptions.length ? tariffOptions[0].value : "");
    setInviteActivate(false);
    setInviteResult(null);
  };
  const sendInvite = useMutation({
    mutationFn: () => portalAdminApi.createInvite(inviteFor!, {
      tariff_id: Number(inviteTariff), activate: inviteActivate,
    }),
    onSuccess: async (result) => {
      setInviteResult({
        link: portalHost(hostRecord.data)
          ? `https://${portalHost(hostRecord.data)}${result.invite_path ?? `/invite/${result.token}`}`
          : result.invite_path ?? `/invite/${result.token}`,
        password: result.password, token: result.token,
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.portalSubscription(inviteFor!) });
    },
  });
  const revokeInvite = useMutation({
    mutationFn: () => portalAdminApi.revokeInvite(inviteResult!.token),
    onSuccess: () => {
      setNotice("Приглашение отозвано");
      setInviteFor(null);
    },
  });
  const copy = async (text: string, what: string) => {
    await navigator.clipboard.writeText(text);
    setNotice(`${what} скопирован`);
  };

  // ----- Управление подпиской (вкладка карточки) -----
  const patchSubscription = useMutation({
    mutationFn: (body: { tariff_id?: number; renew?: boolean }) =>
      portalAdminApi.updateSubscription(cardFor!, body),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.portalSubscription(cardFor!) });
      setNotice("Подписка обновлена");
    },
  });

  // ----- Поиск и сортировка списка -----
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<"name" | "expiry">("name");
  const query = search.trim().toLowerCase();
  const visibleRows = subscribers
    .map((row, index) => ({ row, index, sub: subscriptionOf(index),
      devices: subscriberDevice(row.name, configuration.tunnels) }))
    .filter(({ row, devices }) => !query
      || row.name.toLowerCase().includes(query)
      || (row.label ?? "").toLowerCase().includes(query)
      || devices.some(({ tunnel, peer }) =>
        `${tunnel} / ${peer.name}`.toLowerCase().includes(query)
        || peer.allowed_ips.join(" ").toLowerCase().includes(query)))
    .sort((a, b) => sort === "name" ? a.row.name.localeCompare(b.row.name)
      // Раньше истекающие — первыми; абоненты без подписки — в конце.
      : (a.sub ? new Date(a.sub.expires_at).getTime() : Infinity)
        - (b.sub ? new Date(b.sub.expires_at).getTime() : Infinity));

  // ----- Контакт поддержки (настройка портала) -----
  const support = useQuery({ queryKey: queryKeys.portalSettings(), queryFn: portalAdminApi.readSettings, enabled: admin });
  const [supportUrl, setSupportUrl] = useState<string | null>(null);
  const supportEditing = supportUrl !== null;
  const saveSupport = useMutation({
    mutationFn: () => portalAdminApi.updateSettings({ support_url: supportUrl ?? "" }),
    onSuccess: async (data) => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.portalSettings() });
      setNotice("Контакт поддержки сохранён");
      setSupportUrl(null);
      return data;
    },
  });
  const supportValue = supportEditing ? supportUrl : (support.data?.support_url ?? null);

  const pageError = error ?? removeSubscriber.error ?? tariffs.error ?? saveTariff.error
    ?? removeTariff.error ?? sendInvite.error ?? revokeInvite.error ?? patchSubscription.error
    ?? support.error ?? saveSupport.error;
  const cardTabs = admin
    ? [
        { value: "overview" as const, label: "Обзор" },
        { value: "devices" as const, label: "Устройства" },
        { value: "subscription" as const, label: "Подписка" },
        { value: "manage" as const, label: "Управление" },
      ]
    : [
        { value: "overview" as const, label: "Обзор" },
        { value: "devices" as const, label: "Устройства" },
        { value: "subscription" as const, label: "Подписка" },
      ];
  return <>
    <PageHeader>Абоненты</PageHeader>
    <ErrorNotice error={pageError} />
    <Card title="Абоненты" action={admin ? <Button disabled={!version || removeSubscriber.isPending}
      onClick={() => { setOriginalName(null); editor.begin({ name: "", label: null }); }}>+ Абонент</Button> : undefined}>
      <FormGrid>
        <Field label="Поиск" value={search} placeholder="Имя, описание или устройство"
          onChange={setSearch} />
        <Select label="Сортировка" value={sort} onChange={(v) => setSort(v as "name" | "expiry")}
          options={[{ value: "name", label: "По имени" }, { value: "expiry", label: "По сроку подписки" }]} />
      </FormGrid>
      <div className="table-wide"><DataTable
        heads={["Абонент", "Устройств", "Устройства", "Подписка", "Действия"]}
        empty={search.trim()
          ? <EmptyState>Ничего не найдено по запросу «{search.trim()}».</EmptyState>
          : <EmptyState>Абонентов нет. Добавьте абонента, затем привяжите к нему пир.</EmptyState>}
        rows={visibleRows.map(({ row, sub, devices }) => {
          const badge = subscriptionBadge(sub);
          return [
            <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
              <SubscriberAvatar name={row.name} />
              <Button sx={{ px: 0, justifyContent: "flex-start" }}
                onClick={() => openCard(row.name)}>{row.label ? `${row.name} — ${row.label}` : row.name}</Button>
            </Stack>,
            devices.length,
            devices.map(({ tunnel, peer }) => `${tunnel} / ${peer.name}`).join(", ") || "Нет устройств",
            <Badge tone={badge.tone}>{badge.text}</Badge>,
            admin ? <>
              <Button disabled={tariffs.isLoading || tariffList.length === 0}
                onClick={() => openInvite(row.name)}>Пригласить</Button>
              <DeleteButton label={`Удалить абонента ${row.name}`} onClick={() => setDeleteName(row.name)} />
            </> : "—",
          ];
        })} /></div>
    </Card>
    <Card title="Тарифы" action={admin ? <Button disabled={tariffs.isLoading}
      onClick={() => setTariffDraft({ id: null, name: "", device_limit: "", term_days: "", price_amount: "" })}>+ Тариф</Button> : undefined}>
      <div className="table-wide"><DataTable heads={["Тариф", "Лимит устройств", "Срок, дней", "Цена", ""]}
        empty={<EmptyState>{tariffs.isLoading ? "Загрузка тарифов…" : "Тарифы не созданы."}</EmptyState>}
        rows={tariffList.map((row) => [
          row.name, row.device_limit, row.term_days,
          row.price_amount == null ? "—" : String(row.price_amount),
          admin ? <>
            <Button onClick={() => setTariffDraft({
              id: row.id, name: row.name, device_limit: String(row.device_limit),
              term_days: String(row.term_days),
              price_amount: row.price_amount == null ? "" : String(row.price_amount),
            })}>Редактировать</Button>
            <DeleteButton label={`Удалить тариф ${row.name}`} onClick={() => setDeleteTariffId(row.id)} />
          </> : "",
        ])} /></div>
    </Card>
    <Card title="Поддержка" action={admin ? <Button disabled={support.isLoading}
      onClick={() => setSupportUrl(support.data?.support_url ?? "")}>Изменить</Button> : undefined}>
      {admin && supportEditing ? <FormGrid>
        <Field label="Ссылка на TG-бот поддержки" required value={supportUrl ?? ""}
          hint="Формат https://t.me/<бот>; показывается абонентам в кабинете" onChange={(v) => setSupportUrl(v)} />
        <EditorFooter saving={saveSupport.isPending} valid={!support.isLoading}
          cancel={() => setSupportUrl(null)} save={() => saveSupport.mutate()} />
      </FormGrid> : supportValue ? <InfoNote>Контакт поддержки: <a href={supportValue} target="_blank" rel="noreferrer">{supportValue}</a></InfoNote>
        : <EmptyState>Контакт поддержки не задан.</EmptyState>}
    </Card>

    {/* Карточка абонента — сводка, устройства, подписка и управление */}
    {(() => {
      const index = subscribers.findIndex((row) => row.name === cardFor);
      if (cardFor === null || index < 0) return null;
      const row = subscribers[index];
      const sub = subscriptionOf(index);
      const badge = subscriptionBadge(sub);
      const devices = subscriberDevice(row.name, configuration.tunnels);
      const tariffName = sub?.tariff_id != null
        ? tariffList.find((t) => t.id === sub.tariff_id)?.name ?? null : null;
      return <Dialog open onClose={() => setCardFor(null)} fullWidth maxWidth="md" aria-labelledby="client-card-title">
        <DialogTitle id="client-card-title">Абонент: {row.name}</DialogTitle>
        <DialogContent>
          <ValueTabs tabs={cardTabs} value={cardTab} change={setCardTab} />
          {cardTab === "overview" && <dl className="kv">
            <dt>Описание</dt><dd>{row.label ?? "—"}</dd>
            <dt>Устройств</dt><dd>{devices.length}</dd>
            <dt>Подписка</dt><dd><Badge tone={badge.tone}>{badge.text}</Badge></dd>
            {sub?.expires_at && <><dt>Истекает</dt><dd>{new Date(sub.expires_at).toLocaleString("ru-RU")}</dd></>}
            <dt>Тариф</dt><dd>{tariffName ?? "—"}</dd>
          </dl>}
          {cardTab === "devices" && <DataTable heads={["Устройство", "Туннель", "Разрешённые IP", "DNS"]}
            empty={<EmptyState>У абонента нет устройств. Привяжите пир к нему в разделе «Серверы».</EmptyState>}
            rows={devices.map(({ tunnel, peer }) => [
              peer.name,
              tunnel,
              peer.allowed_ips.join(", ") || "—",
              dnsModeLabel(peer.dns_mode),
            ])} />}
          {cardTab === "subscription" && (sub === null
            ? <>
              <InfoNote>У абонента ещё нет подписки — выслайте приглашение.</InfoNote>
              {admin && <div className="form-actions">
                <Button disabled={tariffs.isLoading || tariffList.length === 0}
                  onClick={() => { setCardFor(null); openInvite(row.name); }}>Пригласить</Button>
              </div>}
            </>
            : <>
              <dl className="kv">
                <dt>Статус</dt><dd><Badge tone={badge.tone}>{badge.text}</Badge></dd>
                {sub.expires_at && <><dt>Истекает</dt><dd>{new Date(sub.expires_at).toLocaleString("ru-RU")}</dd></>}
              </dl>
              {admin && <>
                <FormGrid>
                  <Select label="Тариф" value={subTariff} options={tariffOptions} onChange={setSubTariff} />
                </FormGrid>
                <InfoNote>Понижение тарифа не отключает существующие устройства: абонент не сможет создавать новые, пока не влезет в лимит.</InfoNote>
                <div className="form-actions">
                  <Button disabled={!subTariff || patchSubscription.isPending}
                    onClick={() => patchSubscription.mutate({ tariff_id: Number(subTariff) })}>Сменить тариф</Button>
                  <Button disabled={!subTariff || patchSubscription.isPending}
                    onClick={() => patchSubscription.mutate({ renew: true })}>Продлить</Button>
                </div>
              </>}
            </>)}
          {cardTab === "manage" && admin && <>
            <InfoNote>Удаление убирает абонента вместе с его устройствами и правилами маршрутизации; служебные пиры (без абонента) не затрагиваются.</InfoNote>
            <div className="form-actions">
              <Button onClick={() => { setCardFor(null); setOriginalName(row.name); editor.begin(row); }}>Изменить</Button>
              <Button disabled={tariffs.isLoading || tariffList.length === 0}
                onClick={() => { setCardFor(null); openInvite(row.name); }}>Пригласить</Button>
              <DeleteButton label={`Удалить абонента ${row.name}`} onClick={() => { setCardFor(null); setDeleteName(row.name); }} />
            </div>
          </>}
        </DialogContent>
      </Dialog>;
    })()}

    {/* Редактор абонента — черновик конфигурации */}
    <Dialog open={editor.isEdit} onClose={editor.saving ? undefined : close} fullWidth maxWidth="sm" aria-labelledby="subscriber-editor-title">
      <DialogTitle id="subscriber-editor-title">Абонент: {originalName ?? "Новый абонент"}</DialogTitle>
      <DialogContent>
        <ErrorNotice error={editor.error ?? (duplicate ? new Error("Абонент с таким именем уже есть (subscriber.duplicate_name).") : null)} />
        {editor.value && <FormGrid>
          {referenced ? <Field label="Имя абонента" value={editor.value.name} readOnly hint="Сначала отвяжите устройства, чтобы изменить имя" /> :
            <Field label="Имя абонента" required value={editor.value.name} valid={nameValid(editor.value.name) && !duplicate}
              hint="Латиница, цифры, «_»; до 31 символа" onChange={(name) => editor.setValue({ ...editor.value!, name })} />}
          <Field label="Описание" value={editor.value.label ?? ""}
            onChange={(label) => editor.setValue({ ...editor.value!, label: label || null })} />
        </FormGrid>}
        <EditorFooter saving={editor.saving} valid={valid && admin} cancel={close} save={() => void save()} />
      </DialogContent>
    </Dialog>

    {/* Редактор тарифа — БД портала */}
    <Dialog open={tariffDraft !== null} onClose={() => setTariffDraft(null)} fullWidth maxWidth="sm" aria-labelledby="tariff-editor-title">
      <DialogTitle id="tariff-editor-title">Тариф: {tariffDraft?.id === null || tariffDraft?.id === undefined ? "новый" : tariffDraft?.name}</DialogTitle>
      <DialogContent>
        {tariffDraft && <FormGrid>
          <Field label="Название" required value={tariffDraft.name}
            onChange={(name) => setTariffDraft({ ...tariffDraft, name })} />
          <Field label="Лимит устройств" type="number" required value={tariffDraft.device_limit} inputProps={{ min: 1 }}
            hint="Сколько устройств может создать абонент" onChange={(v) => setTariffDraft({ ...tariffDraft, device_limit: v })} />
          <Field label="Срок подписки, дней" type="number" required value={tariffDraft.term_days} inputProps={{ min: 1 }}
            onChange={(v) => setTariffDraft({ ...tariffDraft, term_days: v })} />
          <Field label="Цена" type="number" value={tariffDraft.price_amount} inputProps={{ min: 0 }}
            hint="Заложено на будущее, в MVP не используется" onChange={(v) => setTariffDraft({ ...tariffDraft, price_amount: v })} />
        </FormGrid>}
        <EditorFooter saving={saveTariff.isPending} valid={tariffValid} cancel={() => setTariffDraft(null)}
          save={() => saveTariff.mutate()} />
      </DialogContent>
    </Dialog>

    {/* Приглашение */}
    <Dialog open={inviteFor !== null} onClose={sendInvite.isPending ? undefined : () => setInviteFor(null)} fullWidth maxWidth="sm" aria-labelledby="invite-title">
      <DialogTitle id="invite-title">Приглашение: {inviteFor ?? ""}</DialogTitle>
      <DialogContent>
        {inviteResult ? <>
          <InfoNote>Ссылка открывается на адресе портала. Приглашение одноразовое и действует 7 дней.</InfoNote>
          <FormGrid>
            <Field label="Ссылка-приглашение" value={inviteResult.link} readOnly
              hint="Абонент задаёт пароль сам; до активации ссылку можно отозвать" />
            {inviteResult.password && <Field label="Пароль" value={inviteResult.password} readOnly
              hint="Показан один раз: учётная запись уже активирована этим паролем" />}
          </FormGrid>
          {inviteResult.password && <InfoNote severity="warning">Готовый пароль перехватывается вместе со ссылкой и даёт доступ навсегда. Передавайте по защищённому каналу.</InfoNote>}
          <div className="form-actions">
            <Button onClick={() => void copy(inviteResult.link, "Ссылка")}>Скопировать ссылку</Button>
            {inviteResult.password && <Button onClick={() => void copy(inviteResult.password!, "Пароль")}>Скопировать пароль</Button>}
            <Button disabled={revokeInvite.isPending} onClick={() => revokeInvite.mutate()}>Отозвать</Button>
            <Button onClick={() => setInviteFor(null)}>Закрыть</Button>
          </div>
        </> : <>
          <FormGrid>
            <Select label="Тариф" value={inviteTariff} options={tariffOptions}
              placeholder={tariffOptions.length ? undefined : { label: "Тарифы не созданы", disabled: true }}
              onChange={setInviteTariff} />
          </FormGrid>
          <FormControlLabel control={<Checkbox checked={inviteActivate}
            onChange={(e) => setInviteActivate(e.target.checked)} />} label="Сразу задать пароль (ссылка с готовым доступом)" />
          {inviteActivate && <InfoNote severity="warning">Готовый пароль перехватывается вместе со ссылкой — доступ получит тот, кто первым её открыл. Это осознанный риск администратора.</InfoNote>}
          {!inviteActivate && <InfoNote>Абонент откроет ссылку и задаст пароль сам; до активации приглашение можно отозвать.</InfoNote>}
          <div className="form-actions">
            <Button disabled={!inviteTariff || sendInvite.isPending} onClick={() => sendInvite.mutate()}>Выслать приглашение</Button>
            <Button disabled={sendInvite.isPending} onClick={() => setInviteFor(null)}>Отмена</Button>
          </div>
        </>}
      </DialogContent>
    </Dialog>

    <ConfirmDialog open={deleteName !== null} title="Удалить абонента?" danger
      body={deleteName
        ? `Абонент ${deleteName} будет удалён вместе с его устройствами и правилами маршрутизации. Служебные пиры (без абонента) не затрагиваются. Действие необратимо.`
        : ""}
      confirmLabel="Удалить" cancelLabel="Отмена"
      onCancel={() => setDeleteName(null)} onConfirm={() => {
        if (deleteName) removeSubscriber.mutate(deleteName);
      }} />
    <ConfirmDialog open={deleteTariffId !== null} title="Удалить тариф?"
      body="Тариф с назначенными подписками удалить нельзя."
      confirmLabel="Удалить" cancelLabel="Отмена" danger
      onCancel={() => setDeleteTariffId(null)} onConfirm={() => removeTariff.mutate(deleteTariffId!)} />
  </>;
}
