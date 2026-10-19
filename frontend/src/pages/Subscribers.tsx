import { useState } from "react";
import { Button, Dialog, DialogContent, DialogTitle } from "@mui/material";
import { Card } from "../components/Card";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { FormGrid } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { nameValid } from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { useConfiguration } from "../state";
import type { Subscriber } from "../types";

export default function Subscribers() {
  const { configuration, version, user, error, saveDraft, setNotice } = useConfiguration();
  const editor = useDraftEditor<Subscriber>();
  const [originalName, setOriginalName] = useState<string | null>(null);
  const [deleteName, setDeleteName] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<unknown>(null);
  const [deleting, setDeleting] = useState(false);
  const subscribers = configuration.subscribers ?? [];
  const devices = (name: string) => configuration.tunnels.flatMap((tunnel) =>
    tunnel.peers.filter((peer) => peer.subscriber === name)
      .map((peer) => `${tunnel.name} / ${peer.name}`));
  const referenced = originalName !== null && devices(originalName).length > 0;
  const duplicate = !!editor.value && subscribers.some((row) =>
    row.name === editor.value?.name && row.name !== originalName);
  const valid = !!editor.value && nameValid(editor.value.name) && !duplicate;
  const close = () => { editor.cancel(); setOriginalName(null); };
  const save = async () => {
    if (!valid || user?.role !== "admin") return;
    await editor.save((value) => ({ ...configuration,
      subscribers: originalName === null ? [...subscribers, value] :
        subscribers.map((item) => item.name === originalName ? value : item),
    }));
  };
  const remove = async () => {
    if (!deleteName || user?.role !== "admin" || deleting || devices(deleteName).length) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      const saved = await saveDraft({ ...configuration,
        subscribers: subscribers.filter((item) => item.name !== deleteName),
      });
      setNotice(`Черновик v${saved.id} сохранён`);
      setDeleteName(null);
    } catch (failure) {
      setDeleteError(failure);
    } finally {
      setDeleting(false);
    }
  };
  return <>
    <PageHeader>Абоненты</PageHeader>
    <ErrorNotice error={error ?? deleteError} />
    <Card title="Абоненты" action={user?.role === "admin" ? <Button disabled={!version || deleting}
      onClick={() => { setOriginalName(null); editor.begin({ name: "", label: null }); }}>+ Абонент</Button> : undefined}>
      <div className="table-wide"><DataTable heads={["Абонент", "Устройств", "Устройства", "Действия"]}
        empty={<EmptyState>Абонентов нет. Добавьте абонента, затем привяжите к нему пир.</EmptyState>}
        rows={subscribers.map((row) => {
          const refs = devices(row.name);
          return [
            row.label ? `${row.name} — ${row.label}` : row.name,
            refs.length,
            refs.join(", ") || "Нет устройств",
            user?.role === "admin" ? <>
              <Button disabled={deleting} onClick={() => { setOriginalName(row.name); editor.begin(row); }}>Редактировать</Button>
              <DeleteButton label={`Удалить абонента ${row.name}`} onClick={() => { setDeleteError(null); setDeleteName(row.name); }} />
            </> : "—",
          ];
        })} /></div>
    </Card>
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
        <EditorFooter saving={editor.saving} valid={valid && user?.role === "admin"} cancel={close} save={() => void save()} />
      </DialogContent>
    </Dialog>
    <ConfirmDialog open={deleteName !== null} title="Удалить абонента?"
      body={deleteName && devices(deleteName).length
        ? `Удаление заблокировано: абонент ${deleteName} привязан к устройствам ${devices(deleteName).join(", ")}. Сначала отвяжите пиры.`
        : `Абонент ${deleteName ?? ""} будет удалён из черновика.`}
      confirmLabel={deleteName && devices(deleteName).length ? "Понятно" : "Удалить из черновика"}
      cancelLabel="Отмена" danger
      onCancel={() => setDeleteName(null)} onConfirm={() => {
        if (deleteName && devices(deleteName).length) setDeleteName(null);
        else void remove();
      }} />
  </>;
}
