import { useState } from "react";
import {
  Alert, Button, Checkbox, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControlLabel, Typography,
} from "@mui/material";
import { useConfiguration } from "../state";
import { Card, ErrorNotice } from "../ui";

export default function SSH() {
  const { configuration, version, saveDraft, setNotice } = useConfiguration();
  const [editing, setEditing] = useState<string[] | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const chosen = editing ?? configuration.ssh?.interfaces ?? [];
  const members = new Set(configuration.interfaces.flatMap((i) => i.members));
  const options = configuration.interfaces.filter((i) => i.zone && !members.has(i.name));
  const wan = chosen.filter((name) => options.find((i) => i.name === name)?.zone === "wan");

  function toggle(name: string) {
    setEditing(chosen.includes(name) ? chosen.filter((value) => value !== name) : [...chosen, name]);
    setError(null);
  }

  async function save() {
    if (!version) return;
    setConfirming(false);
    setSaving(true);
    setError(null);
    try {
      const saved = await saveDraft({
        ...configuration,
        ssh: { interfaces: chosen, wan_confirmed_interfaces: wan },
      });
      setNotice(`Черновик v${saved.id} сохранён`);
      setEditing(null);
    } catch (err) {
      setError(err);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <Typography component="h1" variant="h1" className="page-title">SSH</Typography>
      <Card title="Доступ по SSH">
        <Typography>Разрешите SSH только на нужных интерфейсах. Изменения вступят в силу после применения общей конфигурации.</Typography>
        <Alert severity="info">По умолчанию SSH закрыт на всех интерфейсах. Вход по паролю разрешён, в том числе на WAN при работающей защите от перебора.</Alert>
        <ErrorNotice error={error} />
        {options.length === 0 && <Alert severity="warning">Сначала назначьте интерфейс сетевой зоне.</Alert>}
        {options.map((iface) => (
          <FormControlLabel key={iface.name} control={<Checkbox checked={chosen.includes(iface.name)}
            onChange={() => toggle(iface.name)} disabled={saving} />}
            label={`${iface.name} · ${iface.zone === "wan" ? "WAN" : iface.zone}`} />
        ))}
        <div>
          <Button variant="contained" disabled={!version || saving || editing === null}
            onClick={() => wan.length ? setConfirming(true) : void save()}>
            Сохранить
          </Button>
          <Button disabled={saving || editing === null} onClick={() => { setEditing(null); setError(null); }}>
            Отменить
          </Button>
        </div>
      </Card>
      <Dialog open={confirming} onClose={() => setConfirming(false)}>
        <DialogTitle>Разрешить SSH из WAN?</DialogTitle>
        <DialogContent>
          Вход по паролю через {wan.join(", ")} станет доступен из внешней сети после применения.
          Это повышает риск перебора пароля. Если защита Fail2Ban не работает, агент отклонит применение.
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirming(false)}>Отмена</Button>
          <Button color="warning" onClick={() => void save()}>Подтверждаю риск и сохраняю</Button>
        </DialogActions>
      </Dialog>
    </div>
  );
}
