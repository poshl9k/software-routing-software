import { useState } from "react";
import {
  Alert, Button, Checkbox, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControlLabel, Typography,
} from "@mui/material";
import { useConfiguration } from "../state";
import { Card } from "../components/Card";
import { ErrorNotice } from "../components/ErrorNotice";
import { PageHeader } from "../components/PageHeader";
import { interfaceLabel } from "../components/Select";
import { useDraftEditor } from "../hooks/useDraftEditor";

export default function SSH() {
  const { configuration, version } = useConfiguration();
  const editor = useDraftEditor<string[]>();
  const [confirming, setConfirming] = useState(false);
  const chosen = editor.value ?? configuration.ssh?.interfaces ?? [];
  const members = new Set(configuration.interfaces.flatMap((i) => i.members));
  const options = configuration.interfaces.filter((i) => i.zone && !members.has(i.name));
  const wan = chosen.filter((name) => options.find((i) => i.name === name)?.zone === "wan");

  function toggle(name: string) {
    const next = chosen.includes(name)
      ? chosen.filter((value) => value !== name)
      : [...chosen, name];
    editor.setValue(next);
    editor.setError(null);
  }

  async function save() {
    setConfirming(false);
    await editor.save((interfaces) => ({
      ...configuration,
      ssh: {
        interfaces,
        wan_confirmed_interfaces: interfaces.filter(
          (name) => options.find((i) => i.name === name)?.zone === "wan",
        ),
      },
    }));
  }

  return (
    <div>
      <PageHeader>SSH</PageHeader>
      <Card title="Доступ по SSH">
        <Typography>Разрешите SSH только на нужных интерфейсах. Изменения вступят в силу после применения общей конфигурации.</Typography>
        <Alert severity="info">По умолчанию SSH закрыт на всех интерфейсах. Вход по паролю разрешён, в том числе на WAN при работающей защите от перебора.</Alert>
        <ErrorNotice error={editor.error} />
        {options.length === 0 && <Alert severity="warning">Сначала назначьте интерфейс сетевой зоне.</Alert>}
        {options.map((iface) => (
          <FormControlLabel key={iface.name} control={<Checkbox checked={chosen.includes(iface.name)}
            onChange={() => toggle(iface.name)} disabled={editor.saving} />}
            label={`${interfaceLabel(iface.name, configuration.interfaces)} · ${iface.zone === "wan" ? "WAN" : iface.zone}`} />
        ))}
        <div>
          <Button variant="contained" disabled={!version || editor.saving || editor.value === null}
            onClick={() => wan.length ? setConfirming(true) : void save()}>
            Сохранить
          </Button>
          <Button disabled={editor.saving || editor.value === null} onClick={editor.cancel}>
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