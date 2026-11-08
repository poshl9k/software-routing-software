import { Alert, Box, Button, Chip, CircularProgress, TextField, Typography } from "@mui/material";
import { useEffect, useState, type FormEvent } from "react";
import { masterApi, type MasterTelegramSettings } from "./api";
import { ErrorNotice } from "./pages";

export function TelegramPage() {
  const [settings, setSettings] = useState<MasterTelegramSettings | null>(null);
  const [publicUrl, setPublicUrl] = useState("");
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let mounted = true;
    masterApi.telegramSettings().then(value => {
      if (!mounted) return;
      setSettings(value);
      setPublicUrl(value.public_url ?? (location.protocol === "https:" ? location.origin : ""));
    }).catch(reason => { if (mounted) setError(reason); })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  async function save(event: FormEvent) {
    event.preventDefault();
    setSaving(true); setError(null);
    try {
      const result = await masterApi.configureTelegram({ bot_token: token.trim(), public_url: publicUrl.trim() });
      setSettings(result);
      setPublicUrl(result.public_url ?? "");
      setToken("");
    } catch (reason) { setError(reason); }
    finally { setSaving(false); }
  }

  return <Box>
    <Box className="section-head"><Typography variant="h2">Telegram</Typography></Box>
    <ErrorNotice error={error} />
    {loading ? <Box className="loading"><CircularProgress /></Box> : <>
      {settings && <Chip size="small" variant="outlined" color={settings.configured ? "success" : "warning"}
        label={settings.configured ? "Бот настроен" : "Бот не настроен"} sx={{ mb: 2 }} />}
      <Alert severity="info" sx={{ mb: 2 }}>Используйте отдельного мастер-бота. Уведомления и оплата выключены.</Alert>
      <Box component="form" onSubmit={save} className="form" sx={{ maxWidth: 520 }}>
        <TextField label="Публичный адрес портала" type="url" value={publicUrl}
          onChange={event => setPublicUrl(event.target.value)} placeholder="https://my.example.ru" required fullWidth />
        <TextField label="Токен отдельного мастер-бота" type="password" value={token}
          onChange={event => setToken(event.target.value)} autoComplete="new-password" required fullWidth />
        <Button type="submit" variant="contained" disabled={saving || token.trim().length < 20 || !publicUrl.startsWith("https://")}>
          {saving ? <CircularProgress size={18} /> : "Сохранить"}</Button>
      </Box>
    </>}
  </Box>;
}
