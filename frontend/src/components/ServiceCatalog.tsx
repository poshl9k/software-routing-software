import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Typography } from "@mui/material";
import { api } from "../api";
import { queryKeys } from "../query";
import { tokens } from "../theme";
import type { CatalogResponse, CatalogService } from "../types";
import { Badge, type Tone } from "./Badge";
import { EmptyState } from "./EmptyState";
import { ErrorNotice } from "./ErrorNotice";
import { Field } from "./Field";
import { InfoNote } from "./InfoNote";
import { LoadingSkeleton } from "./LoadingSkeleton";

const categoryTones: Tone[] = ["blue", "purple", "green", "amber", "red"];
const monogramColors: Record<Tone, { color: string; backgroundColor: string }> = {
  blue: { color: tokens.badgeBlue, backgroundColor: tokens.badgeBlueSoft },
  purple: { color: tokens.purple, backgroundColor: tokens.purpleSoft },
  green: { color: tokens.badgeGreen, backgroundColor: tokens.successSoft },
  amber: { color: tokens.warning, backgroundColor: tokens.warningSoft },
  red: { color: tokens.badgeRed, backgroundColor: tokens.errorSoft },
};

export function ServiceCatalog({ open, onClose, onSelect, declaredTags = [] }: {
  open: boolean;
  onClose: () => void;
  onSelect: (ids: string[]) => void;
  declaredTags?: string[];
}) {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const catalog = useQuery<CatalogResponse>({ queryKey: queryKeys.presetCatalog(), queryFn: api.presetCatalog, enabled: open });
  const categories = catalog.data?.categories ?? [];
  const services = catalog.data?.services ?? [];
  const categoryNames = new Map(categories.map((item) => [item.key, item.title]));
  const categoryColors = new Map(categories.map((item, index) => [item.key, categoryTones[index % categoryTones.length]]));
  const term = search.trim().toLocaleLowerCase("ru");
  const visible = services.filter((service) =>
    (!category || service.category === category) &&
    (!term || [service.name, categoryNames.get(service.category) ?? "", service.notice ?? ""].some((value) => value.toLocaleLowerCase("ru").includes(term)))
  );
  const existing = new Set(declaredTags);
  const selectedServices = services.filter((service) => selected.includes(service.id));
  const coveredBy = (service: CatalogService) => selectedServices.find((item) => item.id !== service.id && item.covers.includes(service.id));
  const reset = () => { setSearch(""); setCategory(""); setSelected([]); };
  const close = () => { reset(); onClose(); };
  const choose = () => { onSelect(selected); close(); };
  const toggle = (id: string) => setSelected((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);

  return <Dialog open={open} onClose={close} aria-labelledby="service-catalog-title" maxWidth="md" fullWidth>
    <DialogTitle id="service-catalog-title">Каталог сервисов</DialogTitle>
    <DialogContent>
      <Stack spacing={2} sx={{ pt: 1 }}>
        <Field label="Поиск сервисов" placeholder="netflix, telegram, ai…" value={search} onChange={setSearch} />
        {!catalog.isPending && !catalog.error && <Typography variant="body2">{visible.length} сервисов</Typography>}
        {catalog.isPending ? <LoadingSkeleton /> : catalog.error ? <ErrorNotice error={catalog.error} /> : <>
          <Stack direction="row" gap={1} flexWrap="wrap" role="group" aria-label="Категории сервисов">
            <Chip label={`Все (${services.length})`} clickable color={!category ? "primary" : "default"} onClick={() => setCategory("")} aria-pressed={!category} />
            {categories.map((item) => <Chip key={item.key} label={`${item.title} (${item.count})`} clickable color={category === item.key ? "primary" : "default"} onClick={() => setCategory(item.key)} aria-pressed={category === item.key} />)}
          </Stack>
          {visible.length ? <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" }, gap: 1.5 }}>
            {visible.map((service) => {
              const tone = categoryColors.get(service.category) ?? "blue";
              const covered = coveredBy(service);
              const hasSet = service.declared || service.rule_sets.some((set) => existing.has(set.tag)) || selected.includes(service.id);
              return <Box key={service.id} sx={{ border: `1px solid ${selected.includes(service.id) ? tokens.accent : tokens.border}`, borderRadius: 2, p: 1.5, backgroundColor: tokens.surface }}>
                <Stack direction="row" spacing={1} alignItems="flex-start">
                  <Box aria-hidden="true" sx={{ ...monogramColors[tone], width: 36, height: 36, borderRadius: 1, display: "grid", placeItems: "center", fontWeight: 700, flexShrink: 0 }}>
                    {service.name.slice(0, 1).toLocaleUpperCase("ru")}
                  </Box>
                  <Box sx={{ minWidth: 0, flex: 1 }}>
                    <FormControlLabel control={<Checkbox checked={selected.includes(service.id)} onChange={() => toggle(service.id)} />} label={service.name} />
                    <Typography variant="caption" display="block" color="text.secondary">{categoryNames.get(service.category) ?? service.category}</Typography>
                  </Box>
                </Stack>
                {service.notice && <Typography variant="body2" sx={{ mt: 1 }}>{service.notice}</Typography>}
                <Stack direction="row" gap={0.75} flexWrap="wrap" sx={{ mt: 1 }}>
                  {hasSet && <Badge tone="green">набор уже есть</Badge>}
                  {covered && <Badge tone="purple">входит в {covered.name}</Badge>}
                </Stack>
              </Box>;
            })}
          </Box> : <EmptyState title="Сервисы не найдены">Попробуйте другой запрос или категорию.</EmptyState>}
        </>}
        <InfoNote>Ссылки на наборы правил ведут к сторонним источникам; происхождение и лицензии требуют проверки. Загрузку и обновление выполняет агент, а не браузер.</InfoNote>
      </Stack>
    </DialogContent>
    <DialogActions><Button onClick={close}>Отмена</Button><Button variant="contained" disabled={!selected.length || catalog.isPending || !!catalog.error} onClick={choose}>Выбрать ({selected.length})</Button></DialogActions>
  </Dialog>;
}
