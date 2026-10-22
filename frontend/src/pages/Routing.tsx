import { useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { ErrorNotice } from "../components/ErrorNotice";
import { ValueTabs } from "../components/Tabs";
import { useConfiguration } from "../state";
import { ProxiesEditor, RuleSets } from "./RoutingProxy";
import RoutingMasterPage from "./RoutingMaster";

type RoutingTab = "master" | "proxies" | "rulesets";

/** The «Маршрутизация» section: master wizard + proxy exits + rule-set sources.
 *  The legacy TProxy rules editor was removed: the backend renders sing-box
 *  (tproxy) from the master's routing_rules, so the legacy screen has no role. */
export default function Routing() {
  const { error: apiError } = useConfiguration();
  const [tab, setTab] = useState<RoutingTab>("master");
  return (
    <>
      <PageHeader>Маршрутизация</PageHeader>
      <ErrorNotice error={apiError} />
      <ValueTabs
        value={tab}
        change={setTab}
        tabs={[
          { value: "master", label: "Мастер маршрутизации" },
          { value: "proxies", label: "Прокси-выходы" },
          { value: "rulesets", label: "Источники списков" },
        ]}
      />
      {tab === "master" && <RoutingMasterPage />}
      {tab === "proxies" && <ProxiesEditor />}
      {tab === "rulesets" && <RuleSets />}
    </>
  );
}
