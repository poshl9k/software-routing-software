import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import { emptyConfiguration, sampleConfiguration } from "../fixtures";
import { DHCP } from "../pages/Services";
import Firewall from "../pages/Firewall";
import { Tunnels } from "../pages/ConnectionEditors";
import Maintenance from "../pages/Maintenance";
import App from "../App";

function setup(configuration=sampleConfiguration, extras: (path:string,init?:RequestInit)=>Response|Promise<Response> = ()=>new Response("{}")) {
  const fetch=vi.fn(async(path:string,init?:RequestInit)=>
    path==="/api/auth/me"?new Response(JSON.stringify({id:1,username:"admin",role:"admin"}))
    :path==="/api/versions"?new Response(JSON.stringify([{id:1,status:"draft",configuration}]))
    :extras(path,init));
  vi.stubGlobal("fetch",fetch); return fetch;
}
function mount(node:React.ReactNode){render(<MemoryRouter><RouterProvider>{node}</RouterProvider></MemoryRouter>);}

it("loads runtime leases in the DHCP leases tab",async()=>{
  setup(emptyConfiguration,(path)=>path==="/api/dhcp/leases"?new Response(JSON.stringify([{ip:"192.168.1.5",mac:"aa:bb",hostname:"laptop",subnet:"192.168.1.0/24",expires_in:90}])):new Response("{}"));
  const user=userEvent.setup();mount(<DHCP/>);await user.click(screen.getByRole("tab",{name:"Аренды"}));expect(await screen.findByText("laptop")).toBeVisible();expect(screen.getByText("90")).toBeVisible();
});
it("opens the tunnel peer QR dialog from a blob response",async()=>{
  Object.defineProperty(URL,"createObjectURL",{configurable:true,value:vi.fn(()=>"blob:qr")});const fetch=setup(sampleConfiguration,(path)=>path.includes("/qr")?new Response(new Blob(["png"],{type:"image/png"})):new Response("{}"));
  const user=userEvent.setup();mount(<Tunnels/>);await user.click(await screen.findByRole("button",{name:"Редактировать"}));await user.click(screen.getAllByRole("button",{name:"QR-код"})[0]);expect(await screen.findByRole("dialog")).toBeVisible();expect(screen.getByRole("img",{name:/QR-код пира/})).toBeVisible();expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/tunnels/wg-office/peer/alina-laptop/qr"),expect.objectContaining({credentials:"include"}));
});
it("generates tunnel keys and fills private key plus AWG parameters",async()=>{
  const cfg={...emptyConfiguration,tunnels:[]};
  const fetch=setup(cfg,(path,init)=>path==="/api/keygen/tunnel"?new Response(JSON.stringify({private_key:"a".repeat(44),public_key:"b".repeat(44),obfuscation:{Jc:4,Jmin:35,Jmax:90,S1:12,S2:95,H1:11,H2:12,H3:13,H4:14}})):new Response(JSON.stringify({id:1,status:"draft",configuration:JSON.parse(String(init?.body))})));
  const user=userEvent.setup();mount(<Tunnels/>);await user.click(await screen.findByRole("button",{name:"Редактировать"}));await user.click(screen.getByRole("button",{name:"+ Добавить туннель"}));await user.selectOptions(screen.getByLabelText("Протокол"),"awg");await user.click(screen.getByRole("button",{name:"Сгенерировать ключи"}));await waitFor(()=>expect(screen.getByLabelText("Приватный ключ")).toHaveValue("a".repeat(44)));expect(fetch).toHaveBeenCalledWith("/api/keygen/tunnel",expect.objectContaining({method:"POST",body:JSON.stringify({protocol:"awg"})}));expect(screen.getByLabelText("H4")).toHaveValue(14);expect(screen.getByLabelText("Jmin")).toHaveValue(35);
});
it("generates and fills a peer PSK",async()=>{
  const fetch=setup(sampleConfiguration,(path)=>path==="/api/keygen/peer"?new Response(JSON.stringify({preshared_key:"p".repeat(44)})):new Response("{}"));
  const user=userEvent.setup();mount(<Tunnels/>);await user.click(await screen.findByRole("button",{name:"Редактировать"}));await user.click(screen.getAllByRole("button",{name:"Сгенерировать PSK"})[0]);await waitFor(()=>expect(screen.getAllByLabelText("Preshared key")[0]).toHaveValue("p".repeat(44)));expect(fetch).toHaveBeenCalledWith("/api/keygen/peer",expect.objectContaining({method:"POST",body:"{}"}));
});
it("exports aliases in the selected format",async()=>{
  const fetch=setup(emptyConfiguration,(path)=>path==="/api/aliases/export"?new Response("[]",{headers:{"Content-Type":"application/json"}}):new Response("{}"));
  Object.defineProperty(URL,"createObjectURL",{configurable:true,value:vi.fn(()=>"blob:aliases")});vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});const user=userEvent.setup();mount(<Firewall/>);await user.click(screen.getByRole("tab",{name:"Псевдонимы"}));await user.click(screen.getByRole("button",{name:"Экспорт"}));await waitFor(()=>expect(fetch).toHaveBeenCalledWith("/api/aliases/export",expect.objectContaining({method:"POST",body:JSON.stringify({format:"json",names:null})})));
});
it("renders and validates the ping host field",async()=>{
  setup(emptyConfiguration);mount(<Maintenance/>);const host=screen.getAllByLabelText("Узел")[0];expect(host).toHaveAttribute("aria-invalid","true");expect(screen.getByRole("button",{name:"Ping"})).toBeDisabled();
});
it("renders the maintenance screen through its route",async()=>{
  setup(emptyConfiguration);render(<MemoryRouter initialEntries={["/maintenance"]}><App/></MemoryRouter>);expect(await screen.findByRole("heading",{name:"Обслуживание",level:1})).toBeVisible();
});
it("shows the generated tunnel port rule on the WAN firewall tab", async () => {
  setup({
    ...sampleConfiguration,
    interfaces: [
      {
        name: "eth0",
        type: "physical",
        zone: "wan",
        description: null,
        addressing: "static",
        addresses: ["203.0.113.1/24"],
        parent: null,
        vlan_id: null,
        members: [],
      },
    ],
  });
  mount(<Firewall />);
  expect(await screen.findByText(/udp\/51820/)).toBeVisible();
});
it("warns that backup import needs a free draft and does not activate host config",async()=>{
  setup(emptyConfiguration);mount(<Maintenance/>);
  expect(await screen.findByText(/Перед импортом сбросьте текущий черновик/)).toBeVisible();
  expect(screen.getByText(/Импорт создаёт черновик, не применяет конфигурацию/)).toBeVisible();
});
it("imports backup into a draft without applying it",async()=>{
  let imported=false;
  const fetch=vi.fn(async(path:string)=>new Response(JSON.stringify(
    path==="/api/versions"?[{id:imported?2:1,status:imported?"draft":"confirmed",configuration:emptyConfiguration}]:
    path==="/api/auth/me"?{id:1,username:"admin",role:"admin"}:
    path==="/api/apply/status"?null:
    path==="/api/backup/restore"?(imported=true,{restored:1,skipped:1}):{},
  )));
  vi.stubGlobal("fetch",fetch);
  render(<MemoryRouter initialEntries={["/maintenance"]}><App/></MemoryRouter>);
  await screen.findByText("admin");
  const file=new File(["{}"],"backup.json",{type:"application/json"});
  Object.defineProperty(file,"text",{value:async()=>JSON.stringify({schema_version:1,versions:[{},{}],users:[]})});
  await userEvent.upload(screen.getByRole("button",{name:"Выбрать файл импорта"}).querySelector("input")!,file);
  await userEvent.click(await screen.findByRole("checkbox",{name:/Разрешить пропуск записей без секретов/}));
  await userEvent.click(await screen.findByRole("button",{name:"Импортировать в черновик"}));
  expect(await screen.findByText(/Создан черновик из последней версии; пропущено версий: 1/)).toBeVisible();
  expect(fetch).toHaveBeenCalledWith("/api/backup/restore",expect.objectContaining({
    method:"POST",body:expect.stringContaining('"allow_partial":true'),
  }));
  expect(fetch.mock.calls.some(([path])=>path==="/api/apply")).toBe(false);
});

const RELEASE_COMMIT = "a".repeat(40);
const CURRENT_COMMIT = "b".repeat(40);
function updateStatus(update_available=false, extra:Record<string,unknown>={}) {
  return {configured:true,manifest_url:"https://example.invalid/release.json",
    current:{commit:CURRENT_COMMIT,semver:"0.1.0",installed_at:"2026-10-06T00:00:00Z",source:"iso"},
    available:{commit:RELEASE_COMMIT,semver:"0.2.0"},update_available,running:false,last:null,error:null,...extra};
}
function adminExtras(status:unknown) {
  return (path:string) => path==="/api/auth/me"
    ? new Response(JSON.stringify({id:1,username:"admin",role:"admin"}))
    : path==="/api/apply/status" ? new Response("null")
    : path==="/api/update" ? new Response(JSON.stringify(status)) : new Response("{}");
}
async function openMaintenance() {
  render(<MemoryRouter initialEntries={["/maintenance"]}><App/></MemoryRouter>);
  await screen.findByText("admin");
  const check=await screen.findByRole("button",{name:"Проверить обновление"});
  await waitFor(()=>expect(check).toBeEnabled());
  return check;
}

it("checks the release manifest and offers the available update",async()=>{
  setup(emptyConfiguration, adminExtras(updateStatus(true)));
  const user=userEvent.setup();
  const check=await openMaintenance();
  await user.click(check);
  expect(await screen.findByText("Доступен новый выпуск")).toBeVisible();
  expect(screen.getByRole("button",{name:"Применить обновление"})).toBeEnabled();
  expect(screen.getByText(/0\.2\.0 · aaaaaaa/)).toBeVisible();
});

it("does not apply the update when the confirmation is dismissed",async()=>{
  const fetch=setup(emptyConfiguration, adminExtras(updateStatus(true)));
  vi.spyOn(window,"confirm").mockReturnValue(false);
  const user=userEvent.setup();
  const check=await openMaintenance();
  await user.click(check);
  await user.click(await screen.findByRole("button",{name:"Применить обновление"}));
  expect(fetch.mock.calls.some(([path,init])=>path==="/api/update"&&(init as RequestInit|undefined)?.method==="POST")).toBe(false);
});

it("applies the pinned release commit after confirmation",async()=>{
  const fetch=setup(emptyConfiguration, adminExtras(updateStatus(true)));
  vi.spyOn(window,"confirm").mockReturnValue(true);
  const user=userEvent.setup();
  const check=await openMaintenance();
  await user.click(check);
  await user.click(await screen.findByRole("button",{name:"Применить обновление"}));
  await waitFor(()=>expect(fetch).toHaveBeenCalledWith("/api/update",expect.objectContaining({method:"POST",body:JSON.stringify({release:RELEASE_COMMIT})})));
});

it("shows that no update is available",async()=>{
  setup(emptyConfiguration, adminExtras(updateStatus(false)));
  const user=userEvent.setup();
  const check=await openMaintenance();
  await user.click(check);
  expect(await screen.findByText("Установлен актуальный выпуск")).toBeVisible();
  expect(screen.queryByRole("button",{name:"Применить обновление"})).toBeNull();
});
