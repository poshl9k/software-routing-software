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
  const fetch=vi.fn(async(path:string,init?:RequestInit)=>path==="/api/versions"?new Response(JSON.stringify([{id:1,status:"draft",configuration}])):extras(path,init));
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
