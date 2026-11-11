import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { takeMagicProof, takePortalLink } from "./magic";
import "./styles.css";

const magicProof = takeMagicProof();
const portalLink = takePortalLink();
ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App magicProof={magicProof} portalLink={portalLink} /></React.StrictMode>);
