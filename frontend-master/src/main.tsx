import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { takeMagicProof } from "./magic";
import "./styles.css";

const magicProof = takeMagicProof();
ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App magicProof={magicProof} /></React.StrictMode>);
