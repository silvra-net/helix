import React from "react";
import ReactDOM from "react-dom/client";
import { attachConsole, error as logError } from "@tauri-apps/plugin-log";
import App from "./App";
import "./styles.css";

// Mirror the webview console into the same persistent log file node_process.rs/commands.rs
// write to (see lib.rs's tauri-plugin-log setup) — a frontend crash otherwise leaves nothing
// behind once the window closes, only the Rust-side half of a bug report.
attachConsole();

// console.error alone doesn't fire for exceptions the app itself never caught — an uncaught
// throw or a rejected promise nobody awaited. Log those explicitly so they land in the file too.
window.addEventListener("error", (e) => {
  logError(`uncaught error: ${e.message} at ${e.filename}:${e.lineno}`);
});
window.addEventListener("unhandledrejection", (e) => {
  logError(`unhandled promise rejection: ${String(e.reason)}`);
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
