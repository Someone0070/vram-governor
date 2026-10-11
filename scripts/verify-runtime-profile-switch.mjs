import fs from "node:fs";

const read = (path) => fs.readFileSync(path, "utf8");
const requireText = (text, pattern, message) => {
  if (!pattern.test(text)) throw new Error(message);
};

const commands = read("internal/nodeagent/commands.go");
const config = read("internal/nodeagent/config.go");
const controller = read("configs/controller.yaml");
const helper = read("deploy/ollama/switch-runtime-profile.sh");
const unit = read("deploy/ollama/vram-runtime-profile-switch@.service");
const polkit = read("deploy/ollama/90-vram-runtime-profile-switch.rules");
const docs = read("docs/ollama-multi-profile.md");
const fleet = ["rtx3080", "rtx3090", "cmp170"].map((name) => read(`configs/fleet/${name}-node.yaml`)).join("\n");

requireText(commands, /case "switch_runtime_profile":/, "node command is not allowlisted");
requireText(commands, /exec\.CommandContext\(ctx, command\[0\], command\[1:\]\.\.\.\)/, "profile command must execute fixed argv directly");
if (/exec\.CommandContext\([^\n]*["'](?:sh|bash)["']\s*,\s*["']-c["']/.test(commands)) {
  throw new Error("profile switching must not invoke a shell");
}
requireText(config, /runtime_profiles/, "node profile allowlist is missing");
requireText(config, /strings\.HasPrefix\(profile\.SwitchCommand\[0\], "\/"\)/, "profile executables must be absolute");
requireText(controller, /default_max_accelerators_per_model:\s*1/, "one-card default is missing");
requireText(helper, /\^\(\[A-Za-z0-9_\.-\]\+\):\(\[A-Za-z0-9_\.-\]\+\)\$/, "helper identifier allowlist is missing");
requireText(helper, /owner.*root/, "helper must enforce root-owned profiles");
requireText(unit, /ExecStart=\/usr\/libexec\/vram-governor\/switch-runtime-profile\.sh %i/, "switch unit does not use the fixed helper");
requireText(polkit, /subject\.user !== "vram-governor"/, "polkit rule is not bound to the node-agent account");
requireText(polkit, /\^vram-runtime-profile-switch@/, "polkit rule is not unit-family scoped");
requireText(fleet, /runtime_profiles: # Enable after \/slots-backed live acceptance\./, "fleet examples do not fail closed before live acceptance");
requireText(docs, /Stock Ollama does not expose parallel-slot/, "Ollama verification limitation is not documented");

console.log("runtime profile switch verification passed");
