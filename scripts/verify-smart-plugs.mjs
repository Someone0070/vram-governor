import fs from "node:fs";

const read = path => fs.readFileSync(path, "utf8");
const api = read("internal/api/smart_plugs.go");
const config = read("configs/controller.yaml");
const deploy = read("deploy/controller/controller.yaml.template");
const ui = read("web/ui/src/admin.tsx");
const docs = read("docs/smart-plugs.md");
const required = [
  [api, /tasmotaRequest\(ctx, plug, "Status 0"\)/, "structured read-only telemetry"],
  [api, /\/?m=1/, "read-only web fallback"],
  [api, /tasmotaRequest\(r\.Context\(\), plug, "Power "\+body\.State\)/, "explicit power command"],
  [api, /request\.Header\.Set\("Referer", base\+"\/"\)/, "same-origin referer"],
  [api, /SchedulingDisabled/, "scheduler-off guard"],
  [api, /acknowledge_hard_power_cut/, "hard cut acknowledgment"],
  [config, /smart_plugs: \[\]/, "disabled sample config"],
  [deploy, /smart_plugs:\s*\n\s*- node_id: "cmp170-node"\s*\n\s*url: "http:\/\/10\.0\.0\.222"\s*\n\s*control_enabled: false/, "CMP plug is read-only"],
  [deploy, /smart_plugs:(?![\s\S]*10\.0\.0\.43)/, "test plug not mapped"],
  [ui, /Wall power/, "per-rig wall-power UI"],
  [ui, /setPlugPower\("OFF"\)/, "explicit OFF UI"],
  [docs, /not an end-to-end controller\/LB deployment/, "honest live-control status"]
];
for (const [source, pattern, label] of required) {
  if (!pattern.test(source)) throw new Error(`${label} missing`);
}
console.log("smart plug integration verification passed");
