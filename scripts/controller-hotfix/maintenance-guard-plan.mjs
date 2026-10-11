import crypto from "node:crypto";
import { buildInstallPlan, buildRemovalPlan } from "./maintenance-fence.mjs";

const ROLES = Object.freeze({
  LB115: Object.freeze({ table: "vg_controller_maintenance", protected: [4000, 8443, 18082, 9444, 9445], lanes: [8443], host: "10.0.0.115", access: "ssh" }),
  CT200: Object.freeze({ table: "vg_native_maintenance", protected: [8080, 8188, 8190], lanes: [8080, 8188, 8190], host: "10.0.0.3", access: "proxmox-ct200" }),
});
const SOURCE_PORTS = Object.freeze([443, 444, 445]);
const MAX_NFT_JSON = 4 * 1024 * 1024;
const MAX_NFT_OBJECTS = 16384;
const MAX_NFT_DEPTH = 32;
const MAX_PLAN = 32 * 1024;
const NFT_KINDS = new Set(["metainfo", "table", "chain", "rule", "set", "map", "element", "flowtable", "counter", "quota", "ct helper", "limit", "ct timeout", "ct expectation"]);
const generatedPlans = new WeakSet();

function fail(code) { throw new Error(code); }
function sha256(data) { return crypto.createHash("sha256").update(data).digest("hex"); }
function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function exactKeys(value, keys) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
    const own = Reflect.ownKeys(value);
    if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return keys.every((key) => descriptors[key] && descriptors[key].enumerable && Object.hasOwn(descriptors[key], "value"));
  } catch { return false; }
}
function safeNonce(value) { return typeof value === "string" && /^[a-f0-9]{32}$/.test(value); }

/** Combine unchanged leaf-1.3.10 sourceport plans into one create-only nft batch. */
export function buildCombinedInstallPlan(input) {
  if (!exactKeys(input, ["role", "ownershipNonce"]) || typeof input.role !== "string" || !Object.prototype.hasOwnProperty.call(ROLES, input.role) || !safeNonce(input.ownershipNonce)) fail("plan_input_invalid");
  const role = ROLES[input.role];
  const plans = SOURCE_PORTS.map((sourcePort) => buildInstallPlan({ role: input.role, sourcePort, ownershipNonce: input.ownershipNonce }));
  if (plans.some((plan) => plan.role !== input.role || plan.table !== role.table || plan.ownershipNonce !== input.ownershipNonce || plan.submissionMode !== "nft -f -")) fail("fence_dependency_invalid");
  const split = plans.map((plan) => plan.transaction.trimEnd().split("\n"));
  const common = split[0].slice(0, 3);
  if (split.some((lines) => lines.slice(0, 3).join("\n") !== common.join("\n"))) fail("fence_dependency_invalid");
  const laneRules = [];
  const protectedDrops = [];
  const seenLane = new Set();
  const seenDrop = new Set();
  for (const lines of split) {
    for (const line of lines.slice(3)) {
      if (/^add rule inet \S+ input tcp dport \d+ drop$/.test(line)) {
        if (!seenDrop.has(line)) { seenDrop.add(line); protectedDrops.push(line); }
      } else if (!seenLane.has(line)) {
        seenLane.add(line); laneRules.push(line);
      }
    }
  }
  const transaction = [...common, ...laneRules, ...protectedDrops].join("\n") + "\n";
  if (Buffer.byteLength(transaction, "ascii") > MAX_PLAN || /(?:^|\n)(?:delete|flush|replace|insert)\s/.test(transaction)) fail("plan_transaction_invalid");
  const batchSha256 = sha256(Buffer.from(transaction, "ascii"));
  const result = freeze({ schema: "maintenance-guard-install-plan-v1", role: input.role, table: role.table, ownershipNonce: input.ownershipNonce, sourcePorts: [...SOURCE_PORTS], protectedPorts: [...role.protected], validationDestinationPorts: [...role.lanes], transactionMode: "single-atomic-create-only", submissionMode: "nft -f -", transaction, batchBytes: Buffer.byteLength(transaction, "ascii"), batchSha256 });
  generatedPlans.add(result);
  return result;
}

export function buildCombinedRemovalPlan(plan, disposition) {
  if (!generatedPlans.has(plan) || plan.schema !== "maintenance-guard-install-plan-v1" || !Object.prototype.hasOwnProperty.call(ROLES, plan.role) || plan.table !== ROLES[plan.role].table || !safeNonce(plan.ownershipNonce) || disposition !== "successfully_verified") fail("release_not_verified");
  const receipt = buildInstallPlan({ role: plan.role, sourcePort: 443, ownershipNonce: plan.ownershipNonce }).receipt;
  const one = buildRemovalPlan(receipt, disposition);
  return freeze({ schema: "maintenance-guard-removal-plan-v1", role: plan.role, table: plan.table, ownershipNonce: plan.ownershipNonce, disposition, transaction: one.transaction });
}

function jsonDepth(value, depth = 0) {
  if (depth > MAX_NFT_DEPTH) fail("nft_json_depth");
  if (Array.isArray(value)) for (const child of value) jsonDepth(child, depth + 1);
  else if (value && typeof value === "object") for (const child of Object.values(value)) jsonDepth(child, depth + 1);
}
function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  return JSON.stringify(value);
}
function numericHandle(value) { return Number.isSafeInteger(value) && value > 0; }

function rejectDuplicateJsonKeys(source) {
  let index = 0;
  const whitespace = () => { while (index < source.length && /[\u0009\u000a\u000d\u0020]/.test(source[index])) index += 1; };
  const string = () => {
    const start = index;
    if (source[index++] !== '"') fail("nft_json_invalid");
    while (index < source.length) {
      const char = source[index++];
      if (char === '"') {
        try { return JSON.parse(source.slice(start, index)); } catch { fail("nft_json_invalid"); }
      }
      if (char === "\\") {
        const escaped = source[index++];
        if (escaped === "u") { if (!/^[0-9a-fA-F]{4}$/.test(source.slice(index, index + 4))) fail("nft_json_invalid"); index += 4; }
        else if (!'"\\/bfnrt'.includes(escaped)) fail("nft_json_invalid");
      } else if (char < " ") fail("nft_json_invalid");
    }
    fail("nft_json_invalid");
  };
  const value = (depth = 0) => {
    if (depth > MAX_NFT_DEPTH) fail("nft_json_depth");
    whitespace(); const char = source[index];
    if (char === "{") {
      index += 1; whitespace(); const keys = new Set();
      if (source[index] === "}") { index += 1; return; }
      for (;;) {
        whitespace(); const key = string();
        if (keys.has(key)) fail("nft_json_duplicate");
        keys.add(key); whitespace(); if (source[index++] !== ":") fail("nft_json_invalid");
        value(depth + 1); whitespace(); const separator = source[index++];
        if (separator === "}") return;
        if (separator !== ",") fail("nft_json_invalid");
      }
    }
    if (char === "[") {
      index += 1; whitespace(); if (source[index] === "]") { index += 1; return; }
      for (;;) { value(depth + 1); whitespace(); const separator = source[index++]; if (separator === "]") return; if (separator !== ",") fail("nft_json_invalid"); }
    }
    if (char === '"') { string(); return; }
    const literal = ["true", "false", "null"].find((item) => source.startsWith(item, index));
    if (literal) { index += literal.length; return; }
    const number = source.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (number) { index += number[0].length; return; }
    fail("nft_json_invalid");
  };
  value(); whitespace(); if (index !== source.length) fail("nft_json_invalid");
}

function validateNftObject(kind, value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("nft_object_shape");
  if (kind === "metainfo") {
    if (!exactKeys(value, ["version", "release_name", "json_schema_version"]) || value.version !== "1.0.9" || typeof value.release_name !== "string" || value.release_name.length > 128 || value.json_schema_version !== 1) fail("nft_schema_unknown");
    return;
  }
  if (kind === "table") {
    const shapes = [
      ["family", "name", "handle"], ["family", "name", "handle", "comment"],
      ["family", "name", "handle", "flags"], ["family", "name", "handle", "flags", "comment"],
    ];
    if (!shapes.some((keys) => exactKeys(value, keys)) || typeof value.family !== "string" || typeof value.name !== "string" || !numericHandle(value.handle) || (value.comment !== undefined && typeof value.comment !== "string") || (value.flags !== undefined && !(typeof value.flags === "string" || (Array.isArray(value.flags) && value.flags.every((x) => typeof x === "string"))))) fail("nft_table_shape");
    return;
  }
  if (kind === "chain") {
    const allowed = ["family", "table", "name", "handle", "type", "hook", "prio", "policy", "dev", "newname", "comment"];
    if (Object.keys(value).some((key) => !allowed.includes(key)) || !["family", "table", "name", "handle"].every((key) => Object.hasOwn(value, key)) || typeof value.family !== "string" || typeof value.table !== "string" || typeof value.name !== "string" || !numericHandle(value.handle)) fail("nft_chain_shape");
    if (value.hook !== undefined && (typeof value.hook !== "string" || typeof value.type !== "string" || !Number.isSafeInteger(value.prio) || typeof value.policy !== "string")) fail("nft_chain_shape");
    return;
  }
  if (kind === "rule") {
    const allowed = ["family", "table", "chain", "expr", "handle", "index", "comment"];
    if (Object.keys(value).some((key) => !allowed.includes(key)) || !["family", "table", "chain", "expr", "handle"].every((key) => Object.hasOwn(value, key)) || typeof value.family !== "string" || typeof value.table !== "string" || typeof value.chain !== "string" || !Array.isArray(value.expr) || value.expr.length < 1 || !numericHandle(value.handle) || (value.comment !== undefined && typeof value.comment !== "string")) fail("nft_rule_shape");
    return;
  }
  if (!NFT_KINDS.has(kind)) fail("nft_kind_unknown");
  if (kind === "element") {
    if (!exactKeys(value, ["family", "table", "name", "elem"]) || typeof value.family !== "string" || typeof value.table !== "string" || typeof value.name !== "string") fail("nft_foreign_shape");
    return;
  }
  const shapes = {
    set: [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "type", "policy", "flags", "elem", "timeout", "gc-interval", "size"]],
    map: [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "type", "map", "policy", "flags", "elem", "timeout", "gc-interval", "size"]],
    flowtable: [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "hook", "prio", "dev"]],
    counter: [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "packets", "bytes"]],
    quota: [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "bytes", "used", "inv"]],
    "ct helper": [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "type", "protocol", "l3proto"]],
    limit: [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "rate", "per", "burst", "unit", "inv"]],
    "ct timeout": [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "protocol", "state", "value", "l3proto"]],
    "ct expectation": [["family", "table", "name", "handle"], ["family", "table", "name", "handle", "l3proto", "protocol", "dport", "timeout", "size"]],
  };
  const allowedShapes = shapes[kind];
  if (!allowedShapes || !allowedShapes.some((required) => required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => required.includes(key)))) fail("nft_foreign_shape");
  if (typeof value.family !== "string" || typeof value.table !== "string" || typeof value.name !== "string" || (Object.hasOwn(value, "handle") && !numericHandle(value.handle))) fail("nft_foreign_shape");
}

/** Parse bounded libnftables list-ruleset JSON; unknown versions/kinds/structures are rejected. */
export function parseNftRuleset(input) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (bytes.length === 0 || bytes.length > MAX_NFT_JSON) fail("nft_json_bound");
  let root;
  const source = bytes.toString("utf8");
  if (!Buffer.from(source, "utf8").equals(bytes)) fail("nft_json_invalid");
  rejectDuplicateJsonKeys(source);
  try { root = JSON.parse(source); } catch { fail("nft_json_invalid"); }
  jsonDepth(root);
  if (!exactKeys(root, ["nftables"]) || !Array.isArray(root.nftables) || root.nftables.length > MAX_NFT_OBJECTS) fail("nft_ruleset_shape");
  const objects = []; const seen = new Set(); let schemaSeen = false;
  for (const row of root.nftables) {
    if (!row || typeof row !== "object" || Array.isArray(row) || Object.keys(row).length !== 1) fail("nft_row_shape");
    const kind = Object.keys(row)[0];
    if (!NFT_KINDS.has(kind)) fail("nft_kind_unknown");
    const value = row[kind]; validateNftObject(kind, value);
    if (kind === "metainfo") { if (schemaSeen || objects.length !== 0) fail("nft_metainfo_order"); schemaSeen = true; }
    if (kind === "table" || kind === "chain" || kind === "rule") {
      const identity = kind === "table" ? kind + ":" + value.family + ":" + value.name : kind === "chain" ? kind + ":" + value.family + ":" + value.table + ":" + value.name : kind + ":" + value.family + ":" + value.table + ":" + value.chain + ":" + value.handle;
      if (seen.has(identity)) fail("nft_object_duplicate");
      seen.add(identity);
    }
    objects.push({ kind, value, canonical: canonical(row) });
  }
  if (!schemaSeen) fail("nft_schema_unknown");
  return freeze({ schema: schemaSeen ? 1 : null, objects });
}

export function inspectForeignSnapshot(parsed, role) {
  if (!parsed || !Array.isArray(parsed.objects) || !Object.hasOwn(ROLES, role)) fail("nft_snapshot_input");
  const tableName = ROLES[role].table;
  if (parsed.objects.some(({ kind, value }) => kind === "table" && value.family === "inet" && value.name === tableName)) fail("owned_table_present");
  return sha256(Buffer.from(parsed.objects.map((item) => item.canonical).join("\n"), "utf8"));
}

function getMatch(match) {
  if (!exactKeys(match, ["op", "left", "right"]) || match.op !== "==") fail("owned_rule_expression");
  const left = match.left;
  if (!left || typeof left !== "object" || Array.isArray(left) || Object.keys(left).length !== 1) fail("owned_rule_expression");
  const exprKind = Object.keys(left)[0]; const detail = left[exprKind];
  if (exprKind === "meta" && exactKeys(detail, ["key"]) && ["iifname", "oifname", "skuid"].includes(detail.key)) return ["meta." + detail.key, match.right];
  if (exprKind === "payload" && exactKeys(detail, ["protocol", "field"]) && ["ip", "tcp"].includes(detail.protocol) && ["saddr", "daddr", "sport", "dport"].includes(detail.field)) return [detail.protocol + "." + detail.field, match.right];
  fail("owned_rule_expression");
}
function normalizeOwnedRule(rule) {
  if (!Array.isArray(rule.expr) || rule.expr.length < 2 || rule.expr.length > 12) fail("owned_rule_expression");
  const final = rule.expr[rule.expr.length - 1];
  if (!final || typeof final !== "object" || Array.isArray(final) || Object.keys(final).length !== 1 || !["accept", "drop"].includes(Object.keys(final)[0]) || final[Object.keys(final)[0]] !== null) fail("owned_rule_verdict");
  const predicates = rule.expr.slice(0, -1).map((item) => {
    if (!item || !exactKeys(item, ["match"])) fail("owned_rule_expression");
    return getMatch(item.match);
  });
  if (new Set(predicates.map(([key]) => key)).size !== predicates.length) fail("owned_rule_duplicate_predicate");
  return rule.chain + "|" + predicates.map(([key, value]) => key + "=" + canonical(value)).join(";") + "|" + Object.keys(final)[0];
}

function expectedNormalizedRules(plan) {
  const result = { input: [], output: [] };
  const lines = plan.transaction.trimEnd().split("\n");
  const prefix = [
    `create table inet ${plan.table} { comment "vg-maintenance-owner-nonce-${plan.ownershipNonce}"; }`,
    `add chain inet ${plan.table} input { type filter hook input priority -150; policy accept; }`,
    `add chain inet ${plan.table} output { type filter hook output priority -150; policy accept; }`,
  ];
  if (lines.length < 4 || prefix.some((line, index) => lines[index] !== line)) fail("fence_dependency_invalid");
  for (const line of lines.slice(3)) {
      const match = line.match(/^add rule inet \S+ (input|output) (.*) (accept|drop)$/);
      if (!match) fail("fence_dependency_invalid");
      const chain = match[1]; const body = match[2]; const verdict = match[3];
      const tokens = body.match(/"[^"]*"|\S+/g) || []; const pairs = [];
      for (let i = 0; i < tokens.length;) {
        let key = tokens[i++]; let value;
        if (key === "meta") key = "meta." + tokens[i++];
        else if (key === "ip" || key === "tcp") key = key + "." + tokens[i++];
        else if (key === "iifname" || key === "oifname") key = "meta." + key;
        else fail("fence_dependency_invalid");
        value = tokens[i++];
        if (value === undefined) fail("fence_dependency_invalid");
        if (value.startsWith('"')) value = value.slice(1, -1);
        else if (/^\d+$/.test(value)) value = Number(value);
        pairs.push([key, value]);
      }
      const normalized = chain + "|" + pairs.map(([key, value]) => key + "=" + canonical(value)).join(";") + "|" + verdict;
      result[chain].push(normalized);
  }
  return result;
}

/** Verify table handle/nonce, exactly two fixed base chains, and every normalized rule. */
export function inspectOwnedTable(parsed, plan, retained = null) {
  if (!parsed || !Array.isArray(parsed.objects) || !generatedPlans.has(plan) || plan.schema !== "maintenance-guard-install-plan-v1") fail("owned_inspect_input");
  const rows = parsed.objects.filter(({ value }) => value && value.family === "inet" && (value.table === plan.table || value.name === plan.table));
  const tables = rows.filter(({ kind, value }) => kind === "table" && value.name === plan.table);
  if (tables.length !== 1 || !numericHandle(tables[0].value.handle)) fail("owned_table_identity");
  const table = tables[0].value;
  if (!exactKeys(table, ["family", "name", "handle", "comment"]) || table.family !== "inet" || table.name !== plan.table) fail("owned_table_identity");
  if (table.comment !== "vg-maintenance-owner-nonce-" + plan.ownershipNonce) fail("owned_table_nonce");
  const chains = rows.filter(({ kind }) => kind === "chain");
  if (chains.length !== 2) fail("owned_chain_inventory");
  const chainByName = new Map();
  for (const { value } of chains) {
    if (!exactKeys(value, ["family", "table", "name", "handle", "type", "hook", "prio", "policy"]) || value.family !== "inet" || value.table !== plan.table || value.name !== value.hook || !Object.hasOwn(value, "hook") || value.type !== "filter" || !["input", "output"].includes(value.hook) || value.prio !== -150 || value.policy !== "accept" || chainByName.has(value.hook)) fail("owned_chain_identity");
    chainByName.set(value.hook, value);
  }
  if (!chainByName.has("input") || !chainByName.has("output")) fail("owned_chain_inventory");
  const ruleRows = rows.filter(({ kind }) => kind === "rule");
  if (rows.length !== 1 + chains.length + ruleRows.length) fail("owned_rules_mismatch");
  const actual = { input: [], output: [] };
  for (const { value } of ruleRows) {
    if (!actual[value.chain]) fail("owned_rules_mismatch");
    actual[value.chain].push(normalizeOwnedRule(value));
  }
  const expected = expectedNormalizedRules(plan);
  for (const chain of ["input", "output"]) if (actual[chain].length !== expected[chain].length || actual[chain].some((value, index) => value !== expected[chain][index])) fail("owned_rules_mismatch");
  const flat = actual.input.concat(actual.output);
  const result = freeze({ tableHandle: table.handle, inputHandle: chainByName.get("input").handle, outputHandle: chainByName.get("output").handle, ruleHandles: ruleRows.map(({ value }) => value.handle).sort((a, b) => a - b), ownershipNonce: plan.ownershipNonce, ruleSetSha256: sha256(Buffer.from(flat.join("\n"), "utf8")) });
  if (retained !== null && canonical(result) !== canonical(retained)) fail("owned_table_identity");
  return result;
}

export const GUARD_CONSTANTS = freeze({ roles: ROLES, sourcePorts: SOURCE_PORTS, maxNftJsonBytes: MAX_NFT_JSON, nftKinds: [...NFT_KINDS] });
