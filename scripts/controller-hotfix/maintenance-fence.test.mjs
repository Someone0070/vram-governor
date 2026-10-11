import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildInstallPlan, buildRemovalPlan } from "./maintenance-fence.mjs";

const PORTS = Object.freeze({
  LB115: Object.freeze([4000, 8443, 18082, 9444, 9445]),
  CT200: Object.freeze([8080, 8188, 8190]),
});
const LANE_PORTS = Object.freeze({ LB115: Object.freeze([8443]), CT200: Object.freeze([8080, 8188, 8190]) });
const TABLES = Object.freeze({ LB115: "vg_controller_maintenance", CT200: "vg_native_maintenance" });
const NONCE = "0123456789abcdef0123456789abcdef";
const TEST_NAMES = Object.freeze([
  "LB115 transaction covers every protected destination and exact loopback root lane",
  "CT200 transaction covers every native port without a widened validation lane",
  "packet fixtures preserve excluded-service replies while blocking local protected-port arrivals",
  "plan inputs reject arbitrary roles ports tables rule text and malformed nonces",
  "release requires an immutable generated receipt and successful verification disposition",
  "runner inventory validator rejects zero duplicate unexpected skipped and failed suites",
]);

function expectedBatch(role, sourcePort, nonce) {
  const table = TABLES[role];
  const ports = PORTS[role];
  const lanePorts = LANE_PORTS[role];
  const lines = [
    `create table inet ${table} { comment "vg-maintenance-owner-nonce-${nonce}"; }`,
    `add chain inet ${table} input { type filter hook input priority -150; policy accept; }`,
    `add chain inet ${table} output { type filter hook output priority -150; policy accept; }`,
  ];
  for (const port of lanePorts) {
    lines.push(`add rule inet ${table} input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ${sourcePort} tcp dport ${port} accept`);
    lines.push(`add rule inet ${table} output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ${sourcePort} tcp dport ${port} accept`);
    lines.push(`add rule inet ${table} output oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ${sourcePort} tcp dport ${port} drop`);
  }
  for (const port of ports) {
    lines.push(`add rule inet ${table} input tcp dport ${port} drop`);
  }
  return `${lines.join("\n")}\n`;
}

function ruleDecision(plan, chain, packet) {
  const prefix = `add rule inet ${plan.table} ${chain} `;
  for (const line of plan.transaction.split("\n").filter((entry) => entry.startsWith(prefix))) {
    const tokens = (line.match(/"[^\"]*"|\S+/g) || []).map((token) => token.startsWith('"') ? token.slice(1, -1) : token);
    const action = tokens[tokens.length - 1];
    if (action !== "accept" && action !== "drop") throw new Error("packet_fixture_unknown_action");
    let matches = true;
    for (let index = 5; index < tokens.length - 1;) {
      const key = tokens[index++];
      if (key === "iifname" || key === "oifname") {
        const expected = tokens[index++];
        const actual = key === "iifname" ? packet.iifname : packet.oifname;
        if (actual !== expected) matches = false;
      } else if (key === "meta" && tokens[index] === "skuid") {
        index++;
        const expected = Number(tokens[index++]);
        if (packet.uid !== expected) matches = false;
      } else if (key === "ip" && (tokens[index] === "saddr" || tokens[index] === "daddr")) {
        const direction = tokens[index++];
        const expected = tokens[index++];
        if (packet.family !== "ipv4" || packet[direction] !== expected) matches = false;
      } else if (key === "tcp" && (tokens[index] === "sport" || tokens[index] === "dport")) {
        const direction = tokens[index++];
        const expected = Number(tokens[index++]);
        if (packet.protocol !== "tcp" || packet[direction] !== expected) matches = false;
      } else {
        throw new Error("packet_fixture_unknown_match");
      }
    }
    if (matches) return action;
  }
  return "accept";
}

function localDecision(plan, packet) {
  const output = ruleDecision(plan, "output", packet);
  return output === "accept" ? ruleDecision(plan, "input", packet) : output;
}

function validateTapRun(status, output) {
  if (status !== 0 || typeof output !== "string" || output.length > 1024 * 1024) throw new Error("test_run_failed");
  const lines = output.split(/\r?\n/);
  const terminals = lines.filter((line) => /^(?:ok|not ok)\s+\d+\s+-/.test(line));
  if (terminals.some((line) => /(?:^|\s)#\s*(?:SKIP|TODO)\b/i.test(line))) throw new Error("test_directive_forbidden");
  if (terminals.length !== TEST_NAMES.length || terminals.some((line, index) => line !== `ok ${index + 1} - ${TEST_NAMES[index]}`)) throw new Error("test_inventory_mismatch");
  const plans = lines.filter((line) => /^1\.\.\d+$/.test(line));
  if (plans.length !== 1 || plans[0] !== `1..${TEST_NAMES.length}`) throw new Error("test_plan_mismatch");
  for (const [key, expected] of [["tests", TEST_NAMES.length], ["pass", TEST_NAMES.length], ["fail", 0], ["cancelled", 0], ["skipped", 0], ["todo", 0]]) {
    const summaries = lines.filter((line) => line.startsWith(`# ${key} `));
    if (summaries.length !== 1 || summaries[0] !== `# ${key} ${expected}`) throw new Error("test_summary_mismatch");
  }
  return true;
}

if (process.argv[2] === "--verify") {
  const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", fileURLToPath(import.meta.url)], { encoding: "utf8", timeout: 30000, maxBuffer: 2 * 1024 * 1024, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  try {
    if (child.error) throw new Error("test_runner_error");
    validateTapRun(child.status, child.stdout);
    process.stdout.write("pure maintenance fence controls passed\n");
  } catch {
    process.stderr.write("pure maintenance fence controls failed closed\n");
    process.exitCode = 1;
  }
} else {
  test(TEST_NAMES[0], () => {
    const plan = buildInstallPlan({ role: "LB115", sourcePort: 443, ownershipNonce: NONCE });
    assert.equal(plan.schema, "maintenance-fence-plan-v1");
    assert.equal(plan.transactionMode, "single-atomic-nft-batch");
    assert.equal(plan.submissionMode, "nft -f -");
    assert.equal(plan.role, "LB115");
    assert.equal(plan.table, "vg_controller_maintenance");
    assert.deepEqual(plan.destinationPorts, PORTS.LB115);
    assert.deepEqual(plan.validationDestinationPorts, LANE_PORTS.LB115);
    assert.equal(plan.transaction, expectedBatch("LB115", 443, NONCE));
    assert.ok(plan.transaction.length < 8192);
    assert.ok(plan.transaction.startsWith(`create table inet vg_controller_maintenance { comment "vg-maintenance-owner-nonce-${NONCE}"; }\n`));
    assert.equal(plan.transaction.includes("delete table"), false);
    assert.equal(plan.transaction.includes("flush table"), false);
    assert.equal(plan.transaction.includes("ct state"), false);
    assert.equal(plan.transaction.includes("established"), false);
    assert.equal(plan.transaction.includes("9443"), false);
    assert.equal(plan.transaction.includes("tcp dport 22"), false);
    assert.equal(plan.transaction.includes("tcp dport 53"), false);
    assert.equal(plan.transaction.includes("tcp dport 5432"), false);
    assert.equal(plan.transaction.includes("tcp dport 3900"), false);
    assert.equal(plan.transaction.includes("tcp dport 3901"), false);
    for (const port of PORTS.LB115) {
      assert.ok(plan.transaction.includes(`input tcp dport ${port} drop`));
      assert.equal(plan.transaction.includes(`output tcp dport ${port} drop`), false);
    }
    assert.ok(plan.transaction.includes('input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 443 tcp dport 8443 accept'));
    assert.ok(plan.transaction.includes('output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 443 tcp dport 8443 accept'));
    assert.ok(plan.transaction.includes('output oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 443 tcp dport 8443 drop'));
    for (const port of [4000, 18082, 9444, 9445]) assert.equal(plan.transaction.includes(`tcp sport 443 tcp dport ${port} accept`), false);
  });

  test(TEST_NAMES[1], () => {
    const plan = buildInstallPlan({ role: "CT200", sourcePort: 445, ownershipNonce: NONCE });
    assert.equal(plan.table, "vg_native_maintenance");
    assert.deepEqual(plan.destinationPorts, PORTS.CT200);
    assert.deepEqual(plan.validationDestinationPorts, LANE_PORTS.CT200);
    assert.equal(plan.transaction, expectedBatch("CT200", 445, NONCE));
    for (const port of PORTS.CT200) {
      assert.ok(plan.transaction.includes(`input tcp dport ${port} drop`));
      assert.equal(plan.transaction.includes(`output tcp dport ${port} drop`), false);
      assert.ok(plan.transaction.includes(`input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 445 tcp dport ${port} accept`));
      assert.ok(plan.transaction.includes(`output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 445 tcp dport ${port} accept`));
      assert.ok(plan.transaction.includes(`output oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 445 tcp dport ${port} drop`));
    }
    assert.equal(plan.transaction.includes("tcp dport 4000"), false);
    assert.equal(plan.transaction.includes("tcp dport 9445"), false);
    assert.equal(plan.transaction.includes("ct state"), false);
    assert.equal(plan.transaction.includes('input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 445 tcp dport 4000'), false);
    assert.equal(plan.transaction.includes('output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 445 tcp dport 4000'), false);
  });

  test(TEST_NAMES[2], () => {
    const plan = buildInstallPlan({ role: "LB115", sourcePort: 443, ownershipNonce: NONCE });
    const excludedServices = [22, 9443, 53, 5432, 3900, 3901];
    const clientSourcePorts = PORTS.LB115;
    for (const family of ["ipv4", "ipv6"]) {
      for (const servicePort of excludedServices) {
        for (const clientSourcePort of clientSourcePorts) {
          const clientAddress = family === "ipv4" ? "198.51.100.7" : "2001:db8::7";
          const serverAddress = family === "ipv4" ? "192.0.2.115" : "2001:db8::115";
          const request = { family, protocol: "tcp", iifname: "eth0", saddr: clientAddress, daddr: serverAddress, sport: clientSourcePort, dport: servicePort, uid: null, state: "new" };
          const reply = { family, protocol: "tcp", oifname: "eth0", saddr: serverAddress, daddr: clientAddress, sport: servicePort, dport: clientSourcePort, uid: 0, state: "established" };
          assert.equal(ruleDecision(plan, "input", request), "accept", `excluded service request blocked: ${family}/${servicePort}/${clientSourcePort}`);
          assert.equal(ruleDecision(plan, "output", reply), "accept", `excluded service reply blocked: ${family}/${servicePort}/${clientSourcePort}`);
        }
      }
    }

    for (const role of ["LB115", "CT200"]) {
      const rolePlan = buildInstallPlan({ role, sourcePort: 444, ownershipNonce: NONCE });
      for (const family of ["ipv4", "ipv6"]) {
        for (const state of ["new", "established", "related"]) {
          for (const uid of [0, 1000, null]) {
            for (const port of PORTS[role]) {
              const request = { family, protocol: "tcp", iifname: "eth0", saddr: family === "ipv4" ? "203.0.113.9" : "2001:db8::9", daddr: family === "ipv4" ? "192.0.2.1" : "2001:db8::1", sport: 55000, dport: port, uid, state };
              assert.equal(ruleDecision(rolePlan, "input", request), "drop", `protected ingress escaped: ${role}/${family}/${state}/${uid}/${port}`);
              assert.equal(localDecision(rolePlan, { ...request, oifname: "eth0" }), "drop", `local protected request escaped: ${role}/${family}/${state}/${uid}/${port}`);
            }
          }
        }
      }
    }

    for (const [role, sourcePort, destinationPort] of [["LB115", 443, 8443], ["LB115", 444, 8443], ["CT200", 445, 8080]]) {
      const lanePlan = buildInstallPlan({ role, sourcePort, ownershipNonce: NONCE });
      const validation = { family: "ipv4", protocol: "tcp", iifname: "lo", oifname: "lo", saddr: "127.0.0.1", daddr: "127.0.0.1", sport: sourcePort, dport: destinationPort, state: "new" };
      assert.equal(localDecision(lanePlan, { ...validation, uid: 0 }), "accept");
      for (const uid of [1000, null]) assert.equal(localDecision(lanePlan, { ...validation, uid }), "drop");
      assert.equal(ruleDecision(lanePlan, "output", { ...validation, sport: destinationPort, dport: sourcePort, uid: 0, state: "established" }), "accept");
    }
    const validation = { family: "ipv4", protocol: "tcp", iifname: "lo", oifname: "lo", saddr: "127.0.0.1", daddr: "127.0.0.1", sport: 443, dport: 8443, state: "new", uid: 0 };
    assert.equal(localDecision(plan, { ...validation, dport: 4000 }), "drop");
    assert.equal(localDecision(plan, { ...validation, daddr: "192.0.2.115" }), "drop");
    assert.equal(localDecision(plan, { ...validation, iifname: "eth0", oifname: "eth0" }), "drop");
    assert.equal(localDecision(plan, { ...validation, sport: 446 }), "drop");
    assert.equal(localDecision(plan, { ...validation, family: "ipv6" }), "drop");
  });

  test(TEST_NAMES[3], () => {
    for (const input of [
      { role: "LB116", sourcePort: 443, ownershipNonce: NONCE },
      { role: "CT200", sourcePort: 442, ownershipNonce: NONCE },
      { role: "LB115", sourcePort: 1024, ownershipNonce: NONCE },
      { role: "LB115", sourcePort: 443, ownershipNonce: "../" + NONCE },
      { role: "LB115", sourcePort: 443, ownershipNonce: NONCE, table: "inet evil" },
      { role: "LB115", sourcePort: 443, ownershipNonce: NONCE, transaction: "flush ruleset" },
      { role: "LB115", sourcePort: 443, ownershipNonce: NONCE, destinationPorts: [22] },
      { role: 10, sourcePort: 443, ownershipNonce: NONCE },
      { role: "LB115", sourcePort: "443", ownershipNonce: NONCE },
      { role: "LB115", sourcePort: Number.NaN, ownershipNonce: NONCE },
      { role: "LB115", sourcePort: Number.POSITIVE_INFINITY, ownershipNonce: NONCE },
      { role: "LB115", sourcePort: 443, ownershipNonce: NONCE.toUpperCase() },
      { role: "LB115", sourcePort: 443, ownershipNonce: NONCE.slice(1) },
      { role: "LB115", sourcePort: 443, ownershipNonce: 1 },
      Object.assign(Object.create(null), { role: "LB115", sourcePort: 443, ownershipNonce: NONCE }),
    ]) assert.throws(() => buildInstallPlan(input));
    assert.throws(() => buildInstallPlan(null));
    assert.throws(() => buildInstallPlan(["LB115", 443, NONCE]));
    assert.throws(() => buildInstallPlan({ sourcePort: 443, ownershipNonce: NONCE }));
    assert.throws(() => buildInstallPlan({ role: "LB115", ownershipNonce: NONCE }));
    assert.throws(() => buildInstallPlan({ role: "LB115", sourcePort: 443 }));
    assert.throws(() => buildInstallPlan({ role: "LB115", sourcePort: 443, ownershipNonce: NONCE }, "flush ruleset"));
    let roleCoerced = false;
    const coercibleRole = { [Symbol.toPrimitive]() { roleCoerced = true; return "LB115"; } };
    assert.throws(() => buildInstallPlan({ role: coercibleRole, sourcePort: 443, ownershipNonce: NONCE }), /role_invalid/);
    assert.equal(roleCoerced, false);
    let accessorCalled = false;
    const accessorInput = { sourcePort: 443, ownershipNonce: NONCE };
    Object.defineProperty(accessorInput, "role", { enumerable: true, get() { accessorCalled = true; return "LB115"; } });
    assert.throws(() => buildInstallPlan(accessorInput));
    assert.equal(accessorCalled, false);
    const hiddenInput = { sourcePort: 443, ownershipNonce: NONCE };
    Object.defineProperty(hiddenInput, "role", { value: "LB115", enumerable: false });
    assert.throws(() => buildInstallPlan(hiddenInput));
    const symbolInput = { role: "LB115", sourcePort: 443, ownershipNonce: NONCE, [Symbol("rule")]: "flush ruleset" };
    assert.throws(() => buildInstallPlan(symbolInput));
  });

  test(TEST_NAMES[4], () => {
    const plan = buildInstallPlan({ role: "LB115", sourcePort: 444, ownershipNonce: NONCE });
    const receipt = plan.receipt;
    assert.ok(Object.isFrozen(plan));
    assert.ok(Object.isFrozen(plan.destinationPorts));
    assert.ok(Object.isFrozen(receipt));
    assert.ok(Object.isFrozen(receipt.validationLane));
    assert.ok(Object.isFrozen(receipt.validationLane.destinationPorts));
    assert.throws(() => { plan.destinationPorts[0] = 22; }, TypeError);
    assert.throws(() => { receipt.validationLane.destinationPorts[0] = 22; }, TypeError);
    assert.deepEqual(buildRemovalPlan(receipt, "successfully_verified"), {
      schema: "maintenance-fence-removal-v1",
      role: "LB115",
      table: "vg_controller_maintenance",
      ownershipNonce: NONCE,
      verificationDisposition: "successfully_verified",
      transaction: "delete table inet vg_controller_maintenance\n",
    });
    for (const disposition of ["ambiguous", "failed", "not_verified", true, null]) assert.throws(() => buildRemovalPlan(receipt, disposition), /verification_not_successful/);
    assert.throws(() => buildRemovalPlan({ ...receipt }, "successfully_verified"), /receipt_invalid/);
    assert.throws(() => buildRemovalPlan({ ...receipt, role: "CT200", table: "vg_native_maintenance" }, "successfully_verified"), /receipt_invalid/);
    assert.throws(() => buildRemovalPlan({ ...receipt, ownershipNonce: "f".repeat(32) }, "successfully_verified"), /receipt_invalid/);
    assert.throws(() => buildRemovalPlan({ ...receipt, unexpected: "delete table inet" }, "successfully_verified"), /receipt_invalid/);
    assert.throws(() => buildRemovalPlan(null, "successfully_verified"), /receipt_invalid/);
  });

  test(TEST_NAMES[5], () => {
    const valid = ["TAP version 13", ...TEST_NAMES.map((name, index) => `ok ${index + 1} - ${name}`), `1..${TEST_NAMES.length}`, `# tests ${TEST_NAMES.length}`, `# pass ${TEST_NAMES.length}`, "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0"].join("\n");
    assert.equal(validateTapRun(0, valid), true);
    assert.throws(() => validateTapRun(0, valid.replace(`1..${TEST_NAMES.length}`, "1..0")), /test_inventory_mismatch|test_plan_mismatch/);
    assert.throws(() => validateTapRun(0, valid.replace(`ok 2 - ${TEST_NAMES[1]}`, `ok 1 - ${TEST_NAMES[0]}`)), /test_inventory_mismatch/);
    assert.throws(() => validateTapRun(0, valid.replace(TEST_NAMES[3], "unexpected suite")), /test_inventory_mismatch/);
    assert.throws(() => validateTapRun(0, valid.replace(`ok 3 - ${TEST_NAMES[2]}`, `ok 3 - ${TEST_NAMES[2]} # SKIP`)), /test_directive_forbidden/);
    assert.throws(() => validateTapRun(0, valid.replace(`ok 4 - ${TEST_NAMES[3]}`, `ok 4 - ${TEST_NAMES[3]} # TODO`)), /test_directive_forbidden/);
    assert.throws(() => validateTapRun(0, valid.replace("# todo 0", "# todo 1")), /test_summary_mismatch/);
    assert.throws(() => validateTapRun(0, valid.replace("# skipped 0", "# skipped 1")), /test_summary_mismatch/);
    assert.throws(() => validateTapRun(0, valid.replace("# fail 0", "# fail 1")), /test_summary_mismatch/);
    assert.throws(() => validateTapRun(1, valid), /test_run_failed/);
  });
}
