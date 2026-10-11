const ROLE_TABLES = Object.freeze({
  LB115: "vg_controller_maintenance",
  CT200: "vg_native_maintenance",
});
const ROLE_PORTS = Object.freeze({
  LB115: Object.freeze([4000, 8443, 18082, 9444, 9445]),
  CT200: Object.freeze([8080, 8188, 8190]),
});
const ROLE_LANE_PORTS = Object.freeze({
  LB115: Object.freeze([8443]),
  CT200: Object.freeze([8080, 8188, 8190]),
});
const VALIDATION_SOURCE_PORTS = new Set([443, 444, 445]);
const LOOPBACK_V4 = "127.0.0.1";
const ROOT_UID = 0;
const CHAIN_PRIORITY = -150;
const MAX_TRANSACTION_CHARS = 8192;
const PLAN_SCHEMA = "maintenance-fence-plan-v1";
const RECEIPT_SCHEMA = "maintenance-fence-plan-receipt-v1";
const REMOVAL_SCHEMA = "maintenance-fence-removal-v1";
const RECEIPT_KEYS = ["schema", "role", "table", "ownershipNonce", "validationLane"];
const LANE_KEYS = ["sourceAddress", "destinationAddress", "sourcePort", "outputUid", "destinationPorts"];
const planReceipts = new WeakSet();

function fail(code) { throw new Error(code); }

function exactDataRecord(value, expectedKeys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== expectedKeys.length || keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return expectedKeys.every((key) => descriptors[key] && descriptors[key].enumerable && Object.prototype.hasOwnProperty.call(descriptors[key], "value"));
  } catch {
    return false;
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function expectedReceipt(role, table, ownershipNonce, sourcePort) {
  return deepFreeze({
    schema: RECEIPT_SCHEMA,
    role,
    table,
    ownershipNonce,
    validationLane: {
      sourceAddress: LOOPBACK_V4,
      destinationAddress: LOOPBACK_V4,
      sourcePort,
      outputUid: ROOT_UID,
      destinationPorts: [...ROLE_LANE_PORTS[role]],
    },
  });
}

function validGeneratedReceipt(receipt) {
  if (!planReceipts.has(receipt) || !exactDataRecord(receipt, RECEIPT_KEYS)) return false;
  if (receipt.schema !== RECEIPT_SCHEMA || typeof receipt.role !== "string" || !Object.prototype.hasOwnProperty.call(ROLE_TABLES, receipt.role) || receipt.table !== ROLE_TABLES[receipt.role] || typeof receipt.ownershipNonce !== "string" || receipt.ownershipNonce.length !== 32 || !/^[a-f0-9]{32}$/.test(receipt.ownershipNonce)) return false;
  const lane = receipt.validationLane;
  if (!exactDataRecord(lane, LANE_KEYS) || lane.sourceAddress !== LOOPBACK_V4 || lane.destinationAddress !== LOOPBACK_V4 || lane.outputUid !== ROOT_UID || !VALIDATION_SOURCE_PORTS.has(lane.sourcePort)) return false;
  const ports = ROLE_LANE_PORTS[receipt.role];
  return Array.isArray(lane.destinationPorts) && lane.destinationPorts.length === ports.length && ports.every((port, index) => lane.destinationPorts[index] === port);
}

function transactionFor(table, ownershipNonce, blockedPorts, lanePorts, sourcePort) {
  const lines = [
    `create table inet ${table} { comment "vg-maintenance-owner-nonce-${ownershipNonce}"; }`,
    `add chain inet ${table} input { type filter hook input priority ${CHAIN_PRIORITY}; policy accept; }`,
    `add chain inet ${table} output { type filter hook output priority ${CHAIN_PRIORITY}; policy accept; }`,
  ];
  for (const port of lanePorts) {
    lines.push(`add rule inet ${table} input iifname "lo" ip saddr ${LOOPBACK_V4} ip daddr ${LOOPBACK_V4} tcp sport ${sourcePort} tcp dport ${port} accept`);
    lines.push(`add rule inet ${table} output oifname "lo" meta skuid ${ROOT_UID} ip saddr ${LOOPBACK_V4} ip daddr ${LOOPBACK_V4} tcp sport ${sourcePort} tcp dport ${port} accept`);
    // Reject only the same validation-shaped output tuple when the originating UID is not root.
    lines.push(`add rule inet ${table} output oifname "lo" ip saddr ${LOOPBACK_V4} ip daddr ${LOOPBACK_V4} tcp sport ${sourcePort} tcp dport ${port} drop`);
  }
  for (const port of blockedPorts) {
    // INPUT drops cover all local service arrivals; there is no output destination-port rule.
    lines.push(`add rule inet ${table} input tcp dport ${port} drop`);
  }
  const transaction = `${lines.join("\n")}\n`;
  if (transaction.length > MAX_TRANSACTION_CHARS) fail("transaction_bound");
  return transaction;
}

/**
 * Build a bounded nft batch only. The caller must separately establish exclusive source-port
 * ownership; this output proves neither that fact nor live nft/kernel state.
 */
export function buildInstallPlan(input) {
  if (arguments.length !== 1) fail("input_invalid");
  if (!exactDataRecord(input, ["role", "sourcePort", "ownershipNonce"])) fail("input_invalid");
  const { role, sourcePort, ownershipNonce } = input;
  if (typeof role !== "string" || !Object.prototype.hasOwnProperty.call(ROLE_TABLES, role)) fail("role_invalid");
  if (!VALIDATION_SOURCE_PORTS.has(sourcePort)) fail("source_port_invalid");
  if (typeof ownershipNonce !== "string" || ownershipNonce.length !== 32 || !/^[a-f0-9]{32}$/.test(ownershipNonce)) fail("nonce_invalid");

  const table = ROLE_TABLES[role];
  const destinationPorts = [...ROLE_PORTS[role]];
  const lanePorts = [...ROLE_LANE_PORTS[role]];
  const receipt = expectedReceipt(role, table, ownershipNonce, sourcePort);
  planReceipts.add(receipt);
  return deepFreeze({
    schema: PLAN_SCHEMA,
    transactionMode: "single-atomic-nft-batch",
    submissionMode: "nft -f -",
    role,
    table,
    ownershipNonce,
    destinationPorts,
    validationDestinationPorts: lanePorts,
    transaction: transactionFor(table, ownershipNonce, destinationPorts, lanePorts, sourcePort),
    receipt,
  });
}

/**
 * Generate removal only from this module's immutable plan receipt after explicit success.
 * The plan receipt coordinates the caller; it is not kernel table ownership/custody proof.
 */
export function buildRemovalPlan(receipt, verificationDisposition) {
  if (arguments.length !== 2) fail("input_invalid");
  if (verificationDisposition !== "successfully_verified") fail("verification_not_successful");
  if (!validGeneratedReceipt(receipt)) fail("receipt_invalid");
  return deepFreeze({
    schema: REMOVAL_SCHEMA,
    role: receipt.role,
    table: receipt.table,
    ownershipNonce: receipt.ownershipNonce,
    verificationDisposition,
    transaction: `delete table inet ${receipt.table}\n`,
  });
}
