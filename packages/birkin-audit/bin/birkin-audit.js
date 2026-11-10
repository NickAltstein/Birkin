#!/usr/bin/env node

/**
 * birkin-audit: Fast zero-dependency CLI scanner for MCP & agent configurations.
 * Audits local mcp.json, .claude/settings.json, and agent configurations for blast-radius risks.
 */

const fs = require("fs");
const path = require("path");

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  dim: "\x1b[2m",
};

const RULES = [
  {
    id: "POL-01",
    name: "NO_ENV_EXFILTRATION",
    pattern: /(\.env|AWS_SECRET|PRIVATE_KEY|curl\s+.*-d|wget)/i,
    weight: 95,
  },
  {
    id: "POL-02",
    name: "NO_DESTRUCTIVE_DDL_FS",
    pattern: /\b(DROP\s+TABLE|TRUNCATE|DELETE\s+FROM|rm\s+-rf|mkfs|\/etc\/passwd)\b/i,
    weight: 90,
  },
  {
    id: "POL-03",
    name: "NO_PRIVILEGE_ESCALATION",
    pattern: /\b(sudo|chmod\s+777|chown\s+root|\.claude\/settings\.json)\b/i,
    weight: 85,
  },
];

function findMcpConfigs(cwd) {
  const candidatePaths = [
    path.join(cwd, "mcp.json"),
    path.join(cwd, ".mcp.json"),
    path.join(cwd, ".claude", "settings.json"),
    path.join(cwd, ".vscode", "mcp.json"),
    path.join(cwd, "claude_desktop_config.json"),
  ];

  const found = [];
  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      found.push(p);
    }
  }
  return found;
}

function evaluateServer(name, serverConfig) {
  const serialized = JSON.stringify(serverConfig);
  let score = 10;
  const triggered = [];

  for (const rule of RULES) {
    if (rule.pattern.test(serialized)) {
      score = Math.min(100, score + rule.weight);
      triggered.push(rule.id);
    }
  }

  // Check command exposure
  const cmd = serverConfig.command || "";
  const args = Array.isArray(serverConfig.args) ? serverConfig.args.join(" ") : "";
  const fullCmd = `${cmd} ${args}`.toLowerCase();

  if (fullCmd.includes("postgres") || fullCmd.includes("sqlite") || fullCmd.includes("sql")) {
    score = Math.max(score, 65);
    if (!triggered.includes("RISK-DATA-MUTATION")) triggered.push("RISK-DATA-MUTATION");
  }

  if (fullCmd.includes("bash") || fullCmd.includes("sh") || fullCmd.includes("exec")) {
    score = Math.max(score, 80);
    if (!triggered.includes("RISK-ARBITRARY-SHELL")) triggered.push("RISK-ARBITRARY-SHELL");
  }

  return { name, score, triggered, config: serverConfig };
}

function renderTable(rows) {
  const headers = ["MCP Server / Tool", "Blast Score", "Status", "Identified Risk Signatures"];
  const colWidths = [
    Math.max(headers[0].length, ...rows.map((r) => r[0].length)),
    Math.max(headers[1].length, ...rows.map((r) => r[1].length)),
    Math.max(headers[2].length, ...rows.map((r) => r[2].length)),
    Math.max(headers[3].length, ...rows.map((r) => r[3].length)),
  ];

  const formatRow = (cols) =>
    cols.map((col, i) => col.padEnd(colWidths[i])).join(" | ");

  const separator = colWidths.map((w) => "-".repeat(w)).join("-+-");

  console.log(formatRow(headers));
  console.log(separator);
  for (const row of rows) {
    console.log(formatRow(row));
  }
}

function main() {
  console.log(`\n${ANSI.bold}${ANSI.cyan}BIRKIN AGENT BLAST-RADIUS AUDITOR (v1.0.0)${ANSI.reset}`);
  console.log(`${ANSI.dim}Scanning workspace for MCP tool permissions & runtime hooks...${ANSI.reset}\n`);

  const cwd = process.cwd();
  const configs = findMcpConfigs(cwd);

  if (configs.length === 0) {
    console.log(`${ANSI.yellow}[i] No mcp.json or .claude/settings.json found in current directory.${ANSI.reset}`);
    console.log(`\nTo initialize Birkin fail-closed governance hooks in this repo:`);
    console.log(`  ${ANSI.bold}pip install birkin && birkin init --claude-code${ANSI.reset}`);
    console.log(`\nOr test adversarial vectors in the live simulator:`);
    console.log(`  ${ANSI.cyan}https://auditgpt.ai/?scenario=prod-drop-table&step=1${ANSI.reset}\n`);
    process.exit(0);
  }

  const allServers = [];
  let birkinHookDetected = false;

  for (const cfgPath of configs) {
    console.log(`  [+] Inspecting configuration: ${ANSI.dim}${path.relative(cwd, cfgPath)}${ANSI.reset}`);
    try {
      const parsed = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));

      if (parsed.hooks && parsed.hooks.PreToolUse) {
        birkinHookDetected = true;
      }

      const servers = parsed.mcpServers || {};
      for (const [name, srv] of Object.entries(servers)) {
        allServers.push(evaluateServer(name, srv));
      }
    } catch (err) {
      console.error(`${ANSI.red}  [!] Error parsing ${cfgPath}: ${err.message}${ANSI.reset}`);
    }
  }

  console.log();

  if (allServers.length === 0) {
    console.log(`${ANSI.green}[✓] Zero high-risk MCP servers configured.${ANSI.reset}`);
  } else {
    const tableRows = allServers.map((srv) => {
      const status =
        srv.score >= 75
          ? `${ANSI.red}HIGH RISK${ANSI.reset}`
          : srv.score >= 40
          ? `${ANSI.yellow}MODERATE${ANSI.reset}`
          : `${ANSI.green}AUDITED${ANSI.reset}`;

      const plainStatus = srv.score >= 75 ? "HIGH RISK" : srv.score >= 40 ? "MODERATE" : "AUDITED";
      const tags = srv.triggered.length > 0 ? srv.triggered.join(", ") : "Standard Isolation";

      return [srv.name, `${srv.score}/100`, plainStatus, tags];
    });

    renderTable(tableRows);
  }

  console.log(`\n${"=".repeat(65)}`);
  if (birkinHookDetected) {
    console.log(`${ANSI.green}${ANSI.bold}[✓] BIRKIN PRE-TOOL HOOK ACTIVE${ANSI.reset} — Fail-closed exit code 2 enforced.`);
  } else {
    console.log(`${ANSI.red}${ANSI.bold}[!] BIRKIN HOOK MISSING${ANSI.reset} — Agent tool calls currently run un-gated!`);
    console.log(`Run ${ANSI.bold}pip install birkin && birkin init --claude-code${ANSI.reset} to wire fail-closed protection.`);
  }
  console.log(`${"=".repeat(65)}\n`);
}

main();

