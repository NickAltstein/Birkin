"""Deterministic rule engine: pure functions from ToolCall -> list[Hit].

Zero LLM, zero network. All matching happens over the structured fields the
parsers extracted. Rules are loaded from rules.yaml (shipped with the package,
overridable via RECEIPTD_RULES env var) so users can extend them.

Only filenames, hosts and command tokens ever leave this module - see models.Hit.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from pathlib import Path
from typing import Optional

import yaml

from receiptd.card.models import Hit, ToolCall

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules.yaml"

# Http methods / URLs that constitute an outbound transfer.
HTTP_METHOD_RE = re.compile(r"\b(POST|PUT|PATCH|DELETE)\b", re.IGNORECASE)
# Piped/heredoc data-flow markers: "cmd < file", "cmd ... @file", "| cmd".
DATA_REDIRECT_RE = re.compile(r"(?:<\s*\S+|@\s*[\"']?/?\S+|--data\S*\s+\S+|(?<!\w)\|\s*(?!\s*$))")


def load_rules(path=None):
    """Load rules.yaml; falls back to the packaged file if a custom one is
    unreadable or structurally broken (never raises into the CLI)."""
    if path is None:
        override = os.environ.get("RECEIPTD_RULES")
        path = Path(override) if override else DEFAULT_RULES_PATH
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict) or not isinstance(data.get("version"), int):
            raise ValueError("rules file must be a mapping with an integer version")
        return data
    except Exception:
        with open(DEFAULT_RULES_PATH, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)


def rules_version(rules):
    return str(rules.get("version", "0"))


def _glob_match(pattern, path, case_insensitive=True):
    pattern, path = str(pattern), str(path)
    # A leading ~ in a rule stands for *any* user's home directory: the rule
    # "~/.ssh/*" must match "/home/<whoever>/.ssh/id_rsa", regardless of who
    # runs receiptd. Match the home-relative tail instead of a concrete home.
    if pattern.startswith("~/"):
        pattern = "*" + pattern[1:]  # "*/.ssh/*"
    if case_insensitive:
        pattern, path = pattern.lower(), path.lower()
    return fnmatch.fnmatch(path, pattern)


def _expand_home(path):
    """Normalize a logged path for matching: expand ~, strip cwd prefixes."""
    return os.path.expanduser(path)


def _match_any(patterns, value, **kwargs):
    return any(_glob_match(p, value, **kwargs) for p in patterns)


def _tokens(command):
    """Shell tokens of a command line (best effort; falls back to splitting)."""
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


# Command separators: every segment of a pipeline / && chain gets its own
# program, so `cat key | curl -d @- host` is examined as cat AND curl.
_SEGMENT_SPLIT_RE = re.compile(r"\||&&|\|\||;|\n")


def _pipeline_programs(command):
    """[(program, args)] for every command segment in the line."""
    segments = []
    for segment in _SEGMENT_SPLIT_RE.split(command or ""):
        tokens = _tokens(segment.strip())
        if tokens:
            segments.append((os.path.basename(tokens[0]), tokens[1:]))
    return segments


def _program_and_args(command):
    tokens = _tokens(command)
    if not tokens:
        return "", []
    program = os.path.basename(tokens[0])
    return program, tokens[1:]


# Programs whose first non-flag argument is a remote host.
_NETWORK_CLIENTS = {"nc", "ncat", "netcat", "ssh", "scp", "sftp", "telnet", "ftp", "rsync"}
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")


def _host_argument(program, args):
    """First non-flag argument of a network client command, if host-like."""
    if program not in _NETWORK_CLIENTS:
        return None
    for arg in args:
        if arg.startswith("-"):
            continue
        if _HOSTNAME_RE.match(arg):
            return arg
    return None


def _first_match_text(patterns, text):
    """First case-insensitive substring of `text` matching any pattern."""
    lowered = text.lower()
    for pattern in patterns:
        if pattern.lower() in lowered:
            return pattern
    return None


# ---------------------------------------------------------------------------
# PRIVATE
# ---------------------------------------------------------------------------


def _private_path_match(rules, path):
    """Return (rule, display) if `path` matches a private rule, else None.

    `display` is a filename only - never a directory or full path.
    """
    if not path:
        return None
    expanded = _expand_home(path)
    filename = os.path.basename(expanded)
    private = rules.get("private", {})
    filename_globs = list(private.get("filename_globs", [])) + list(
        private.get("extra_filename_globs", [])
    )
    for glob in filename_globs:
        if _glob_match(glob, filename):
            return ("filename_glob", filename)
    path_globs = private.get("path_globs", [])
    for glob in path_globs:
        if _glob_match(glob, expanded):
            return ("path_glob", filename)
    keywords = private.get("path_keywords", [])
    keyword = _first_match_text(keywords, expanded.replace(os.sep, "/"))
    if keyword:
        return (f"keyword:{keyword}", filename)
    return None


def classify_private(call: ToolCall, rules) -> list:
    """Sensitive local reads: file_path / pattern targets only."""
    hits = []
    match = _private_path_match(rules, call.file_path)
    if match:
        rule, display = match
        hits.append(
            Hit("PRIVATE", call.index, call.tool, display, call.timestamp, rule, is_path=True)
        )
    # A grep/glob pattern can itself point at a sensitive file (e.g. "*.pem").
    if call.pattern:
        pattern_match = _private_path_match(rules, call.pattern)
        if pattern_match:
            rule, display = pattern_match
            hits.append(
                Hit("PRIVATE", call.index, call.tool, display, call.timestamp, rule, is_path=True)
            )
    return hits


# ---------------------------------------------------------------------------
# UNTRUSTED
# ---------------------------------------------------------------------------


def _untrusted_path_match(rules, path):
    if not path:
        return None
    expanded = _expand_home(path)
    filename = os.path.basename(expanded)
    for glob in rules.get("untrusted", {}).get("path_globs", []):
        if _glob_match(glob, expanded):
            return ("path_glob", filename)
    return None


def _untrusted_tool_match(rules, call: ToolCall):
    untrusted = rules.get("untrusted", {})
    names = list(untrusted.get("tool_names", [])) + list(untrusted.get("extra_tool_names", []))
    for glob in names:
        if _glob_match(glob, call.tool):
            # Target is a host (from the URL) or the tool name itself -
            # never the query / prompt text.
            from receiptd.card.models import URL_HOST_RE

            host_match = URL_HOST_RE.search(call.url or "")
            target = host_match.group(1) if host_match else call.tool
            return ("tool_name", target)
    return None


def classify_untrusted(call: ToolCall, rules) -> list:
    """Untrusted input: fetch tools, fetched-file reads, non-local MCP results."""
    hits = []
    tool_match = _untrusted_tool_match(rules, call)
    if tool_match:
        rule, target = tool_match
        hits.append(Hit("UNTRUSTED", call.index, call.tool, target, call.timestamp, rule))
    match = _untrusted_path_match(rules, call.file_path)
    if match:
        rule, filename = match
        hits.append(
            Hit("UNTRUSTED", call.index, call.tool, filename, call.timestamp, rule, is_path=True)
        )
    # Reading the output of curl/wget (piped or from a file it wrote): the
    # curl/wget segment itself is flagged as the untrusted data source.
    if call.command:
        untrusted = rules.get("untrusted", {})
        fetch_programs = set(untrusted.get("command_tokens", []))
        for program, _args in _pipeline_programs(call.command):
            if program in fetch_programs:
                host = call.hosts()[0] if call.hosts() else None
                hits.append(
                    Hit(
                        "UNTRUSTED",
                        call.index,
                        call.tool,
                        host or program,
                        call.timestamp,
                        "curl_wget_output",
                    )
                )
                break
    # MCP results from non-local servers: any mcp__ tool whose server is listed.
    if call.tool.startswith("mcp__") and call.server:
        servers = rules.get("untrusted", {}).get("nonlocal_mcp_servers", [])
        for glob in servers:
            if _glob_match(glob, call.server):
                hits.append(
                    Hit("UNTRUSTED", call.index, call.tool, call.server, call.timestamp, "nonlocal_mcp")
                )
                break
    return hits


# ---------------------------------------------------------------------------
# EGRESS
# ---------------------------------------------------------------------------


def _egress_command_match(rules, command):
    """(rule, target) if any segment of the command performs outbound transfer."""
    if not command:
        return None
    egress = rules.get("egress", {})
    segments = _pipeline_programs(command)
    if not segments:
        return None
    all_tokens = list(egress.get("command_tokens", [])) + list(egress.get("extra_command_tokens", []))
    lowered = command.lower()
    matched_rule = None
    matched_program = ""
    # Multi-word tokens (e.g. "git push", "npm publish") match the raw line.
    for token in all_tokens:
        token_l = token.lower()
        if " " in token_l:
            if token_l in lowered:
                matched_rule = f"command:{token}"
                matched_program = token_l
                break
    # Single-word tokens match the program of any pipeline segment.
    if matched_rule is None:
        programs = {program for program, _args in segments}
        for token in all_tokens:
            token_l = token.lower()
            if " " not in token_l and token_l in programs:
                matched_rule = f"program:{token}"
                matched_program = token_l
                break
    if matched_rule is None:
        return None
    # Target: URL host, user@host, host argument or the program token itself.
    from receiptd.card.models import URL_HOST_RE, USER_HOST_RE

    host_match = URL_HOST_RE.search(command) or USER_HOST_RE.search(" " + command + " ")
    if host_match:
        return (matched_rule, host_match.group(1))
    for program, args in segments:
        if program == matched_program:
            host = _host_argument(program, args)
            if host:
                return (matched_rule, host)
            break
    return (matched_rule, matched_program)


def _is_allowlisted(rules, host):
    if not host:
        return False
    allow = rules.get("egress", {}).get("allowlisted_hosts", [])
    return any(_glob_match(p, host) for p in allow)


def classify_egress(call: ToolCall, rules) -> list:
    """Outbound data transfer: network commands, HTTP to hosts, sending MCP tools."""
    hits = []
    # Bash-family network commands.
    command_match = _egress_command_match(rules, call.command)
    if command_match:
        rule, target = command_match
        hits.append(Hit("EGRESS", call.index, call.tool, target, call.timestamp, rule))
    # WebFetch / HTTP to non-allowlisted hosts.
    if call.url:
        from receiptd.card.models import URL_HOST_RE

        host_match = URL_HOST_RE.search(call.url)
        if host_match and not _is_allowlisted(rules, host_match.group(1)):
            host = host_match.group(1)
            method_match = HTTP_METHOD_RE.search(call.command or "")
            if call.tool in ("WebFetch", "WebSearch", "web_search", "websearch") or method_match:
                rule = "webfetch_host" if call.tool == "WebFetch" else "web_to_host"
                hits.append(Hit("EGRESS", call.index, call.tool, host, call.timestamp, rule))
            elif method_match:
                hits.append(Hit("EGRESS", call.index, call.tool, host, call.timestamp, "http_method"))
    # MCP tools whose names/descriptions imply send/post/create/upload.
    if call.tool.startswith("mcp__"):
        egress = rules.get("egress", {})
        tokens = egress.get("mcp_tokens", [])
        haystack = f"{call.tool} {call.description or ''}".lower()
        for token in tokens:
            if token.lower() in haystack:
                target = call.server or call.tool.split("__")[0]
                hits.append(Hit("EGRESS", call.index, call.tool, target, call.timestamp, f"mcp_token:{token}"))
                break
    return hits


# ---------------------------------------------------------------------------
# combined classifier
# ---------------------------------------------------------------------------


def classify_call(call: ToolCall, rules) -> list:
    """All hits for one tool call, in PRIVATE / UNTRUSTED / EGRESS order."""
    hits = []
    hits.extend(classify_private(call, rules))
    hits.extend(classify_untrusted(call, rules))
    hits.extend(classify_egress(call, rules))
    return hits


def classify_session(calls, rules) -> list:
    """Classify a full session's tool calls (order preserved)."""
    hits = []
    for call in calls:
        hits.extend(classify_call(call, rules))
    return hits
