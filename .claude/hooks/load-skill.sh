#!/usr/bin/env bash
#
# Claude Code PreToolUse hook for Write|Edit.
#
# Maps the target file path to a cybersquad skill and injects that skill's
# SKILL.md content into the model context via hookSpecificOutput.additionalContext
# - effectively auto-loading the relevant skill before each edit.
#
# Session-scoped sentinel: each skill is injected at most once per session, on
# the first matching Edit/Write. Subsequent edits in the same session are silent
# (the skill is already in context).
#
# Wired via .claude/settings.json. Silently noops if jq is missing or the
# expected stdin shape is absent - never blocks the edit.
#
set -uo pipefail

# Bail quietly on anything unexpected - this hook must never break a tool call.
trap 'exit 0' ERR

command -v jq >/dev/null 2>&1 || exit 0

input=$(cat)
file_path=$(echo "$input" | jq -r '.tool_input.file_path // ""')
session_id=$(echo "$input" | jq -r '.session_id // ""')

[ -z "$file_path" ] && exit 0
[ -z "$session_id" ] && exit 0

# Repo-root anchor: hook runs from project cwd; resolve skill paths against it.
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
skills_root="$repo_root/.claude/skills"
state_dir="${TMPDIR:-/tmp}/cybersquad-skills-$session_id"
mkdir -p "$state_dir"

# Emit the skill content as additionalContext, once per session per skill.
emit_skill() {
    local skill_name="$1"
    local sentinel="$state_dir/$skill_name"
    [ -f "$sentinel" ] && exit 0  # already loaded this session

    local skill_path="$skills_root/$skill_name/SKILL.md"
    [ -f "$skill_path" ] || exit 0

    touch "$sentinel"
    local content
    content=$(cat "$skill_path")

    jq -n --arg skill "$skill_name" --arg content "$content" '
        {
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                additionalContext: ("Auto-loading skill \($skill) (matched on file path; this is its first edit this session).\n\n" + $content)
            }
        }
    '
    exit 0
}

# Most specific match wins (case statement evaluates top-down).
case "$file_path" in
    */tools/pentest/*|*/squad/penetration_tester/__init__.py)
        emit_skill cybersquad-pentest-tool
        ;;
    */tests/features/*|*/tests/bdd/*)
        emit_skill cybersquad-bdd
        ;;
    */tests/*)
        emit_skill cybersquad-test-fixtures
        ;;
    */crew.py)
        emit_skill cybersquad-agent-llm
        ;;
    */squad/__init__.py|*/squad/workspace_tools.py|*/squad/*/__init__.py)
        emit_skill cybersquad-tool
        ;;
esac

exit 0
