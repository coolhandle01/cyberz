#!/usr/bin/env bash
#
# Claude Code PreToolUse hook for Write|Edit.
#
# Maps the target file path to a stack of cybersquad skills and injects each
# matched skill's SKILL.md content into the model context via
# hookSpecificOutput.additionalContext - effectively auto-loading the relevant
# skills before each edit.
#
# Stacking: a path may match more than one skill (e.g. a pentest probe wrapper
# matches both the generic cybersquad-tool and the specialist
# cybersquad-pentest-tool). Generic skills are matched first and specialists
# layer on top, so the specialist appears later in the context window.
#
# Session-scoped sentinel: each skill is injected at most once per session, on
# the first matching Edit/Write. Subsequent edits in the same session are silent
# for skills that have already loaded.
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

# Build the matched-skill stack. Generic matchers come first; specialists
# layer on top. Each branch is independent so a path can match more than one.
matches=()

case "$file_path" in
    */squad/__init__.py|*/squad/workspace_tools.py|*/squad/*/__init__.py)
        matches+=(cybersquad-tool)
        ;;
esac

case "$file_path" in
    */tools/pentest/*|*/squad/penetration_tester/__init__.py)
        matches+=(cybersquad-pentest-tool)
        ;;
esac

case "$file_path" in
    */tests/*)
        matches+=(cybersquad-test-fixtures)
        ;;
esac

case "$file_path" in
    */tests/features/*|*/tests/bdd/*)
        matches+=(cybersquad-bdd)
        ;;
esac

case "$file_path" in
    */crew.py)
        matches+=(cybersquad-agent-llm)
        ;;
esac

[ "${#matches[@]}" -eq 0 ] && exit 0

# Emit each matched skill once per session, joined into a single
# additionalContext blob in stack order (generic first, specialist on top).
combined=""
for skill_name in "${matches[@]}"; do
    sentinel="$state_dir/$skill_name"
    [ -f "$sentinel" ] && continue

    skill_path="$skills_root/$skill_name/SKILL.md"
    [ -f "$skill_path" ] || continue

    touch "$sentinel"
    content=$(cat "$skill_path")
    header="Auto-loading skill $skill_name (matched on file path; this is its first edit this session)."
    if [ -n "$combined" ]; then
        combined="$combined"$'\n\n---\n\n'
    fi
    combined="${combined}${header}"$'\n\n'"${content}"
done

[ -z "$combined" ] && exit 0

jq -n --arg content "$combined" '
    {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            additionalContext: $content
        }
    }
'

exit 0
