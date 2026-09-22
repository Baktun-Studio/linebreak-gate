#!/usr/bin/env bash
# The Action's acceptance-criteria step (issue #256): resolve the `story` and
# `manual` inputs into `linebreak-gate check` flags, state the scope as the
# first line of the report, run the check, and exit with ITS code.
#
# Usage: check-scope.sh <project-path> <report-file>
#
# Inputs (environment):
#   INPUT_STORY   all | auto | <story id>
#                 all  = every approved story (the pre-1.11 behavior)
#                 auto = infer <id> from a feat/<id> or story/<id> branch
#                        (a trailing slug is allowed: feat/<id>-add-login) when
#                        it is an approved story; otherwise --started-only
#   INPUT_MANUAL  warn | block | "" (empty = warn on pull_request, block else)
#   INPUT_STAGE   release | pr | "" (empty = release, the pre-1.12 behavior);
#                 pr skips `check.when: release` criteria (listed, not counted)
#   EVENT_NAME    the GitHub event name (github.event_name)
#   BRANCH        the source branch (github.head_ref on PRs, ref_name else)
#
# Exit: the check's own exit code (0 pass / 1 blocking / 2 tool error). An
# invalid input is exit 2 without running anything: fail closed. Note that
# --started-only itself is exit 2 when no story has a started local state, so
# the `auto` fallback never turns an unresolvable branch into a green check.
set -uo pipefail

path="${1:?project path}"
report="${2:?report file}"
: > "$report"

note() {
  echo "linebreak-gate action: $*" | tee -a "$report"
}

# Is <id> an approved story? `spec show` exits 0 for an approved story (and
# when no spec exists at all, in which case the check is a no-op either way).
approved() {
  linebreak-gate spec show "$1" --path "$path" >/dev/null 2>&1
}

# Resolve the story id from a branch name: the segment after feat/ or story/,
# then progressively without its trailing -slug parts (feat/E1-S1-add-login
# tries E1-S1-add-login, E1-S1-add, E1-S1). Prints the first approved id.
infer_story() {
  local branch="$1" candidate
  local slug_re='^(feat|story)/([A-Za-z0-9][A-Za-z0-9._-]*)$'
  [[ "$branch" =~ $slug_re ]] || return 1
  candidate="${BASH_REMATCH[2]}"
  while [ -n "$candidate" ]; do
    if approved "$candidate"; then
      echo "$candidate"
      return 0
    fi
    [[ "$candidate" == *-* ]] || break
    candidate="${candidate%-*}"
  done
  return 1
}

manual="${INPUT_MANUAL:-}"
if [ -z "$manual" ]; then
  if [ "${EVENT_NAME:-}" = "pull_request" ]; then manual=warn; else manual=block; fi
fi
case "$manual" in
  warn|block) ;;
  *)
    note "invalid 'manual' input '$manual' (expected warn or block); gate stays closed"
    exit 2
    ;;
esac

stage="${INPUT_STAGE:-release}"
case "$stage" in
  release|pr) ;;
  *)
    note "invalid 'stage' input '$stage' (expected release or pr); gate stays closed"
    exit 2
    ;;
esac

args=(check --path "$path" --manual "$manual" --stage "$stage")
story="${INPUT_STORY:-}"
branch="${BRANCH:-}"
case "$story" in
  all)
    scope="scope: all stories (story: all)"
    ;;
  auto)
    if id=$(infer_story "$branch"); then
      args+=(--story "$id")
      scope="scope: story $id inferred from branch $branch (story: auto)"
    else
      args+=(--started-only)
      scope="scope: started stories only; no approved story id in branch '$branch' (story: auto)"
    fi
    ;;
  "")
    note "invalid 'story' input (empty; expected all, auto, or a story id); gate stays closed"
    exit 2
    ;;
  *)
    args+=(--story "$story")
    scope="scope: story $story (story input)"
    ;;
esac

note "$scope; manual criteria: $manual; stage: $stage"
linebreak-gate "${args[@]}" 2>&1 | tee -a "$report"
exit "${PIPESTATUS[0]}"
