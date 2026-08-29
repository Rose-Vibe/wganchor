# Sprints

Unified home for all planning, roadmap, and implementation tracking.

## Structure

```
docs/sprints/
  README.md                         # this file
  archive/                          # completed sprints (dated: 2026-07-17-sprint-name/)
  {sprint-name}/                    # active sprint directory
    SPRINT.md                       # optional overview, purpose, rough roadmap
    plan-{name}.md                  # task plan with checkboxes and context
    plan-{name}-COMPLETE.md         # completed plan (renamed from plan-{name}.md)
    doc-{name}.md                   # supporting documents (design notes, research, etc.)
```

## Sprints

Named directories grouping related work. When all plans in a sprint are complete,
move the sprint directory into `archive/` with an ISO date prefix:
`mv docs/sprints/my-sprint docs/sprints/archive/2026-07-17-my-sprint`

## Plans

Primary work-tracking artifact. Each `plan-{name}.md` is scoped to one major
feature or implementation unit with checkbox'd task lists and enough context to
implement from. When complete, rename to `plan-{name}-COMPLETE.md`.
