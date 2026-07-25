# Contributing to llm-security-skills

New skills and improvements are welcome. A good security skill is **accurate,
framework-mapped, and authorized-use-only.**

## Adding a skill

1. Create `skills/<your-skill>/SKILL.md` with YAML front-matter (`name`,
   `description`) and a clear, step-by-step methodology body.
2. Map its checks to a recognized framework where possible (OWASP LLM Top 10 2025,
   MITRE ATLAS).
3. State its scope and limits, and include an authorized-use note.
4. Keep it methodology, not exploit code.

## Quality bar

- Repeatable: another reviewer following the skill should reach the same result.
- Honest: no "first/best" claims; cite frameworks and sources.
- Safe: nothing that only makes sense for attacking systems you don't control.

Open a PR describing what the skill reviews and which framework items it covers.
