<h1 align="center">llm-security-skills</h1>

<p align="center">
  <b>Agent Skills that turn your AI coding agent into an LLM security reviewer.</b><br>
  Drop-in <code>SKILL.md</code> packs for prompt-injection testing, OWASP LLM Top 10 audits,
  MCP &amp; RAG review, and KVKK/PII checks — English &amp; Turkish.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <img alt="Skills" src="https://img.shields.io/badge/skills-7-brightgreen.svg">
  <img alt="Multilingual" src="https://img.shields.io/badge/lang-EN%20%2B%20TR-informational">
</p>

---

Agent Skills are small, model-facing instruction packs (`SKILL.md`) that an agent
loads to do a focused job well. This repo packages **LLM/AI security expertise** as
skills, so your agent can run a structured review instead of improvising.

> ⚠️ **Authorized use only.** These skills are for testing and securing systems you
> own or have written permission to assess. They describe methodology, not exploits.

## Install

Copy the skills you want into your agent's skills directory:

```bash
# Claude Code / agents that read ~/.claude/skills or a project .claude/skills
git clone https://github.com/fevziegeyurtsevenler/llm-security-skills
cp -r llm-security-skills/skills/* ~/.claude/skills/
```

Then ask your agent to use them by name (e.g. *"use the llm-red-team skill on this app"*).

## The skills

| Skill | What it does |
|---|---|
| **prompt-injection-tester** | Systematically probes an LLM app/endpoint for direct & indirect prompt injection (EN + TR payload families), mapped to OWASP LLM01. |
| **llm-red-team** | Runs a structured red-team across the OWASP LLM Top 10 (2025): scope, method, per-risk tests, reporting. |
| **owasp-llm-top10-audit** | Checklist-driven audit of an LLM app against the OWASP LLM Top 10, with evidence and mitigations. |
| **agent-skill-auditor** | Vets an Agent Skill / MCP config / rules file **before install** using [`uncloak`](https://github.com/fevziegeyurtsevenler/uncloak) — hidden Unicode, tool-poisoning, exfil, the lethal trifecta. |
| **mcp-security-review** | Reviews an MCP server/config for tool-poisoning, command injection, excessive agency and token leakage (MITRE ATLAS-mapped). |
| **rag-security-review** | Reviews a RAG pipeline for indirect injection, data poisoning, access control and citation safety. |
| **kvkk-pii-review** | (Turkish) Reviews an LLM app for KVKK/PII exposure — 18 personal-data types incl. TCKN/IBAN/VKN — and recommends masking & data minimization. |

## Why skills (not another tool)

The scanners already exist; the missing piece is **applied methodology** your agent
can follow consistently. Each skill encodes how a reviewer actually works, so results
are repeatable and mapped to recognized frameworks (OWASP LLM Top 10, MITRE ATLAS).

## Related

- [`uncloak`](https://github.com/fevziegeyurtsevenler/uncloak) — scanner the auditor skill calls.
- [`prompt-injection-corpus`](https://github.com/fevziegeyurtsevenler/prompt-injection-corpus) — payload/technique corpus the tester skill draws on.
- [`awesome-agent-supply-chain-security`](https://github.com/fevziegeyurtsevenler/awesome-agent-supply-chain-security) — the wider field.

## Contributing

New skills and improvements welcome — keep them accurate, framework-mapped and
authorized-use-only. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE) © Fevzi Ege Yurtsevenler
