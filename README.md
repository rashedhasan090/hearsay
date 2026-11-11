# hearsay

Multi-agent systems pass facts around in messages. A planner tells an operator which version to roll back to, a researcher tells a writer which CVE applies, a triage agent tells a fixer which commit broke the build. Nobody checks whether the agent that said it ever actually saw it.

`hearsay` reads a multi-agent trace and follows every concrete fact (numbers with units, versions, commit hashes, CVE IDs, URLs, file paths, emails, backticked identifiers) back to where it came from. It labels each one:

- **grounded**: the speaker saw it in its own tool result, or the user said it. Not reported.
- **rumor**: the first agent to state it had no tool result or user message behind it. It was made up or misremembered.
- **hearsay**: the speaker only got it from another agent's message. Low severity if some agent really observed it upstream, medium if the chain ends in a rumor.
- **acted-on-hearsay / acted-on-rumor**: the fact then went into a tool call (a deploy, a revert, a firewall rule) by an agent that never observed it. Acting on a rumor is high severity.

## What's new here

Hallucination checkers compare a single answer with a single context. Provenance and taint tools follow data from sources to sinks inside one program. `hearsay` does something in between for agent teams. It keeps a separate view of what each agent observed, tracks how a fact travels from agent to agent through messages, and reports the full relay chain back to whoever first said it. This shows the multi-agent failure where one agent's guess turns into another agent's command, and it also covers injected or spoofed peer messages, since a fact planted in a message has no observation behind it.

It is offline, uses only the Python standard library, and runs in CI.

## Install

```bash
pip install git+https://github.com/rashedhasan090/hearsay
# or, from a clone
pip install .
```

## Run

```bash
hearsay trace.jsonl                     # human-readable report
hearsay trace.jsonl --format json       # machine-readable
hearsay trace.jsonl --format md         # table for a PR comment
hearsay trace.jsonl --fail-on acted-on-rumor,high   # exit 1 in CI
hearsay trace.jsonl --shared-results    # every agent sees every tool result
cat trace.jsonl | hearsay -
```

Other options are `--min-severity low|medium|high`, and `--min-number N`, which ignores bare integers below N (default 11) so that step counts don't show up as findings.

## Trace format

One JSON object per line.

| field | meaning |
|---|---|
| `step` | ordering (optional, defaults to line order) |
| `agent` | who produced the event (`user` for the human) |
| `type` | `user`, `message`, `tool_call`, or `tool_result` |
| `content` | text, or an object for tool-call arguments |
| `tool` | tool name (optional) |

A `tool_result` counts as observed by its `agent`, which means the agent that made the call. Use `--shared-results` when your framework puts every tool result on a shared blackboard.

## Demo

`examples/incident.jsonl` is a three-agent incident response. The investigator really measured latency and the bad deploy, but made up a CVE. The planner made up a rollback target and a config path. The operator then rolled back to them.

```
$ hearsay examples/incident.jsonl
[MEDIUM] step 4 investigator: rumor cve 'cve-2026-31337'
         chain: - | origin: none
         first stated here with no tool result or user message behind it
[MEDIUM] step 5 planner: hearsay cve 'cve-2026-31337'
         chain: investigator@4 | origin: none
         relayed from another agent; nobody ever observed it
[LOW   ] step 5 planner: hearsay version '3.18.2'
         chain: investigator@4 | origin: tool_result:investigator@3
         relayed from another agent; observed by investigator@3
[MEDIUM] step 5 planner: rumor version '3.17.9'
         chain: - | origin: none
         first stated here with no tool result or user message behind it
[MEDIUM] step 5 planner: rumor path 'deploy/checkout/values.yaml'
         chain: - | origin: none
         first stated here with no tool result or user message behind it
[MEDIUM] step 6 operator: hearsay version '3.17.9'
         chain: planner@5 | origin: none
         relayed from another agent; nobody ever observed it
[LOW   ] step 6 operator: hearsay number '2400ms'
         chain: investigator@4 | origin: tool_result:investigator@3
         relayed from another agent; observed by investigator@3
[HIGH  ] step 7 operator: acted-on-rumor version '3.17.9'
         chain: operator@6 <- planner@5 | origin: none
         passed to tool deploy.rollback without this agent ever observing it
[HIGH  ] step 7 operator: acted-on-rumor path 'deploy/checkout/values.yaml'
         chain: planner@5 | origin: none
         passed to tool deploy.rollback without this agent ever observing it
summary: acted-on-rumor=2, hearsay=4, rumor=3
```

The 2400ms and 3.18.2 relays are low severity because the investigator really measured them. The rollback to 3.17.9 using `deploy/checkout/values.yaml` is the real problem, since no agent ever saw either value.

## Limits

Facts are found with patterns, not semantic parsing, so a paraphrased number ("about two and a half seconds") is not matched. Matching is literal after normalization (case, trailing punctuation, thousands separators). Treat findings as leads to check, not as proof.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

## License

MIT
