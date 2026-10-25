# Threat model

agentguard is a reference monitor for the tool calls of an LLM agent. This document states
what it defends against, what it assumes, and where it stops. It is a defensive, lab-only
project: every tool in this repository is a fake that acts on an in-memory fixture world,
and every "attack" is a hand-written prompt-injection fixture aimed at that world.

## Assets

| asset | example in the sandbox | harmed by |
|---|---|---|
| money | `pay`, `add_payee` | transfers to attacker-controlled payees, overpayment, many small payments |
| confidential data | `secrets/**`, `finance/**`, internal e-mail | exfiltration via `send_email` or URL query strings (`fetch_url`) |
| integrity of the workspace | `write_file`, `delete_file` | deleting logs/evidence, planting files outside the granted area |
| the user's identity | `send_email` from the user's mailbox | phishing colleagues "from" the user |
| the audit trail | `audit.jsonl` | editing, deleting or truncating records to hide what happened |

## Adversary

**Primary: indirect prompt injection.** The attacker cannot talk to the agent directly but
can put text where the agent will read it: a web page, an inbound e-mail, a downloaded
file, or a note that an earlier (already compromised) session wrote into the workspace.

We assume the worst case for the model: **once it has read attacker text, it may do
anything the attacker says**, with any arguments, in any order, as often as the loop lets
it. The scenario suite's fake model is scripted to behave exactly like that. Safety must
therefore never depend on the system prompt, the model's judgement, or detecting the
injection.

**Secondary: a careless or fatigued approver.** Approvals are a control, not a guarantee.
The `guard-rubber-stamp` configuration measures what an approve-everything human lets
through.

**Out of scope** (not defended):

* A malicious *user* who legitimately holds a broad grant. The policy is the user's
  authority; agentguard limits the agent to it, not the user.
* Compromise of the host process, the Python runtime, the policy file, or the tool
  implementations themselves. The guard is in-process; anything that can patch it can
  bypass it.
* Side channels and covert channels inside *allowed* actions (e.g. encoding data in the
  wording of an approved e-mail to an allowed recipient, or in which allowed URL is
  fetched). See "Limits" below.
* Denial of service against the agent (an attacker can always make an agent less useful by
  tainting its context).
* Correctness of the model's work. The guard decides whether an action is *permitted*, not
  whether it is *right*.

## Trust assumptions

1. Every tool call goes through `GuardedSession.call`. The agent loop in
   `agentguard.agent` has no other path to a handler; an embedding application must keep
   it that way.
2. Tool **specs are honest**: declared capabilities, impact, egress flag, spend arguments,
   argument aliases and output labels are written by the tool author, not by the model.
3. Tool **output labels are honest**: a tool that returns attacker-controllable text must
   label it `untrusted` (the sandbox's `fetch_url`, unverified `read_email`, files under
   `downloads/`, and files written by a tainted context do).
4. The user prompt and system prompt are trusted.
5. The audit HMAC key (if used) and the head anchor are stored where the agent cannot write.

## Controls and what each one stops

| control | where | stops |
|---|---|---|
| default deny, capability grants per task | `policy.py`, `engine.py` stage 4 | tools the task never needs (`attack-research-pay`) |
| argument constraints (globs, URL allow-lists, e-mail allow-lists, decimal bounds, enums) | `constraints.py` | exfiltration to foreign addresses/hosts, path traversal, overpayment |
| explicit deny rules (win over grants) | `engine.py` stage 3 | carve-outs such as `**/.env` or a `petty-cash` payee |
| strict arg schemas, `additionalProperties: false` by default | `schema.py` | smuggled extra arguments, type confusion (`True` as an amount) |
| context taint (integrity label) | `labels.py`, `session.py` | any high-impact action after the context has read untrusted text, including allowed-recipient exfiltration and cross-session laundering through files |
| secrecy label + egress rule | `engine.py` stage 9 | sending out a context that holds `secret` data without a human |
| approval thresholds and modes | `policy.py` | large or sensitive actions even from clean contexts |
| sliding-window rate limits, per-session budgets, tool-call cap | `limits.py` | many-small-payments and runaway loops, even with rubber-stamped approvals |
| hash-chained, optionally HMAC-keyed audit log + head anchor | `audit.py` | silent editing, deletion, reordering or truncation of the record |
| auditor-side invariant check | `session.check_taint_invariant` | lets a third party prove from the log alone that no high-impact call ran from a tainted context without an approval |

### The core invariant

> No tool with `impact: high` executes while the session context is labelled
> `untrusted`, unless an approver returned an explicit yes for that exact call.

It holds by construction (the policy parser rejects `taint.high: allow`; the engine
applies the taint stage after every grant matched), it is property-tested over random call
sequences with random approvers (`tests/test_properties_invariants.py`), it is checked on
every scenario run, and it can be re-checked by an auditor from the audit log.

## Labels and why they are context-level

Each session has one monotone label: integrity (`trusted` < `untrusted`) × secrecy
(`public` < `internal` < `secret`). Every tool result joins its label into the context;
nothing ever lowers it.

Value-level taint tracking (marking individual strings) is not sound around an LLM: the
model can paraphrase, translate or re-encode any token it has seen into any later
argument. So the unit of taint is the whole conversation. The price is utility: after one
web page, *every* high-impact action in that session needs a human — that is exactly what
the "calls allowed without a prompt" column in the evaluation measures.

Files keep the label of the context that wrote them (`write_file` stores `ctx.label`), and
overwriting never lowers it, so a tainted session cannot launder instructions through the
workspace for a later session (`attack-bookkeeper-laundered-note`).

## Audit log

Each JSONL record contains `seq`, `prev` (previous hash) and `hash = H(canonical record)`.
`H` is SHA-256, or HMAC-SHA256 with `AGENTGUARD_AUDIT_KEY`.

* edit / delete / insert / reorder → detected by `agentguard verify`.
* drop the tail → detected only with the head anchor (`<log>.head`, written by
  `agentguard run --audit`) stored out of the agent's reach.
* rewrite the whole chain consistently → detected only with the HMAC key.
* Arguments marked `sensitive` in a tool schema (e-mail bodies, account numbers) are
  replaced by an unsalted SHA-256 prefix. That proves *what* was sent to someone who has
  the plaintext, but low-entropy values (a 4-digit PIN) can be brute-forced from it.
* Appending to an existing log first verifies it; a tampered log is refused, not extended.

## Limits (candid)

* **Allowed channels stay open.** If a task may e-mail anyone at `example.com` and the
  context is clean, the guard cannot tell a good e-mail from a bad one. Data can also leak
  through *which* allow-listed URL is fetched (`fetch_url` is low-impact so it stays
  usable after browsing). Tighten with path prefixes, or mark such tools medium/high.
* **Medium-impact writes from tainted contexts are allowed by the shipped policy.** The
  held-out attack `attack-organizer-env-copy` "succeeds" in the sense that a file named
  `workspace/public/env.txt` is created — the credential read itself is denied, but the
  scripted model writes the token text it was never given. A real model could only write
  what it saw; the result is reported as a success anyway because that was the attack goal
  as declared before the run. Set `taint.medium: require_approval` if writes matter.
* **Approval fatigue.** With an approve-all human, half of the held-out attacks land. The
  approval request shows the taint trace to help a human, but agentguard cannot make
  people read it.
* **Labels are only as good as tool authors.** A tool that returns web content labelled
  `trusted` silently disables the main defence.
* **Coarse taint costs utility** (see the evaluation). Splitting work into separate
  sessions (one that reads untrusted content and writes a report, one that acts) is the
  intended pattern; the guard does not do it automatically.
* **In-process enforcement.** A real deployment should run tools in a separate process or
  sandbox and give the guard the only credential that can invoke them.
* **No real effects were tested.** All tools are fakes. Integrating real tools means
  writing honest specs and labels for them.
