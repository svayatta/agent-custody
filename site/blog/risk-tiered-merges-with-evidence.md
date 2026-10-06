---
title: Risk-tiered merges, with evidence
description: Agents open more pull requests than humans can read. SOC 2 and ISO 27001 do not ask for a human on every change; they ask for evidence. Here is a merge gate that produces it.
---

# Risk-tiered merges, with evidence

*Partha, 6 October 2026*

Teams whose agents write code hit a wall in the same place. The agents open pull requests faster than the humans can review them, and the compliance programme says every change needs review. So either the humans become the bottleneck, or the review becomes a rubber stamp, and an auditor can tell which.

The wall is partly imagined. ISO 27001 A.8.32 and SOC 2 CC8.1 do not say a human must read every change. They say each change must be authorized, tested, and approved under a defined process, with evidence that it was. Risk-tiered review is such a process: small, low-risk changes merge automatically; larger ones need a human; changes to sensitive paths need two. Plenty of teams already run it.

What they are missing is the evidence. The tier decision is made by the pipeline, the approvals are recorded by the pipeline, and the "immutable audit trail" at the bottom of the diagram is written by the pipeline. An auditor reading it is reading the pipeline's account of itself.

## The gate

Put a gateway between the release agent and the git host. The agent asks to merge; the gateway fetches the facts itself: the diff size, whether sensitive paths are touched, the deterministic gate results, and which humans approved. A policy decides the tier:

```cedar
// Low risk: small, nothing sensitive, every gate green, the reviewer agent approves. Merges alone.
permit(principal, action == Action::"pr.merge", resource)
when { context.facts.checks.all_green && context.facts.reviews.reviewer_agent == "approve"
    && context.facts.pr.additions <= 200 && !context.facts.pr.touches_sensitive };

// Medium risk: larger, nothing sensitive, and at least one human CODEOWNER approved.
permit(principal, action == Action::"pr.merge", resource)
when { context.facts.checks.all_green && context.facts.reviews.reviewer_agent == "approve"
    && !context.facts.pr.touches_sensitive && context.facts.reviews.human_count >= 1 };

// High risk, sensitive paths: no permit, so no agent merges it. Two humans do, in the host.
```

A merge the policy allows is committed to the log before it is forwarded, so the evidence exists before the side effect. A merge it refuses never reaches the host, and the refusal is a receipt too. Every receipt carries the facts as the gateway saw them, the policy's digest, and the signed grant from the person who authorized the agent.

## The evidence

At the end, the receipts alone produce the index an auditor asks for. Per change: the tier, the decision, the approvers, the policy version, the human authority, and the log positions showing authorization preceded execution, each line verifiable with public keys.

```
pr.merge        {"number":"101"}  low     executed  authority release-manager  approvers []        authorized at leaf 0, executed at leaf 1
pr.merge        {"number":"102"}  medium  denied    authority release-manager  approvers []        nothing forwarded
pr.merge        {"number":"102"}  medium  executed  authority release-manager  approvers ["alice"] authorized at leaf 3, executed at leaf 4
pr.merge        {"number":"103"}  high    denied    authority release-manager  approvers ["alice"] nothing forwarded
deploy.promote  {"env":"staging"}         executed  authority release-manager                      authorized at leaf 6, executed at leaf 7
deploy.promote  {"env":"prod"}            denied    authority release-manager                      nothing forwarded
```

That is what the two controls ask for, produced by a key the agents do not hold, checkable without us.

The whole gate runs against a stand-in git host with no API key in [example 24](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts). Against real GitHub, the three fact lookups are the pull request, check-runs, and reviews endpoints, and the merge is the merge endpoint, through the same REST upstream configuration. The [compliance mapping](/receipts/compliance#agent-made-changes-the-merge-gate) says which controls it answers.
