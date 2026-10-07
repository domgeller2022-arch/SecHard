# Agent runtime restrictions: operator requirements

These are requirements on the **operator** who runs an AI coding agent against a repository using
this hardening kit. They are not instructions to the agent, because instructions are not a boundary:
an agent that has been told not to read a credential file can still read it if the filesystem permits
it. Prompt text cannot satisfy AGT-01. Only the tool's own restrictions can.

This repository cannot configure your agent for you. It states what must be true and how to check it.

## 1. Filesystem

- The agent's working root should be the repository, and it should not be able to read outside it.
- Credential stores must be outside that root: `~/.aws`, `~/.ssh`, `~/.config/gcloud`, `~/.netrc`,
  `~/.npmrc` (if it holds a token), `~/.docker/config.json`, and any password manager directory.
  Note that an agent with a shell can usually read these. That is the point of the requirement.
- Deployment state, production dumps, and unrelated checkouts should not be reachable either.

**Check:** ask the agent to read a path outside the root and confirm the tool refuses. A prompt that
says "do not read outside the repository" proves nothing.

## 2. Credentials

- The agent must not be able to reach deployment, publishing, or production credentials. Give it
  none. If it needs a repository credential, use a short-lived one scoped to the single repository,
  with the minimum permissions required, and revoke it afterwards.
- Do not put credentials in the environment the agent's shell inherits. An agent that can read
  `process.env` can read them.
- Repository secrets belong in the CI secret store, not in the agent's environment.

**Check:** have the agent dump its environment and confirm no credential is present. If one is,
remove it rather than adding an instruction not to use it.

## 3. Network

- Restrict egress where the tool supports it. An agent that can reach any host can exfiltrate
  anything it can read.
- Where egress cannot be restricted, treat every credential it can read as already disclosed, and
  scope accordingly.
- An allowlist should name the package registry and the hosts the work actually needs, not the
  whole internet.

**Check:** attempt a request to a host outside the allowlist and confirm it fails.

## 4. Runtime permissions

- File writes should be limited to the repository. The agent should not be able to install system
  packages, change system configuration, or modify files outside its root.
- Administrative elevation must not be available.
- Where the tool offers an approval mode, the boundary is the restriction it enforces, not the
  approval prompt. A prompt is a speed bump; a permission rule is a wall.

**Check:** attempt an operation outside the root and confirm the tool denies it.

## What this means for the kit

- `AGT-01` is recorded as **manual evidence** for exactly this reason. This repository cannot inspect
  your agent's configuration, so the operator records what was configured and how it was checked.
- The generated instruction files (`agent-rules/generated/`) state the rules the agent must follow.
  They are necessary and not sufficient. If a rule matters, enforce it outside the model.
