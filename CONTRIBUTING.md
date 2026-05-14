# Contributing to APIHawk

Thanks for your interest in contributing to APIHawk! This document outlines how to get involved and help improve the tool.

## How to Contribute

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/apihawk.git
   cd apihawk
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-new-check
   ```
4. **Make your changes** and commit them with clear, descriptive messages.
5. **Push** your branch to your fork:
   ```bash
   git push origin feature/my-new-check
   ```
6. **Open a Pull Request** against the `main` branch of this repository. Describe what your change does, why it is useful, and how to test it.

## What We Need Help With

We're actively looking for contributions in the following areas:

- **New wordlists** — endpoint, parameter, and directory wordlists tuned for API discovery.
- **New vulnerability checks** — additional detection logic for common and emerging API vulnerabilities.
- **Bug fixes** — fixing crashes, false positives, false negatives, and other reported issues.
- **Better WAF evasion techniques** — payload encoding, header manipulation, request smuggling tricks, and other bypass strategies.
- **Subdomain scanner** — a module to enumerate subdomains as part of recon.
- **HTML report generator** — turning scan results into a clean, shareable HTML report.
- **Auth bypass testing** — checks for broken authentication, JWT issues, IDOR, privilege escalation, and similar weaknesses.

## Code Style

- **Python 3** only. We do not support Python 2.
- Use **`async`/`await`** where possible. APIHawk is built around asynchronous I/O for performance, so new network code should follow the same pattern.
- **Follow the existing class structure.** Keep new checks and modules consistent with the patterns already used in `Apihawk.py`.
- **Add comments** where they clarify non-obvious logic, tricky payloads, or the reasoning behind a particular check.
- Keep dependencies minimal and prefer the standard library when reasonable.

## Reporting Bugs

If you've found a bug, please open a GitHub issue and include:

- The **exact command** you ran.
- The **output** you got (paste relevant logs, error messages, or stack traces).
- The **expected behavior** — what you thought should happen instead.

The more detail you provide, the faster we can reproduce and fix the issue.

## Feature Requests

Have an idea for a new feature? Open a GitHub issue describing:

- The **feature idea** — what you'd like APIHawk to do.
- **Why it's useful for bug bounty hunters** — the real-world use case, the kinds of targets it helps with, and how it fits into a recon or testing workflow.

Concrete examples and references to writeups, CVEs, or HackerOne reports are very welcome and help us prioritize.

---

Thanks again for helping make APIHawk better!
