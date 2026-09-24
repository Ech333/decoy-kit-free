# Decoy Kit Free

A real SSH key honeytoken trap, free forever. This is one full module out of
[Decoy Kit](https://northstartproductionstudio.com/decoy-kit) — Northstar's paid honeytoken
package (cloud metadata SSRF traps, Kubernetes, Postman, RAG corpora — 20 traps total) — given
away in full, not a crippled demo.

## What it does

Automated secret scanners (TruffleHog, GitLeaks) and human attackers validate a found SSH key by
its *structure*, not its content. A string that merely looks like a private key fails their regex
checks; a real, valid key with a suspicious comment does not.

`decoy-kit-free` generates a genuinely valid SSH keypair via the real `ssh-keygen` binary and sets
its comment field to a beacon URL. Plant the private key somewhere an attacker who compromises
your filesystem or a repo would find it — `~/.ssh/`, a CI secret store, a backup archive. The
moment anyone uses it (or even just extracts the public key to look), the comment field carries
the beacon URL back to a small receiver you run yourself.

## Self-hosted, same as the paid product

This is not a hosted service — there's no signup, no account, no data sent anywhere Northstar
operates. You run the receiver (`decoy-kit-free serve`), you plant the key, you own the whole
loop end to end. That's a deliberate choice, not a limitation of the free tier specifically —
every Northstar product works this way.

## Install

```bash
pip install decoy-kit-free
# or, to also run the receiver:
pip install 'decoy-kit-free[serve]'
```

Needs `ssh-keygen` on PATH (any normal dev machine has it) — there's no pure-Python fallback,
because producing a key indistinguishable from a genuine `ssh-keygen` output is the entire point.

## Use

```bash
# Generate the key. --host is wherever you'll run `serve` below.
decoy-kit-free generate ssh-key --host honeypot.yourdomain.com --out ./trap

# Run the receiver that catches the beacon.
decoy-kit-free serve --port 8000
```

Plant `./trap/id_rsa_prod` somewhere real. When it's used, the receiver logs the hit — wire your
own alerting via `serve.build_app(siem_webhook=...)` if you're running this as a library instead
of the CLI.

## What's real, what isn't

- A genuinely valid key, verified to round-trip through `ssh-keygen -y` with the beacon URL intact
  in the comment field — not a lookalike string.
- Deterministic, HMAC-seeded — the same seed always produces the same plant id, so a hit traces
  back to exactly which planted key was used.
- Does **not** verify the key was ever actually placed anywhere — that's a deployment decision
  this tool has no opinion on.
- A hit here is a trigger for a human to look, not an automatic verdict on intent.
- No independent third-party audit of this codebase — same honest status as every Northstar
  product at this stage.

## Want the other 19 traps?

Cloud metadata SSRF (AWS/GCP/Azure), a Kubernetes exec-credential honeytoken, a poisoned Postman
collection, RAG honeydocuments, an API tarpit for scanner-bait paths, time-rotating decoy routes,
decoy PyPI/npm registries, a decoy MCP server, directory honeyfiles, an LLM tarpit document,
router/IoT and serial-to-IP gateway traps, Redis and Firebase traps, a poisoned tool manifest, and
a calendar-invite trap — all in [Decoy Kit](https://northstartproductionstudio.com/decoy-kit), same design
principles, same self-hosted model.

## License

MIT. See [LICENSE](LICENSE).
