# GitHub Free personal-account topology

These files are portable templates, not an active authority deployment.

1. Create `governance-authority` in the public target from a reviewed authority
   bundle, then apply exactly one authority-ref ruleset. Use the sole-user file
   only when no second eligible reviewer exists.
2. Create the separate private broker. Copy the three caller workflows there,
   replace the example target and every repeated authority SHA, and keep their
   `uses` and `authority_sha` values identical.
3. Store the target-only App key as `DISPOSITION_APP_PRIVATE_KEY` in the private
   broker's Actions secrets. Do not put it in the public target.
4. Register the clean single-job `governed-reviewer-jit` runner only to the
   private broker and pre-authenticate Codex through ChatGPT. Do not use an
   OpenAI API key or register the runner to the public target.
5. Run qualification and disposition manually. Render the target ruleset with
   the App integration ID, apply it disabled, verify the check source and exact
   refs, then activate it.

The protected reusable workflows and governance bundle are deployment-owned
content on the authority ref. These broker callers are non-authoritative
transport: changing a caller cannot change the protected target registry,
policy, reviewer identity, admission kernel, or publication payload.
