# Contributing

Thanks for helping with NetGoat.

## Workflow

1. Branch from the default branch. Use `feat/<short-slug>`,
   `fix/<short-slug>`, `docs/<short-slug>` or `chore/<short-slug>`.
2. Make the change and run the checks CI runs:

   ```bash
   go vet ./... && go test -race ./... && node --test scripts/dashboard.test.mjs && node --test software-errors/server.test.mjs
   ```

3. Commit with a Conventional Commit subject, for example
   `feat(api): add instance join endpoint`.
4. Open a pull request, fill in the template, and link the issue it closes.
5. A pull request is ready to merge when CI is green and a reviewer approves.

Never commit `.env`, credentials, keys, binaries or build output.

## Pull requests

- One logical change per pull request.
- Describe the effect and how you verified it.
- Do not force-push a branch under review; push follow-up commits instead.
- Update the README when configuration, endpoints or deployment change.

## Reviews

CI covers `Go · go vet · go test -race · gofmt · node --test` checks, a Docker build and secret scanning. CodeRabbit is
enabled for automated review where the repository has it installed. Neither
replaces a human reviewer, and no bot may approve or merge its own change.
