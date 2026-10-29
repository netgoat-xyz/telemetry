## What does this change do?

<!-- One or two sentences. Link the issue it closes. -->

Closes #

## How was it verified?

<!-- Commands you ran, plus anything a reviewer should click through. -->

```bash
go vet ./... && go test -race ./... && node --test scripts/dashboard.test.mjs && node --test software-errors/server.test.mjs
```

## Checklist

- [ ] No `.env`, credentials, keys or build output committed
- [ ] Behaviour preserved for existing callers unless the change is intentional
- [ ] Docs updated if configuration, endpoints or deployment changed
