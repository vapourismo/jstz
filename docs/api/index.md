# 🧰 API Reference

This is a reference for all runtime APIs available in `jstz`. Since `jstz` is a JavaScript server runtime
running on Tezos's smart optimistic rollups, some APIs are not available (e.g. `DOM`).

::: danger
⚠️ `jstz`'s APIs are currently very unstable and not compliant with specifications. ⚠️
:::

## Web Platform APIs

- [`console`](./console.md)
- `atob`
- `btoa`
- Fetch API:
  - [`Headers`](./headers.md)
  - [`Request`](./request.md)
  - [`Response`](./response.md)
- URL API:
  - [`URL`](./url.md)
  - [`URLSearchParams`](./url_search_params.md)

## `jstz`-specific APIs

- [`Kv`](./kv.md)
- [`Contract`](./contract.md)
- [`Ledger`](./ledger.md)
