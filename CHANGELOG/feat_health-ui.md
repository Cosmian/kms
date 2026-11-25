## Features

### Server Health page in the Web UI

- New **Server Health** page (`/ui/server-health`, menu entry after **HSM Status**). It shows the global status of
  `GET /health` (`UP`, `DEGRADED`, `DOWN`), each dependency (database, HSMs, KMIP socket server) with its latency and
  message, and the live nodes of `GET /cluster/status` with the leader. It refreshes when the **Refresh** button is
  pressed, or at the period chosen in **Auto-refresh** (5, 10 or 30 seconds, or 1 minute; manual by default, remembered
  by the browser, paused while the browser tab is hidden).
- The footer shows the health as a three-state marker (🟢 `UP`, 🟡 `DEGRADED`, 🔴 `DOWN` or unreachable) that links to
  the page and follows every refresh made on the page.
- The server serves the page on a browser reload (`/ui/server-health` is a registered UI route).

## Bug Fixes

### Web UI

- A `/health` answer that fails, is slow or is not the expected JSON (for example the 503 page of a reverse proxy) no
  longer replaces the server version in the footer: `/health` is now fetched on its own, with a 5 s timeout instead of
  2 s, which was below the server's own 2 s HSM probe limit.
- A `DEGRADED` node is no longer shown in red like a `DOWN` one.
- Reloading a page (F5, or following a bookmark) of the **FPE** menu (`/ui/fpe/*`) or of **HSM Status**
  (`/ui/hsm-status`) no longer returns a 404: both are now registered UI routes, like the other pages. This fix is not
  related to the Server Health page; it is included in this change.

## Testing

- Unit tests for the health client, the Server Health page (including server text that contains HTML) and the footer;
  Playwright tests for the page and the footer marker; `GET /cluster/status` is checked against the OpenAPI spec.
- `/ui/hsm-status` is added to the Playwright sitemap, which already loads each FPE page directly.
