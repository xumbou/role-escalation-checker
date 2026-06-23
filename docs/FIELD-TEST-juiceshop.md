# Field test — bacscan vs OWASP Juice Shop

Second real-target validation, on the most popular vulnerable web app, run **without Docker**:
OWASP Juice Shop v20 launched from its **pre-built release** (Node 22 binary +
`_node22_linux_x64.tgz`, **no `npm install`**) inside WSL.

## Setup
- Two accounts registered + logged in via the REST API (`POST /api/Users`, `POST /rest/user/login`).
- **Ground truth**: with user A's token, `GET /rest/basket/{otherId}` returns **HTTP 200 with data**
  → the classic Juice Shop **basket BOLA** ("view another user's basket") is present.

## Result
bacscan (probes `idor`, `idor_dynamic`), HAR = user A's legitimate `GET /rest/basket/{ownId}`:

| Finding | Verdict |
|---|---|
| `idor-sequential` on `/rest/basket/4`, `/5`, `/7`, `/8` (neighbours of own basket `6`) | **confirmed (HIGH)** |

→ bacscan found the real basket BOLA by **sequential id enumeration** (the basket id is a small
integer): four other users' baskets reachable with a single user's token. **0 false positive.**

## Takeaways
- **A second real lab confirms the tool** beyond VAmPI — a genuine BOLA on a famous target, found
  automatically, no FP.
- **A no-Docker recipe that works**: the pre-built release + a matching Node binary sidesteps both
  the Docker requirement and the heavy `npm install` / OOM on a RAM-capped WSL.
- The config-swap `idor` probe didn't fire here (both test accounts happened to share a basket id);
  `idor_dynamic`'s sequential enumeration is what nailed it — a good reason to run both.
