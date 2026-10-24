# Login and Logout

## Specification

KMIP 2.1 defines two operations to authenticate requests with a ticket instead of repeating
credentials:

- **Login** (§6.1.30) asks the server to allow future requests to be authenticated using a ticket
  that it returns. The request payload has three optional items: Lease Time, Request Count and
  Usage Limits. The response payload holds the Ticket.
- **Logout** (§6.1.31) asks the server to invalidate a ticket. The request payload holds the
  Ticket; the response payload is empty. The error `Invalid Ticket` is defined for it.

A ticket is presented in the `Authentication` of the Request Message header, as a Credential of
type `Ticket` (Ticket Type `Login` and a Ticket Value).

## Implementation

The Eviden KMS issues a ticket that **adds a check** to a request; it never replaces the
authentication of the transport (TLS client certificate, JWT, API token). A request carrying a
ticket must therefore still be authenticated, and the ticket is only accepted for the user the
transport authenticated.

| Item                  | Behaviour                                                                                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ticket                | 32 random bytes from the server DRBG, Ticket Type `Login`, bound to the authenticated user                                                                             |
| Lease Time            | An Interval in seconds. 0 or absent selects 1 hour; values above 24 hours are lowered to 24 hours. The Date Time form is not supported                                  |
| Request Count         | Number of Request Messages the ticket can authenticate. Absent: unlimited within the lease. Zero or negative: `Invalid Field`                                          |
| Usage Limits          | Not supported: `Feature Not Supported`                                                                                                                                 |
| Limits                | At most 10,000 live tickets on the server and 64 per user: `Server Limit Exceeded` beyond. Expired tickets do not count                                                |
| Consumption           | Each Request Message that carries the ticket consumes one request, even if a later check rejects the message. An exhausted ticket is refused with `Usage Limit Exceeded` until its lease ends |
| Refusal               | A ticket that is unknown, expired, issued to another user, or of another type fails the whole message with `Invalid Ticket`; the message does not tell these cases apart |
| Logout                | Invalidates a ticket of the same user, whatever requests it has left. Another user's or an unknown ticket: `Invalid Ticket`                                              |
| Role `Operator`       | Login and Logout are allowed to Operators (they do not output or modify key material)                                                                                  |
| Storage               | Tickets are held in memory only: they are lost on restart and not shared between server instances                                                                      |

Result Reasons: Table 255 of the specification (Login errors) does not list `Server Limit Exceeded`,
`Usage Limit Exceeded` or `Invalid Ticket`; the server uses them for a full ticket store, an
exhausted ticket and an unusable ticket, because no listed reason describes these cases.

Not supported: Delegated Login (rights-restricted tickets) and Hashed Password credentials.

!!! warning "A ticket is a bearer secret"
    Anyone who holds a ticket *and* is authenticated by the transport as the same user can use
    it. Do not log it. When the server runs without authentication, every client is the same
    default user, so a ticket does not separate clients.

## Example - Login with a Request Count of 1, then use the ticket

Login:

=== "Request"

    ```json
    {
      "tag": "Login",
      "value": [
        {
          "tag": "RequestCount",
          "type": "Integer",
          "value": 1
        }
      ]
    }
    ```

=== "Response"

    The `BatchItem` of the Response Message:

    ```json
    {
      "tag": "BatchItem",
      "value": [
        { "tag": "Operation", "type": "Enumeration", "value": "Login" },
        { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" },
        {
          "tag": "ResponsePayload",
          "value": [
            {
              "tag": "Ticket",
              "value": [
                { "tag": "TicketType", "type": "Enumeration", "value": "Login" },
                {
                  "tag": "TicketValue",
                  "type": "ByteString",
                  "value": "CD91E237AA2066DCBF2BFB7E04B50EAD6A3F385DC29B6A166A34C1ED0682FDBB"
                }
              ]
            }
          ]
        }
      ]
    }
    ```

A Request Message that carries the ticket in its header:

```json
{
  "tag": "RequestMessage",
  "value": [
    {
      "tag": "RequestHeader",
      "value": [
        {
          "tag": "ProtocolVersion",
          "value": [
            { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
            { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
          ]
        },
        {
          "tag": "Authentication",
          "value": [
            {
              "tag": "Credential",
              "value": [
                { "tag": "CredentialType", "type": "Enumeration", "value": "Ticket" },
                {
                  "tag": "CredentialValue",
                  "value": [
                    {
                      "tag": "Ticket",
                      "value": [
                        { "tag": "TicketType", "type": "Enumeration", "value": "Login" },
                        {
                          "tag": "TicketValue",
                          "type": "ByteString",
                          "value": "CD91E237AA2066DCBF2BFB7E04B50EAD6A3F385DC29B6A166A34C1ED0682FDBB"
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        },
        { "tag": "BatchCount", "type": "Integer", "value": 1 }
      ]
    },
    {
      "tag": "BatchItem",
      "value": [
        { "tag": "Operation", "type": "Enumeration", "value": "Query" },
        {
          "tag": "RequestPayload",
          "value": [
            { "tag": "QueryFunction", "type": "Enumeration", "value": "QueryOperations" }
          ]
        }
      ]
    }
  ]
}
```

The first message is processed. A second message with the same ticket fails:

```json
{
  "tag": "BatchItem",
  "value": [
    { "tag": "Operation", "type": "Enumeration", "value": "Query" },
    { "tag": "ResultStatus", "type": "Enumeration", "value": "OperationFailed" },
    { "tag": "ResultReason", "type": "Enumeration", "value": "Usage_Limit_Exceeded" },
    {
      "tag": "ResultMessage",
      "type": "TextString",
      "value": "the ticket's Request Count is exhausted"
    }
  ]
}
```

## Example - Logout

=== "Request"

    ```json
    {
      "tag": "Logout",
      "value": [
        {
          "tag": "Ticket",
          "value": [
            { "tag": "TicketType", "type": "Enumeration", "value": "Login" },
            {
              "tag": "TicketValue",
              "type": "ByteString",
              "value": "CD91E237AA2066DCBF2BFB7E04B50EAD6A3F385DC29B6A166A34C1ED0682FDBB"
            }
          ]
        }
      ]
    }
    ```

A ticket that another user issued is refused with the same error as an unknown one:

```json
{
  "tag": "BatchItem",
  "value": [
    { "tag": "Operation", "type": "Enumeration", "value": "Logout" },
    { "tag": "ResultStatus", "type": "Enumeration", "value": "OperationFailed" },
    { "tag": "ResultReason", "type": "Enumeration", "value": "Invalid_Ticket" },
    {
      "tag": "ResultMessage",
      "type": "TextString",
      "value": "unknown, expired or exhausted ticket"
    }
  ]
}
```

## Security review

Scope: `crate/server/src/core/operations/login.rs` (store, Login, Logout, redemption), its call
sites in `message.rs` and `dispatch.rs` (Operator role gate), the logging and audit paths that
see a request or a response, and the KMIP types `Ticket` and `CredentialValue`. Evidence: the
unit tests of `login.rs` and the vectors `negative/security/ticket_*` (see Verification).

| # | Threat | Result |
| - | ------ | ------ |
| 1 | Guessing a ticket | Not feasible: 256 random bits from the OpenSSL private DRBG (`KmsRng`, 256-bit strength required). A value whose length is not 32 bytes is refused before the lookup, so an oversized Ticket Value is never hashed |
| 2 | Using or revoking another user's ticket | Refused. The ticket is bound to the user the transport authenticated; an unknown, expired, foreign or wrong-type ticket gives the same `Invalid Ticket` message, for Query-style use and for Logout. Only the owner can see `Usage Limit Exceeded` |
| 3 | Timing side channel | None usable: lookup in a `HashMap` keyed by the (random) ticket with a per-process random hasher; the only comparison on a secret is on the user name, after a hit |
| 4 | Privilege escalation through a ticket | None: a ticket only adds a check and grants no right. The HTTP middlewares authenticate every request first, and authorisation (ownership, grants, Operator role) is unchanged. Login and Logout are allowed to Operators because they output and modify no key material; every other unmapped operation stays denied for them |
| 5 | Double spend of a limited ticket | Not possible: the lookup, the Request Count test and the decrement are one critical section of one `Mutex`, and no `.await` happens while it is held. A poisoned lock is recovered because no update spans a panic point |
| 6 | Memory and CPU exhaustion | Bounded: 10,000 live tickets, 64 per user, lease at most 24 h, Request Count at most `u32`. See findings F1 and F2 |
| 7 | Leak through logs and audit | None found: Login/Logout log the user name only, the `kmip` debug target logs the operation tag and the user, `LoginResponse` displays only the length of the ticket, and the audit extraction records the operation name, object UID and algorithm. `Ticket` has a manual `Debug` that prints only the length of the value, so a `{:?}` of a request header or a Login response cannot print it |
| 8 | Replay | A ticket is a bearer value that is not bound to the TLS session or the source address. This is acceptable because holding the ticket gives nothing that the transport credentials do not give already, but it must not be treated as proof of a fresh authentication |
| 9 | Deployments without authentication | All clients are the default user, so they share tickets: a ticket separates users only when the server authenticates them (mTLS, JWT, API token, socket-server certificate) |
| 10 | Restart and several instances | Fail-closed: tickets are in memory and do not survive a restart or move between instances; the client gets `Invalid Ticket` and logs in again |
| 11 | Unsupported credential forms | Hashed Password credentials are rejected, Delegated Login is not implemented, Usage Limits give `Feature Not Supported`: none can be used to obtain a ticket with other rights |

### Findings

- **F1 (fixed): redeeming a ticket scanned the whole store.** Every `redeem` or `revoke` first
  purged the expired tickets of the whole store (O(n), n up to 10,000) under the global ticket
  lock. A Request Message may carry any number of Ticket credentials, so one authenticated
  request of a few hundred kilobytes forced millions of entry visits under the lock and stalled
  every other ticket user. `redeem` and `revoke` now look the ticket up directly and test its
  lease; expired tickets are purged when the next ticket is issued.
- **F2 (residual, low): Login is O(n) under the lock.** Issuing a ticket purges the expired ones
  and counts the user's tickets. A batch of up to 10,000 Login items from one user repeats that
  scan; it only delays other ticket users, not the other operations. Filling the global quota
  needs 157 distinct authenticated identities (64 per user, 10,000 in total); expired tickets
  free the quota at the next Login. Mitigation if it matters in a deployment: rate-limit Login
  at the reverse proxy.
- **F3 (informational): a request consumes its ticket before the rest of the message is
  validated.** A message rejected later (critical extension, authorisation) has still spent one
  request, and a header that repeats the ticket spends one request per copy. Only the ticket's owner can cause it, so it is a self-inflicted loss, not an attack.
- **F4 (informational): Login inside an `Undo` batch is not rolled back** (an undone batch leaves
  the ticket valid). The ticket is bound to its owner and grants nothing, so there is no
  security effect. This comes from reading `batch_undo.rs`; it was not exercised.

### Verification

- Unit tests in `login.rs`: Request Count consumed then exhausted, foreign-user refusal, Logout of
  an own ticket only, lease cap and expiry (including Logout after expiry), global and per-user
  bounds.
- Vectors `negative/security/ticket_bound_to_user`, `ticket_forged` and
  `ticket_request_count_exhausted` run through the real server and mTLS identities.
- Not covered by an automated test: the ticket path of the socket server, and F2 under load.
