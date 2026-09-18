# sameday-sms-screener

Inbound SMS screening proxy for Patriot Pest Control's Sameday AI numbers.

```
Twilio number webhook -> screener -> classify -> Sameday AI (normal)
                                         \-> hold for human approval (bizarre)
```

## Endpoints

- `POST /sms/inbound` — Twilio webhook. Validates `X-Twilio-Signature`
  when `TWILIO_AUTH_TOKEN` is set. Classifies the body; in `hold` mode,
  bizarre classes return empty TwiML and never reach the upstream AI.
- `POST /sms/replay` — JSON `{"from","to","body"}` classification dry run.
- `GET /api/holds` — held messages, newest first.
- `GET /api/stats` — counts by type and class.
- `GET /healthz` — readiness.

## Classes

`prompt_injection`, `scam`, `spam`, `wrong_number`, `gibberish`,
`test`, `normal`, `blocklisted`.

## Env

| var | default | notes |
|---|---|---|
| `PORT` | 8080 | listen port |
| `SCREENER_MODE` | observe | `observe` logs+forwards; `hold` drops bizarre inbound |
| `UPSTREAM_SMS_URL` | empty | Sameday AI webhook to forward normal traffic to |
| `TWILIO_AUTH_TOKEN` | empty | enables Twilio signature validation |
| `BLOCKLIST` | empty | comma separated E.164 numbers to drop silently |
| `DATA_DIR` | /data | JSONL event log location |
| `PUBLIC_BASE_URL` | empty | canonical public URL for signature validation |

Fail closed: signature failures are rejected; classification misses stay
`normal` and are logged for review. Sending any held reply always requires
human approval. No credentials in the repo.
