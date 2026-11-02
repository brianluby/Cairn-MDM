# Command delivery and notification recovery

Queue acceptance, APNs notification and the device's result are separate states.
The completion branch uses SQLite transactions for queue changes and command
history in both the CLI and console. A failed history write rolls back queueing.
Device reports update queue state and history together. A late NotNow cannot
overwrite an acknowledged history entry. A profile assignment recorded after
an early acknowledgement uses that result instead of reverting to sent.

An operation using APNs also commits a notification row with its command. The
server retries pending notifications after restart. Workers claim one row with
a 30-second lease and make a push attempt with a 15-second context deadline.
Failures wait 30, 60, 120, 240 and 300 seconds, up to six attempts total. A lost
worker lease can be reclaimed; an old worker cannot overwrite a newer result.
Retries send wakeups only. They never enqueue another MDM command, including
for destructive command types.

Device history shows notification state and attempt count beside the device's
command status. `accepted` means the APNs request succeeded; it does not mean
the device connected. `exhausted` means automatic notification attempts ended (retry limit or a known non-retryable APNs rejection);
the MDM command remains queued. `resolved` means a device result made further
pending notifications unnecessary. `-no-push` creates no notification intent.

Console actions carry a session-scoped operation key. Replaying the same form
uses the same command UUID; different content, targets or notification intent
under that key are rejected. CLI callers can deliberately reuse `-operation-key`
when retrying an uncertain result. A new page/action key is a new operation.
The key is not an authorization credential and does not bypass role or CSRF checks.

An operator can retry an exhausted notification from device history. This starts
another bounded notification cycle for the existing pending command. Replaying
that form does not reset its attempt counter. Completed or disabled enrollments
cannot start a new cycle. The operation records its actor in the audit log.

Disabling an enrollment clears its queue, cancels pending history and resolves
pending/exhausted notifications in one transaction. Device-channel disable also
covers its user channels. New commands to disabled enrollments are rejected.
The adapter enumerates user-channel mapping suffixes itself to avoid NanoMDM
v0.9.0's upstream prefix/suffix bug in its disable helper.

Known APNs token, topic, certificate and payload rejections end the automatic
cycle immediately. Rate limiting and service failures use bounded backoff;
unknown transport/provider failures also use that bound. Stored errors use
allowlisted reasons, not raw provider strings. Correct a permanent failure
before using the manual retry action. Cairn does not delete an enrollment merely
because APNs rejects a token. See Apple's [notification response guidance](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns).

Limits still requiring work: full upgrade/restore/real-device qualification. The older KV methods outside
queue operations still use upstream best-effort transaction semantics. Do not
describe all NanoMDM storage as crash-atomic.
