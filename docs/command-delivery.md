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
the device connected. `exhausted` means automatic notification attempts ended;
the MDM command remains queued. `resolved` means a device result made further
pending notifications unnecessary. `-no-push` creates no notification intent.

Limits still requiring work: operator-action idempotency across repeated
clicks; a notification-only manual retry action after exhaustion; permanent
versus transient APNs error classification; lifecycle handling for queued work
when a device checks out; full upgrade/restore/real-device qualification.
The older KV methods outside queue operations still use upstream best-effort
transaction semantics. Do not describe all NanoMDM storage as crash-atomic.
