/* name: inject-apc */
/* technique: T1055 */
/* score: 5 */
/* kind: trace */
/* summary: APC queued to a thread via the NtQueueApcThread family. */
/* */
/* APC injection is a common execution primitive in commodity frameworks. */
/* The thread handle does not reveal its owning process at this boundary, */
/* so the row is evidence (score 5), not a cross-process verdict. It pairs */
/* with inject-rwx and inject-remote-thread when an operator is reading a */
/* case, and is not chained on its own. Modern builds route QueueUserAPC */
/* through NtQueueApcThreadEx2, so the whole family is matched. */
syscall:::entry
/(probefunc == "NtQueueApcThread" || probefunc == "NtQueueApcThreadEx" || probefunc == "NtQueueApcThreadEx2") && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_apc\",\"tid\":%d,\"comm\":\"%s\",\"func\":\"%s\"}\n",
           tid, execname, probefunc);
}
