/* name: inject-hijack */
/* technique: T1055 */
/* score: 5 */
/* kind: trace */
/* summary: NtSetContextThread on a thread other than the caller. */
/* */
/* Thread hijacking rewrites another thread's context so it resumes at the */
/* attacker's code. NtCurrentThread() is the pseudo-handle -2; comparing the */
/* low 32 bits avoids depending on how this DTrace build types a 64-bit */
/* literal. The handle does not reveal the owning process, so this is */
/* evidence (score 5) that pairs with a remote-thread or write row. */
syscall:::entry
/probefunc == "NtSetContextThread" && (arg0 & 0xffffffff) != 0xfffffffe && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_hijack\",\"tid\":%d,\"comm\":\"%s\",\"remote_thread\":\"1\"}\n",
           tid, execname);
}
