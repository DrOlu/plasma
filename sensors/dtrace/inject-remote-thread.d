/* name: inject-remote-thread */
/* technique: T1055 */
/* score: 6 */
/* kind: trace */
/* summary: NtCreateThreadEx targeting a process handle other than the caller. */
/* */
/* NtCurrentProcess() is the pseudo-handle -1 (0xffffffffffffffff). arg3 is */
/* the target ProcessHandle, so any other value means the caller is starting */
/* a thread in a different process. The row emits a normalised remote flag */
/* rather than the raw 64-bit handle: it reads the same on every DTrace */
/* build and keeps the printf portable. */
syscall:::entry
/probefunc == "NtCreateThreadEx" && arg3 != 0xffffffffffffffff && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_remote_thread\",\"tid\":%d,\"comm\":\"%s\",\"remote\":\"1\"}\n",
           tid, execname);
}
