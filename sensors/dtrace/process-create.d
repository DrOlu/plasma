/* name: process-create */
/* technique: T1059 */
/* score: 5 */
/* kind: process */
/* summary: process/thread creation syscalls with the calling image. */
/* */
/* syscall entry probes are stable across Windows builds; the function filter */
/* keeps the row volume bounded even during a busy compile. */
syscall:::entry
/(probefunc == "NtCreateUserProcess" || probefunc == "NtCreateThreadEx") && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"%s\",\"pid\":%d,\"tid\":%d,\"comm\":\"%s\"}\n",
           probefunc, pid, tid, execname);
}
