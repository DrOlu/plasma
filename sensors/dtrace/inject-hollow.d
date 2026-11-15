/* name: inject-hollow */
/* technique: T1055 */
/* score: 6 */
/* kind: trace */
/* summary: NtUnmapViewOfSection against a process other than the caller. */
/* */
/* Process hollowing unmaps the target image before writing a replacement. */
/* arg0 is the target ProcessHandle; the pseudo-handle -1 is the caller. */
/* A standalone unmap is suspicious but not conclusive, so it scores 6 and */
/* completes injection_hollow_chain with a write and a remote thread. */
syscall:::entry
/probefunc == "NtUnmapViewOfSection" && (arg0 & 0xffffffff) != 0xffffffff && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_hollow\",\"tid\":%d,\"comm\":\"%s\",\"remote\":\"1\"}\n",
           tid, execname);
}
