/* name: inject-write */
/* technique: T1055 */
/* score: 5 */
/* kind: trace */
/* summary: NtWriteVirtualMemory into a process other than the caller. */
/* */
/* Writing into an already-executable region leaves neither an RWX flip nor */
/* a remote thread, so the existing chains cannot start. arg0 is the target */
/* ProcessHandle; -1 is the caller. Score 5 alone; injection_write_chain */
/* requires a remote thread from the same image. */
syscall:::entry
/probefunc == "NtWriteVirtualMemory" && (arg0 & 0xffffffff) != 0xffffffff && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_write\",\"tid\":%d,\"comm\":\"%s\",\"remote\":\"1\"}\n",
           tid, execname);
}
