/* name: inject-remote-thread */
/* technique: T1055 */
/* score: 6 */
/* kind: trace */
/* summary: NtCreateThreadEx targeting a process handle other than the caller. */
/* */
/* NtCurrentProcess() is the pseudo-handle -1. Comparing only the low 32 */
/* bits avoids depending on how this DTrace build types a 64-bit literal: */
/* the pseudo-handle's low word is all ones, while real handle values are */
/* small multiples of four and can never be 0xffffffff. arg3 is the target */
/* ProcessHandle. A normalised remote flag is emitted instead of the raw */
/* 64-bit handle so the row reads the same on every build. */
syscall:::entry
/probefunc == "NtCreateThreadEx" && (arg3 & 0xffffffff) != 0xffffffff && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_remote_thread\",\"tid\":%d,\"comm\":\"%s\"}\n",
           tid, execname);
}
