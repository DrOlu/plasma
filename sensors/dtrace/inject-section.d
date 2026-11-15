/* name: inject-section */
/* technique: T1055 */
/* score: 5 */
/* kind: trace */
/* summary: NtMapViewOfSection into a process other than the caller. */
/* */
/* Section injection maps an attacker-controlled section into the target. */
/* arg0 is the target ProcessHandle; -1 is the caller. Score 5 alone; */
/* injection_section_chain requires a remote thread from the same image. */
syscall:::entry
/probefunc == "NtMapViewOfSection" && (arg0 & 0xffffffff) != 0xffffffff && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_section\",\"tid\":%d,\"comm\":\"%s\",\"remote\":\"1\"}\n",
           tid, execname);
}
