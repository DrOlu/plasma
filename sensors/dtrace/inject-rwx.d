/* name: inject-rwx */
/* technique: T1055 */
/* score: 5 */
/* kind: trace */
/* summary: NtProtectVirtualMemory granting PAGE_EXECUTE_READWRITE (0x40). */
/* */
/* Executable writable memory is the permission state injected code needs */
/* before it can run. Legitimate JITs flip RW to RX (0x20); matching that */
/* would drown the signal, so only 0x40 is selected. */
/* Argmap for NtProtectVirtualMemory: arg1 BaseAddress, arg2 RegionSize, */
/* arg3 NewProtect. The syscall provider is used because its entry probes */
/* are stable across Windows builds; fbt symbol availability is not. */
syscall:::entry
/probefunc == "NtProtectVirtualMemory" && arg3 == 0x40 && execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"inject_rwx\",\"tid\":%d,\"comm\":\"%s\",\"protect\":\"0x%x\"}\n",
           tid, execname, arg3);
}
