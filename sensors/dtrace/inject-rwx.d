/* name: inject-rwx */
/* technique: T1055 */
/* score: 5 */
/* kind: trace */
/* summary: NtProtectVirtualMemory granting executable writable memory. */
/* */
/* Base protection lives in the low byte: 0x40 is PAGE_EXECUTE_READWRITE; */
/* 0x140, 0x240 and 0x440 add PAGE_GUARD, PAGE_NOCACHE or PAGE_WRITECOMBINE */
/* and are at least as suspicious. arg0 is the target process handle, so the */
/* row separates a process flipping its own page (JIT, score 5) from one */
/* flipping another process's page (injection, score 8). */
/* Argmap: arg0 ProcessHandle, arg1 BaseAddress, arg2 RegionSize, arg3 NewProtect. */
syscall:::entry
/probefunc == "NtProtectVirtualMemory" && (arg3 & 0xff) == 0x40 && execname != "dtrace.exe"/
{
    is_self = arg0 == 0xffffffffffffffff;
    score = 8;
    if (is_self) {
        score = 5;
    }
    printf("plasma|{\"probe\":\"inject_rwx\",\"tid\":%d,\"comm\":\"%s\",\"protect\":\"0x%x\",\"self\":%d,\"score\":%d}\n",
           tid, execname, arg3, is_self, score);
}
