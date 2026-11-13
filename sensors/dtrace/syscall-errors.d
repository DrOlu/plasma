// name: syscall-errors
// technique: T1106
// score: 6
// kind: trace
// summary: NT syscalls returning a non-success status (root-cause evidence).
//
// Bounded by the runner: `plasma trace run syscall-errors --for 10s`.
// The only output contract is lines beginning with `plasma|` and a JSON body.
syscall:::return
/arg0 != 0/
{
    printf("plasma|{\"probe\":\"syscall_error\",\"pid\":%d,\"comm\":\"%s\",\"func\":\"%s\",\"status\":\"0x%x\"}\n",
           pid, execname, probefunc, arg0);
}
