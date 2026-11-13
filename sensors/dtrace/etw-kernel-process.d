/* name: etw-kernel-process */
/* technique: T1057 */
/* score: 4 */
/* kind: process */
/* summary: ETW Microsoft-Windows-Kernel-Process events (header fields only). */
/* */
/* The etw provider syntax: etw:<provider-guid-lowercase>:<level>_<keyword>:<event-id|generic_event>. */
/* Kernel-Process GUID: 22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716. */
/* Payload parsing is deliberately not attempted here: the header-derived */
/* tid/comm are enough to correlate with Sysmon and the tap, and the script */
/* stays valid across provider versions. */
etw:22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716:0xff_0xffffffffffffffff:generic_event
/execname != "dtrace.exe"/
{
    printf("plasma|{\"probe\":\"etw_kernel_process\",\"pid\":%d,\"tid\":%d,\"comm\":\"%s\"}\n",
           pid, tid, execname);
}
