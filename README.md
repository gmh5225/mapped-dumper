# Manual Mapped Module Dumper
A program written in C++ for remotely dumping manual mapped modules.

## Brief Explanation
When you want to inject a module into a process and you don't want it to be found by typical routines (load notifications, tls callbacks, etc) you use manual mapping to get your module into the process. This is a tool I wrote to dump said modules for an [anti-cheat I was developing](https://github.com/dllcrt0/Dynsec) to gain knowledge on the internals of Windows. It iterates through memory pages and does some simple checking on permissions and flags to determine if it's a mapped module. This isn't perfect, if the PE header memory is released then it'll need a few lines changed, none-the-less it was useful for dumping many P2C's which were utilizing BlackBone to inject for testing my detection routines.
