## Hook Function 

| action                   | hook function                          |
| ------------------------ | -------------------------------------- |
| execve                   | kernel.function("sys_execve").return   |
| connect                  | kernel.function("sys_connect").return  |
| accept/accept4           | kernel.function("sys_accept4").return  |
| open/openat/creat        | kernel.{function("vfs_create"), function("vfs_mknod")}  |
| ptrace                   | kernel.function("sys_ptrace").return   |
| init_module/finit_module | kernel.function("load_module").return  |
| recvfrom                 | kernel.functiom("sys_recvfrom").return |

## Custom C Function

| get data  | from                                    |
| --------- | --------------------------------------- |
| node name | current->nsproxy->uts_ns->name.nodename |

## Test

```bash
yum install systemtap systemtap-runtime
stap -g hook.stp
```