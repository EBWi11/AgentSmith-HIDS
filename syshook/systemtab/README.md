## Hook Function 

| action                   | hook function                          |
| ------------------------ | -------------------------------------- |
| execve                   | kernel.function("sys_execve").return   |
| connect                  | kernel.function("sys_connect").return  |
| accept/accept4           | kernel.function("sys_accept4").return  |
| open/openat/creat        | kernel.function("do_sys_open").return  |
| ptrace                   | kernel.function("sys_ptrace").return   |
| init_module/finit_module | kernel.function("load_module").return  |
| recvfrom                 | kernel.functiom("sock_recvmsg").return |

## Custom C Function

| get data  | from                                    |
| --------- | --------------------------------------- |
| node name | current->nsproxy->uts_ns->name.nodename |

## Test
```bash
stap -g hook.stp
```