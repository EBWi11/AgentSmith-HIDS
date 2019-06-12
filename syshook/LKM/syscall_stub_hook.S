.text
.global monitor_stub_execve_hook
.global monitor_stub_connect_hook
.global monitor_stub_accept_hook
.global monitor_stub_accept4_hook

monitor_stub_execve_hook:
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    call monitor_execve_hook
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rcx
    pop     %rdx
    pop     %rsi
    pop     %rdi
    movabs  $59, %rax
    jmp     *orig_sys_call_table(, %rax, 8)

monitor_stub_connect_hook:
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    call    hook_update_use_count
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rcx
    pop     %rdx
    pop     %rsi
    pop     %rdi
    movabs  $42, %rax
    jmp     monitor_connect_hook

monitor_stub_accept_hook:
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    call    hook_update_use_count
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rcx
    pop     %rdx
    pop     %rsi
    pop     %rdi
    movabs  $43, %rax
    jmp     monitor_accept_hook

monitor_stub_accept4_hook:
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    call    hook_update_use_count
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rcx
    pop     %rdx
    pop     %rsi
    pop     %rdi
    movabs  $288, %rax
    jmp     monitor_accept4_hook