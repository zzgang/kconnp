/*For 64bits asm*/

.section .text

.align 2

.globl connp_sys_poll

.type connp_sys_poll, @function

connp_sys_poll:
	jmp    *orig_sys_poll
	push   %r12
	mov    %rdx,%r12
	push   %rbp
	mov    %rdi,%rbp
	push   %rbx
	mov    %esi,%ebx
	sub    $0x8,%rsp
	cmp    $0x1,%esi
	je     connp_poll
   orig_sys_call:
	mov    %r12,%rdx
	mov    %ebx,%esi
	mov    %rbp,%rdi
	add    $0x8,%rsp
	pop    %rbx
	pop    %rbp
	pop    %r12
	jmp    *orig_sys_poll
   out_ret:
	add    $0x8,%rsp
	pop    %rbx
	pop    %rbp
	pop    %r12
	retq   
   connp_poll:
	mov    %rdi,%rsi
	mov    $0x8,%edx
	mov    %rsp,%rdi
	callq  _copy_from_user
	test   %rax,%rax
	jne    orig_sys_call
	testb  $0x1,0x4(%rsp)
	je     orig_sys_call
	mov    (%rsp),%edi
	xor    %edx,%edx
	xor    %esi,%esi
	mov    $0x69,%ecx
	callq  check_if_ignore_auth_procedure 
	test   %eax,%eax
	je     orig_sys_call
	orw    $0x1,0x6(%rsp)
	xor    %eax,%eax
	mov    (%rsp),%rdx
	mov    %rdx,0x0(%rbp)
	test   %eax,%eax
	jne    orig_sys_call
	mov    $0x1,%eax
	jmp    out_ret
