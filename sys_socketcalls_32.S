/*for 32bits asm*/
.section .text 

.globl connp_sys_poll

.type connp_sys_poll, @function

connp_sys_poll:
	push   %ebp
	mov    %esp,%ebp
	push   %edi
	push   %esi
	push   %ebx
	sub    $0x8,%esp
	mov    0xc(%ebp),%edi
	mov    0x8(%ebp),%esi
	cmp    $0x1,%edi
	jne    orig_sys_call
	lea    -0x14(%ebp),%eax
	mov    $0x8,%ecx
	mov    %esi,%edx
	call   _copy_from_user
	test   %eax,%eax
	mov    %eax,%ebx
    jne    orig_sys_call
	testb  $0x1,-0x10(%ebp)
	je     orig_sys_call
	mov    -0x14(%ebp),%eax
	xor    %edx,%edx
	xor    %ecx,%ecx
	push   $0x69
	call   check_if_ignore_auth_procedure
	pop    %edx
	test   %eax,%eax
	je     orig_sys_call
	orw    $0x1,-0xe(%ebp)
	mov    -0x14(%ebp),%eax
	mov    -0x10(%ebp),%edx
	mov    %eax,(%esi)
	mov    %edx,0x4(%esi)
	test   %ebx,%ebx
	mov    $0x1,%eax
	je     out_ret

    orig_sys_call:
	lea    -0xc(%ebp),%esp
	pop    %ebx
	pop    %esi
	pop    %edi
	pop    %ebp
/*change call to jmp to fix bug when the kconnp is unloaded*/
/*
	pushl  0x10(%ebp)
	push   %edi
	push   %esi
*/
    jmp    *orig_sys_poll
/*
	add    $0xc,%esp
*/
    out_ret:
	lea    -0xc(%ebp),%esp
	pop    %ebx
	pop    %esi
	pop    %edi
	pop    %ebp
	ret    
