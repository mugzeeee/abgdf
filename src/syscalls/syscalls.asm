;; ============================================================================
;; Direct Syscall Stub (x64 MASM)
;;
;; Uses a global variable for the SSN so that function arguments stay in
;; their correct registers (RCX, RDX, R8, R9, stack).
;;
;; NT syscall convention (x64):
;;   EAX = System Service Number (SSN)
;;   R10 = First argument (copied from RCX)
;;   RDX = Second argument
;;   R8  = Third argument
;;   R9  = Fourth argument
;;   Stack = 5th+ arguments
;;
;; By using a global SSN, we call DoSyscall(arg1, arg2, arg3, arg4, ...)
;; with args in their natural positions, then just set EAX from the global.
;; ============================================================================

.data
    ; The C++ code sets this before calling DoSyscall
    PUBLIC currentSSN
    currentSSN DD 0

.code

; DoSyscall - arguments are already in the correct NT registers
; RCX = first NT arg, RDX = second, R8 = third, R9 = fourth, stack = 5th+
DoSyscall PROC
    mov r10, rcx                ; NT convention: r10 = first argument
    mov eax, dword ptr [currentSSN]  ; EAX = SSN from global
    syscall
    ret
DoSyscall ENDP

END
