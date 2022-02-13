---
title: Decompetition CTF - babyc & babycpp
date: 2022-02-12
categories: [re]
tags: [decompetition2022]
toc: true
---

#### Overview:
- I spent some time this weekend playing Shellphish's Decompetition ctf. It's a ctf mainly for reverse engineers and the goal is to convert assembly into native code. There is a specific scoring algorithm as well as diff checkers so that you can compare what you wrote vs. what was in the original assembly. I enjoyed this format and wish there were more CTFs like it. 

- I mainly focused on C and some C++ problems. I enjoyed the "malware" challenge but didn't get 100% in time, the other challs were interesting too but I mainly focused on the ones shown below. I'll be posting some of my writeups/analysis as well in the next few posts

![Snippet of main()](/assets/img/decompetition22/decompetition_info.png)


#### Notes:
- A small challenge. We are given only x86-64 asm and we have to convert it back to native code. 
- [Link on __ctype_b_loc()](https://stackoverflow.com/questions/37702434/ctype-b-loc-what-is-its-purpose)

#### Problem 1 (baby-c):

```

; This is the disassembly you're trying to reproduce.
; It uses Intel syntax (mov dst, src).

main:                             ; Sets up the function stack frame and assigns 1 to a
  endbr64                           local var at rbp-0x15, we'll call this "check"    
  push    rbp 
  mov     rbp, rsp  
  push    rbx
  sub     rsp, 0x18
  mov     [rbp-0x15], 1
block1:                           ; Reads a character from stdin into a local var at 
  mov     rax, [stdin]              rbp-0x14 we'll call this "input_char" 
  mov     rdi, rax                  
  call    getc@plt.sec
  mov     [rbp-0x14], eax
  cmp     [rbp-0x14], -1
  je      block7
block2:
  call    __ctype_b_loc@plt.sec   ; __ctype_b_loc() is a function that returns a
  mov     rax, [rax]                ptr to a traits table filled with flags.
  mov     edx, [rbp-0x14]           I experimented with this for a bit and "and eax
  movsxd  rdx, edx                  , 0x2000" is essentially isspace()
  add     rdx, rdx
  add     rax, rdx
  movzx   eax, [rax]
  movzx   eax, ax
  and     eax, 0x2000
  test    eax, eax
  je      block4
block3:
  mov     rdx, [stdout]           ; block2 checks if "input_char" was a space & sets 
  mov     eax, [rbp-0x14]           "check" to 1 if it is
  mov     rsi, rdx                  
  mov     edi, eax
  call    putc@plt.sec
  mov     [rbp-0x15], 1
  jmp     block1                  ; jump back to the beginning (while(1))
block4:
  cmp     [rbp-0x15], 0           ; checks if "check" is set to 0, 
  je      block6                    
block5:
  mov     rbx, [stdout]           ; print uppercase version of "input_char" to stdout
  mov     eax, [rbp-0x14]
  mov     edi, eax
  call    toupper@plt.sec
  mov     rsi, rbx
  mov     edi, eax
  call    putc@plt.sec
  mov     [rbp-0x15], 0
  jmp     block1
block6:
  mov     rbx, [stdout]           ; print lowercase version of "input_char" to stdout
  mov     eax, [rbp-0x14]
  mov     edi, eax
  call    tolower@plt.sec
  mov     rsi, rbx
  mov     edi, eax
  call    putc@plt.sec
  jmp     block1
block7:
  mov     eax, 0                  ; clean-up and exit
  add     rsp, 0x18
  pop     rbx
  pop     rbp
  ret

```

#### Answer 1 (baby-c):
- This program takes a character from stdin and checks if its a space or if its EOF. It prints out the uppercase variant if check is satisfied, otherwise it prints the lowercase variant.

```

#include <ctype.h>
#include <stdio.h>

int main() {
    char check = 1;
    while (1) {
      int input_char = getc(stdin);
      if (input_char == EOF) {
          break;
      } 
      if (isspace(input_char)) {
          putc(input_char, stdout);
          check = 1;
      }
      else if (check) {
        putc(toupper(input_char), stdout);
        check = 0;
      } else {
        putc(tolower(input_char), stdout); 
      }
    } 
    
    return 0;
}

```

#### Problem 2 (baby-cpp):

```
main:                             ; sets up the function stack frame
  endbr64
  push    rbp
  mov     rbp, rsp
  sub     rsp, 0x20
  mov     [rbp-0x14], edi
  mov     [rbp-0x20], rsi
  cmp     [rbp-0x14], 2           ; if argc != 2, print out USAGE and exit
  je      block2
block1:                           
  lea     rsi, [mem1]; "USAGE: ./grade n"
  lea     rdi, [_ZSt4cerr]
  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt.sec
  mov     rdx, rax
  mov     rax, [_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_]
  mov     rsi, rax
  mov     rdi, rdx
  call    _ZNSolsEPFRSoS_E@plt.sec
  mov     edi, 2
  call    exit@plt.sec
block2:                           ; convert argv[1] to int via atoi(), store in rbp-0x4,
  mov     rax, [rbp-0x20]           we'll call this "grade", set rbp-0xc to 1, this will be
  add     rax, 8                    "sum", checks if grade is > 0
  mov     rax, [rax]
  mov     rdi, rax
  call    atoi@plt.sec
  mov     [rbp-4], eax
  mov     [rbp-0xc], 1
  cmp     [rbp-4], 0
  jg      block4
block3:                           ; exits the program if grade was < 1
  lea     rsi, [mem2]; "Don't be so negative."
  lea     rdi, [_ZSt4cerr]
  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt.sec
  mov     rdx, rax
  mov     rax, [_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_]
  mov     rsi, rax
  mov     rdi, rdx
  call    _ZNSolsEPFRSoS_E@plt.sec
  mov     edi, 2
  call    exit@plt.sec
block4:                           ; demangling this, its using sqrt(grade) and
  mov     eax, [rbp-4]              stores it in rbp-0x8, which will be "sqrt_grade"
  mov     edi, eax
  call    _ZSt4sqrtIiEN9__gnu_cxx11__enable_ifIXsrSt12__is_integerIT_E7__valueEdE6__typeES3_
  cvttsd2si eax, xmm0
  mov     [rbp-8], eax
block5:                          ; check if sqrt_grade > 1, begin looping
  cmp     [rbp-8], 1
  jle     block9
block6:                          ; block 6 & 7 performs the following calculations: 
  mov     eax, [rbp-4]             if (grade % sqrt_grade == 0) 
  cdq                                   sum += grade / sqrt_grade
  idiv    [rbp-8]                       sum += sqrt_grade
  mov     eax, edx
  test    eax, eax
  jne     block8
block7:
  mov     eax, [rbp-4]
  cdq
  idiv    [rbp-8]
  add     [rbp-0xc], eax
  mov     eax, [rbp-8]
  add     [rbp-0xc], eax
block8:                        ; decrement sqrt_grade, jmp back to begining of while-loop
  sub     [rbp-8], 1
  jmp     block5
block9:                        
  mov     eax, [rbp-0xc]         
  cmp     eax, [rbp-4]         ; checks if sqrt_grade and grade are equal
  jne     block11
block10:                       
  lea     rsi, [mem3]; "Perfect!"
  lea     rdi, [_ZSt4cout]
  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt.sec
  mov     rdx, rax
  mov     rax, [_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_]
  mov     rsi, rax
  mov     rdi, rdx
  call    _ZNSolsEPFRSoS_E@plt.sec
  mov     eax, 0
  jmp     block12
block11:                        
  lea     rsi, [mem4]; "Needs improvement."
  lea     rdi, [_ZSt4cout]
  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt.sec
  mov     rdx, rax
  mov     rax, [_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_]
  mov     rsi, rax
  mov     rdi, rdx
  call    _ZNSolsEPFRSoS_E@plt.sec
  mov     eax, 1
block12:
  leave
  ret
```

#### Answer 2 (baby-cpp):
- This program takes in a grade, n, and calculates the sum based on the grade & sqrt(grade)

```
#include <cmath>
#include <iostream>

using namespace std;

int main(int argc, char** argv) {
    if (argc != 2) {
        cerr << "USAGE: ./grade n" << endl;
        exit(2);
    } else {
        int grade = atoi(argv[1]);
        int sum = 1;
        if (grade < 1) {
            cerr << "Don't be so negative." << endl;  
            exit(2);
        } 
        int sqrt_grade = sqrt(grade);
        while(sqrt_grade > 1) {
            if (grade % sqrt_grade == 0) {
                  sum += grade / sqrt_grade;
                  sum += sqrt_grade;
            }
            sqrt_grade--;
        }
        if (sum == grade) {
            cout << "Perfect!" << endl;  
            return 0;
        } else {
            cout << "Needs improvement." << endl;
        }
    }
    return 1;
}
```
