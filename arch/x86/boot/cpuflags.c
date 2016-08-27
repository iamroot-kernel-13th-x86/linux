#include <linux/types.h>
#include "bitops.h"

#include <asm/processor-flags.h>
#include <asm/required-features.h>
#include <asm/msr-index.h>
#include "cpuflags.h"

struct cpu_features cpu;
u32 cpu_vendor[3];

static bool loaded_flags;

static int has_fpu(void)
{
	u16 fcw = -1, fsw = -1;		//2byte 모든 bit를 1로 채우기 위함
	unsigned long cr0;

	asm volatile("mov %%cr0,%0" : "=r" (cr0));
	if (cr0 & (X86_CR0_EM|X86_CR0_TS)) {         // EM CR0 2 flag 0 FPU 있음, 1 FPU 없음  //If set, no x87 floating point unit present, if clear, x87 FPU present
		cr0 &= ~(X86_CR0_EM|X86_CR0_TS);						// EM, TS 초기화 
		asm volatile("mov %0,%%cr0" : : "r" (cr0));
	}

	asm volatile("fninit ; fnstsw %0 ; fnstcw %1" //fninit(http://x86.renejeschke.de/html/file_module_x86_id_97.html) state word 0, control word 0x037F , fnstsw : 상태 저장, fnstcw: 제어 저장  
		     : "+m" (fsw), "+m" (fcw)); 						// 

	return fsw == 0 && (fcw & 0x103f) == 0x003f; //fsw == 0, fcw(= 0x037) & 0x103f == 0x003f 
}

/*
 * For building the 16-bit code we want to explicitly specify 32-bit
 * push/pop operations, rather than just saying 'pushf' or 'popf' and
 * letting the compiler choose. But this is also included from the
 * compressed/ directory where it may be 64-bit code, and thus needs
 * to be 'pushfq' or 'popfq' in that case.
 */
#ifdef __x86_64__
#define PUSHF "pushfq"
#define POPF "popfq"
#else
#define PUSHF "pushfl"
#define POPF "popfl"
#endif

int has_eflag(unsigned long mask)
{
	unsigned long f0, f1;

	asm volatile(PUSHF "	\n\t"  //PUSHF -> x86 = pushfl, x64 = pushfq (eflag 값 stack에 push)
		     PUSHF "	\n\t"
		     "pop %0	\n\t"
		     "mov %0,%1	\n\t"
		     "xor %2,%1	\n\t"
		     "push %1	\n\t"
		     POPF "	\n\t"				// POPF -> x86 = popfl, x64 = popfq ==> pop해서 기존 eflag에 AC bit(18)만  1로 설정후 eflag에 저장 (참고) Alignment check enabled if AM set, AC flag (in EFLAGS register) set, and privilege level is 3 
		     PUSHF "	\n\t"
		     "pop %1	\n\t"
		     POPF								// 기존 eflag 값을 원복
		     : "=&r" (f0), "=&r" (f1)
		     : "ri" (mask));

	return !!((f0^f1) & mask);  // 386인 경우  eflag가  최상위  비트가 18개, 486은 ac비트가 포함되서 19개, 386에 없는 19번째 eflag를 이용하여 386인지 x86인지 체크 (https://en.wikipedia.org/wiki/FLAGS_register)
}

/* Handle x86_32 PIC using ebx. */
#if defined(__i386__) && defined(__PIC__)
# define EBX_REG "=r"
#else
# define EBX_REG "=b"
#endif

static inline void cpuid(u32 id, u32 *a, u32 *b, u32 *c, u32 *d)
{
	asm volatile(".ifnc %%ebx,%3 ; movl  %%ebx,%3 ; .endif	\n\t"// .ifnc -> Assembles if the strings are not the same.
		     "cpuid					\n\t"
		     ".ifnc %%ebx,%3 ; xchgl %%ebx,%3 ; .endif	\n\t"
		    : "=a" (*a), "=c" (*c), "=d" (*d), EBX_REG (*b) // output
		    : "a" (id)																			// input - ax가 0인 경우는 제조업체 ID가져오
	);
}

void get_cpuflags(void)
{
	u32 max_intel_level, max_amd_level;
	u32 tfms;
	u32 ignored;

	if (loaded_flags)					// 아래의 연산을 최초 한번만 처리하고 전역변수에 저장후 다음부터는 아래 동작 안함 
		return;
	loaded_flags = true;

	if (has_fpu())
		set_bit(X86_FEATURE_FPU, cpu.flags); //cpu.flags의 0번째 bit를 1로 설정, X86_FEATURE_FPU = 0*32 + 0, cpu.flags = 0 ;https://www.kernel.org/doc/htmldocs/kernel-api/API-set-bit.html;

	if (has_eflag(X86_EFLAGS_ID)) { // eflags 21 bit; Able to use CPUID instruction (Pentium+); 
		cpuid(0x0, &max_intel_level, &cpu_vendor[0], &cpu_vendor[2],
		      &cpu_vendor[1]); // ax = 0x0 -> cpu 제조업체 ID 

		if (max_intel_level >= 0x00000001 &&
		    max_intel_level <= 0x0000ffff) { //https://en.wikipedia.org/wiki/CPUID#EAX.3D0:_Highest_Function_Parameter
			cpuid(0x1, &tfms, &ignored, &cpu.flags[4],
			      &cpu.flags[0]);          // eax = 1 -> 3:0 – Stepping 7:4 – Model 11:8 – Family 13:12 – Processor Type 19:16 – Extended Model 27:20 – Extended Family ; https://en.wikipedia.org/wiki/CPUID#EAX.3D1:_Processor_Info_and_Feature_Bits
			cpu.level = (tfms >> 8) & 15;  // 11:8 – Family 
			cpu.model = (tfms >> 4) & 15;  // 7:4 – Model
			if (cpu.level >= 6)
				cpu.model += ((tfms >> 16) & 0xf) << 4;  // 19:16 – Extended Model
		}

		cpuid(0x80000000, &max_amd_level, &ignored, &ignored,
		      &ignored);

		if (max_amd_level >= 0x80000001 &&
		    max_amd_level <= 0x8000ffff) {
			cpuid(0x80000001, &ignored, &ignored, &cpu.flags[6],
			      &cpu.flags[1]);
		}
	}
}
