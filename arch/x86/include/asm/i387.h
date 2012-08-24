/*
 * Copyright (C) 1994 Linus Torvalds
 *
 * Pentium III FXSR, SSE support
 * General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 * x86-64 work by Andi Kleen 2002
 */

#ifndef _ASM_X86_I387_H
#define _ASM_X86_I387_H

#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/regset.h>
#include <linux/hardirq.h>
#include <linux/slab.h>
#include <asm/asm.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/sigcontext.h>
#include <asm/user.h>
#include <asm/uaccess.h>
#include <asm/xsave.h>

#ifdef CONFIG_X86_64
# include <asm/sigcontext32.h>
# include <asm/user32.h>
#else
# define user_i387_ia32_struct	user_i387_struct
# define user32_fxsr_struct	user_fxsr_struct
#endif

extern unsigned int mxcsr_feature_mask;
extern void fpu_init(void);
extern void mxcsr_feature_mask_init(void);
extern int init_fpu(struct task_struct *child);
extern void math_state_restore(void);
extern int dump_fpu(struct pt_regs *, struct user_i387_struct *);

DECLARE_PER_CPU(struct task_struct *, fpu_owner_task);

extern void convert_from_fxsr(struct user_i387_ia32_struct *env,
			      struct task_struct *tsk);
extern void convert_to_fxsr(struct task_struct *tsk,
			    const struct user_i387_ia32_struct *env);

extern user_regset_active_fn fpregs_active, xfpregs_active;
extern user_regset_get_fn fpregs_get, xfpregs_get, fpregs_soft_get,
				xstateregs_get;
extern user_regset_set_fn fpregs_set, xfpregs_set, fpregs_soft_set,
				 xstateregs_set;

/*
 * xstateregs_active == fpregs_active. Please refer to the comment
 * at the definition of fpregs_active.
 */
#define xstateregs_active	fpregs_active

#ifdef CONFIG_MATH_EMULATION
# define HAVE_HWFP		(boot_cpu_data.hard_math)
extern void finit_soft_fpu(struct i387_soft_struct *soft);
#else
# define HAVE_HWFP		1
static inline void finit_soft_fpu(struct i387_soft_struct *soft) {}
#endif

#define X87_FSW_ES (1 << 7)	/* Exception Summary */

static __always_inline __pure bool use_xsaveopt(void)
{
	return 0;
}

static __always_inline __pure bool use_xsave(void)
{
	return static_cpu_has(X86_FEATURE_XSAVE);
}

static __always_inline __pure bool use_fxsr(void)
{
        return static_cpu_has(X86_FEATURE_FXSR);
}

extern void __sanitize_i387_state(struct task_struct *);

static inline void sanitize_i387_state(struct task_struct *tsk)
{
	if (!use_xsaveopt())
		return;
	__sanitize_i387_state(tsk);
}

#ifdef CONFIG_X86_64
static inline int fxrstor_checking(struct i387_fxsave_struct *fx)
{
	int err;

	/* See comment in fxsave() below. */
	asm volatile("1:  rex64/fxrstor (%[fx])\n\t"
		     "2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3:  movl $-1,%[err]\n"
		     "    jmp  2b\n"
		     ".previous\n"
		     _ASM_EXTABLE(1b, 3b)
		     : [err] "=r" (err)
		     : [fx] "R" (fx), "m" (*fx), "0" (0));
	return err;
}

static inline int fxsave_user(struct i387_fxsave_struct __user *fx)
{
	/* See comment in fxsave() below. */
	asm volatile("1:  rex64/fxsave (%[fx])\n\t"
		     "2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3:  movl $-1,%[err]\n"
		     "    jmp  2b\n"
		     ".previous\n"
		     _ASM_EXTABLE(1b, 3b)
		     : [err] "=r" (err), "=m" (*fx)
		     : [fx] "R" (fx), "0" (0));
	if (unlikely(err) &&
	    __clear_user(fx, sizeof(struct i387_fxsave_struct)))
		err = -EFAULT;
	/* No need to clear here because the caller clears USED_MATH */
	return err;
}

static inline void fpu_fxsave(struct fpu *fpu)
{
	/* Using "rex64; fxsave %0" is broken because, if the memory operand
	   uses any extended registers for addressing, a second REX prefix
	   will be generated (to the assembler, rex64 followed by semicolon
	   is a separate instruction), and hence the 64-bitness is lost.
	   Using "fxsaveq %0" would be the ideal choice, but is only supported
	   starting with gas 2.16.
	asm volatile("fxsaveq %0"
		     : "=m" (fpu->state->fxsave));
	   Using, as a workaround, the properly prefixed form below isn't
	   accepted by any binutils version so far released, complaining that
	   the same type of prefix is used twice if an extended register is
	   needed for addressing (fix submitted to mainline 2005-11-21).
	asm volatile("rex64/fxsave %0"
		     : "=m" (fpu->state->fxsave));
	   This, however, we can work around by forcing the compiler to select
	   an addressing mode that doesn't require extended registers. */
	asm volatile("rex64/fxsave (%[fx])"
		     : "=m" (fpu->state->fxsave)
		     : [fx] "R" (&fpu->state->fxsave));
}

#else  /* CONFIG_X86_32 */

/* perform fxrstor iff the processor has extended states, otherwise frstor */
static inline int fxrstor_checking(struct i387_fxsave_struct *fx)
{
	/*
	 * The "nop" is needed to make the instructions the same
	 * length.
	 */
	alternative_input(
		"nop ; frstor %1",
		"fxrstor %1",
		X86_FEATURE_FXSR,
		"m" (*fx));

	return 0;
}

static inline void fpu_fxsave(struct fpu *fpu)
{
	asm volatile("fxsave %[fx]"
		     : [fx] "=m" (fpu->state->fxsave));
}

#endif	/* CONFIG_X86_64 */

/* We need a safe address that is cheap to find and that is already
   in L1 during context switch. The best choices are unfortunately
   different for UP and SMP */
#ifdef CONFIG_SMP
#define safe_address (__per_cpu_offset[0])
#else
#define safe_address (kstat_cpu(0).cpustat.user)
#endif

/*
 * These must be called with preempt disabled. Returns
 * 'true' if the FPU state is still intact.
 */
static inline int fpu_save_init(struct fpu *fpu)
{
	if (use_xsave()) {
		fpu_xsave(fpu);

		/*
		 * xsave header may indicate the init state of the FP.
		 */
		if (!(fpu->state->xsave.xsave_hdr.xstate_bv & XSTATE_FP))
			return 1;
	} else if (use_fxsr()) {
		fpu_fxsave(fpu);
	} else {
		asm volatile("fnsave %[fx]; fwait"
			     : [fx] "=m" (fpu->state->fsave));
		return 0;
	}

	/*
	 * If exceptions are pending, we need to clear them so
	 * that we don't randomly get exceptions later.
	 *
	 * FIXME! Is this perhaps only true for the old-style
	 * irq13 case? Maybe we could leave the x87 state
	 * intact otherwise?
	 */
	if (unlikely(fpu->state->fxsave.swd & X87_FSW_ES)) {
		asm volatile("fnclex");

		/* AMD K7/K8 CPUs don't save/restore FDP/FIP/FOP unless an exception
		   is pending.  Clear the x87 state here by setting it to fixed
		   values. safe_address is a random variable that should be in L1 */
		alternative_input(
			ASM_NOP8 ASM_NOP2,
			"emms\n\t"	  	/* clear stack tags */
			"fildl %P[addr]",	/* set F?P to defined value */
			X86_FEATURE_FXSAVE_LEAK,
			[addr] "m" (safe_address));

		return 0;
	}
	return 1;
}

static inline int __save_init_fpu(struct task_struct *tsk)
{
	return fpu_save_init(&tsk->thread.fpu);
}

static inline int fpu_fxrstor_checking(struct fpu *fpu)
{
	return fxrstor_checking(&fpu->state->fxsave);
}

static inline int fpu_restore_checking(struct fpu *fpu)
{
	if (use_xsave())
		return fpu_xrstor_checking(fpu);
	else
		return fpu_fxrstor_checking(fpu);
}

static inline int restore_fpu_checking(struct task_struct *tsk)
{
	struct thread_info *ti = task_thread_info(tsk);

	/* AMD K7/K8 CPUs don't save/restore FDP/FIP/FOP unless an exception
	   is pending.  Clear the x87 state here by setting it to fixed
	   values. "m" is a random variable that should be in L1 */
	alternative_input(
		ASM_NOP8 ASM_NOP2,
		"emms\n\t"	  	/* clear stack tags */
		"fildl %P[addr]",	/* set F?P to defined value */
		X86_FEATURE_FXSAVE_LEAK,
		[addr] "m" (ti->status & TS_USEDFPU));

	return fpu_restore_checking(&tsk->thread.fpu);
}

/*
 * Software FPU state helpers. Careful: these need to
 * be preemption protection *and* they need to be
 * properly paired with the CR0.TS changes!
 */
static inline int __thread_has_fpu(struct thread_info *ti)
{
	return ti->status & TS_USEDFPU;
}

/* Must be paired with an 'stts' after! */
static inline void __thread_clear_has_fpu(struct thread_info *ti)
{
	ti->status &= ~TS_USEDFPU;
	percpu_write(fpu_owner_task, NULL);
}

/* Must be paired with a 'clts' before! */
static inline void __thread_set_has_fpu(struct thread_info *ti)
{
	ti->status |= TS_USEDFPU;
	percpu_write(fpu_owner_task, tsk);
}

/*
 * Encapsulate the CR0.TS handling together with the
 * software flag.
 *
 * These generally need preemption protection to work,
 * do try to avoid using these on their own.
 */
static inline void __thread_fpu_end(struct thread_info *ti)
{
	__thread_clear_has_fpu(ti);
	stts();
}

static inline void __thread_fpu_begin(struct thread_info *ti)
{
	clts();
	__thread_set_has_fpu(ti);
}

/*
 * FPU state switching for scheduling.
 *
 * This is a two-stage process:
 *
 *  - switch_fpu_prepare() saves the old state and
 *    sets the new state of the CR0.TS bit. This is
 *    done within the context of the old process.
 *
 *  - switch_fpu_finish() restores the new state as
 *    necessary.
 */
typedef struct { int preload; } fpu_switch_t;

/*
 * FIXME! We could do a totally lazy restore, but we need to
 * add a per-cpu "this was the task that last touched the FPU
 * on this CPU" variable, and the task needs to have a "I last
 * touched the FPU on this CPU" and check them.
 *
 * We don't do that yet, so "fpu_lazy_restore()" always returns
 * false, but some day..
 */
static inline int fpu_lazy_restore(struct task_struct *new, unsigned int cpu)
{
	return new == percpu_read_stable(fpu_owner_task) &&
		cpu == new->thread.fpu.last_cpu;
}

static inline fpu_switch_t switch_fpu_prepare(struct task_struct *old, struct task_struct *new, int cpu)
{
	fpu_switch_t fpu;

	fpu.preload = tsk_used_math(new) && new->fpu_counter > 5;
	if (__thread_has_fpu(old)) {
		if (!__save_init_fpu(old))
			cpu = ~0;
		old->thread.fpu.last_cpu = cpu;
		old->thread.fpu.has_fpu = 0;	/* But leave fpu_owner_task! */

		/* Don't change CR0.TS if we just switch! */
		if (fpu.preload) {
			new->fpu_counter++;
			__thread_set_has_fpu(new);
			prefetch(new->thread.fpu.state);
		} else
			stts();
	} else {
		old->fpu_counter = 0;
		old->thread.fpu.last_cpu = ~0;
		if (fpu.preload) {
			new->fpu_counter++;
			if (fpu_lazy_restore(new, cpu))
				fpu.preload = 0;
			else
				prefetch(new->thread.fpu.state);
			__thread_fpu_begin(new);
		}
	}
	return fpu;
}

/*
 * By the time this gets called, we've already cleared CR0.TS and
 * given the process the FPU if we are going to preload the FPU
 * state - all we need to do is to conditionally restore the register
 * state itself.
 */
static inline void switch_fpu_finish(struct task_struct *new, fpu_switch_t fpu)
{
	if (fpu.preload) {
		if (unlikely(restore_fpu_checking(new)))
			__thread_fpu_end(new);
	}
}

/*
 * Signal frame handlers...
 */
extern int save_xstate_sig(void __user *buf, void __user *fx, int size);
extern int __restore_xstate_sig(void __user *buf, void __user *fx, int size);

static inline int xstate_sigframe_size(void)
{
	return use_xsave() ? xstate_size + FP_XSTATE_MAGIC2_SIZE : xstate_size;
}

static inline int restore_xstate_sig(void __user *buf, int ia32_frame)
{
	void __user *buf_fx = buf;
	int size = xstate_sigframe_size();

	if (ia32_frame && use_fxsr()) {
		buf_fx = buf + sizeof(struct i387_fsave_struct);
		size += sizeof(struct i387_fsave_struct);
	}

	return __restore_xstate_sig(buf, buf_fx, size);
}

static inline void __drop_fpu(struct task_struct *tsk)
{
	if (__thread_has_fpu(task_thread_info(tsk))) {
		/* Ignore delayed exceptions from user space */
		asm volatile("1: fwait\n"
			     "2:\n"
			     _ASM_EXTABLE(1b, 2b));
		__thread_fpu_end(task_thread_info(tsk));
	}
}

extern bool irq_fpu_usable(void);
extern void kernel_fpu_begin(void);
extern void kernel_fpu_end(void);

/*
 * Some instructions like VIA's padlock instructions generate a spurious
 * DNA fault but don't modify SSE registers. And these instructions
 * get used from interrupt context as well. To prevent these kernel instructions
 * in interrupt context interacting wrongly with other user/kernel fpu usage, we
 * should use them only in the context of irq_ts_save/restore()
 */
static inline int irq_ts_save(void)
{
	/*
	 * If in process context and not atomic, we can take a spurious DNA fault.
	 * Otherwise, doing clts() in process context requires disabling preemption
	 * or some heavy lifting like kernel_fpu_begin()
	 */
	if (!in_atomic())
		return 0;

	if (read_cr0() & X86_CR0_TS) {
		clts();
		return 1;
	}

	return 0;
}

static inline void irq_ts_restore(int TS_state)
{
	if (TS_state)
		stts();
}

#ifdef CONFIG_X86_64

static inline void save_init_fpu(struct task_struct *tsk)
{
	__save_init_fpu(tsk);
	stts();
}

#define unlazy_fpu	__unlazy_fpu
#define clear_fpu	__clear_fpu

#else  /* CONFIG_X86_32 */

/*
 * The question "does this thread have fpu access?"
 * is slightly racy, since preemption could come in
 * and revoke it immediately after the test.
 *
 * However, even in that very unlikely scenario,
 * we can just assume we have FPU access - typically
 * to save the FP state - we'll just take a #NM
 * fault and get the FPU access back.
 *
 * The actual user_fpu_begin/end() functions
 * need to be preemption-safe, though.
 *
 * NOTE! user_fpu_end() must be used only after you
 * have saved the FP state, and user_fpu_begin() must
 * be used only immediately before restoring it.
 * These functions do not do any save/restore on
 * their own.
 */
static inline int user_has_fpu(void)
{
	return __thread_has_fpu(current_thread_info());
}

static inline void user_fpu_end(void)
{
	preempt_disable();
	__thread_fpu_end(current_thread_info());
	preempt_enable();
}

static inline void user_fpu_begin(void)
{
	preempt_disable();
	if (!user_has_fpu())
		__thread_fpu_begin(current_thread_info());
	preempt_enable();
}

/*
 * These disable preemption on their own and are safe
 */
static inline void save_init_fpu(struct task_struct *tsk)
{
	WARN_ON_ONCE(!__thread_has_fpu(task_thread_info(tsk)));
	preempt_disable();
	__save_init_fpu(tsk);
	__thread_fpu_end(task_thread_info(tsk));
	preempt_enable();
}

extern void unlazy_fpu(struct task_struct *tsk);

static inline void drop_fpu(struct task_struct *tsk)
{
	/*
	 * Forget coprocessor state..
	 */
	tsk->fpu_counter = 0;
	preempt_disable();
	__drop_fpu(tsk);
	preempt_enable();
	clear_used_math();
}

#endif	/* CONFIG_X86_64 */

/*
 * i387 state interaction
 */
static inline unsigned short get_fpu_cwd(struct task_struct *tsk)
{
	if (cpu_has_fxsr) {
		return tsk->thread.fpu.state->fxsave.cwd;
	} else {
		return (unsigned short)tsk->thread.fpu.state->fsave.cwd;
	}
}

static inline unsigned short get_fpu_swd(struct task_struct *tsk)
{
	if (cpu_has_fxsr) {
		return tsk->thread.fpu.state->fxsave.swd;
	} else {
		return (unsigned short)tsk->thread.fpu.state->fsave.swd;
	}
}

static inline unsigned short get_fpu_mxcsr(struct task_struct *tsk)
{
	if (cpu_has_xmm) {
		return tsk->thread.fpu.state->fxsave.mxcsr;
	} else {
		return MXCSR_DEFAULT;
	}
}

static bool fpu_allocated(struct fpu *fpu)
{
	return fpu->state != NULL;
}

static inline int fpu_alloc(struct fpu *fpu)
{
	if (fpu_allocated(fpu))
		return 0;
	fpu->state = kmem_cache_alloc(task_xstate_cachep, GFP_KERNEL);
	if (!fpu->state)
		return -ENOMEM;
	WARN_ON((unsigned long)fpu->state & 15);
	return 0;
}

static inline void fpu_free(struct fpu *fpu)
{
	if (fpu->state) {
		kmem_cache_free(task_xstate_cachep, fpu->state);
		fpu->state = NULL;
	}
}

static inline void fpu_copy(struct fpu *dst, struct fpu *src)
{
	memcpy(dst->state, src->state, xstate_size);
}

extern void fpu_finit(struct fpu *fpu);

static inline unsigned long
alloc_mathframe(unsigned long sp, int ia32_frame, unsigned long *buf_fx,
		unsigned long *size)
{
	unsigned long frame_size = xstate_sigframe_size();

	*buf_fx = sp = round_down(sp - frame_size, 64);
	if (ia32_frame && use_fxsr()) {
		frame_size += sizeof(struct i387_fsave_struct);
		sp -= sizeof(struct i387_fsave_struct);
	}

	*size = frame_size;
	return sp;
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_I387_H */
