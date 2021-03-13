#ifndef __KRG_EXIT_H__
#define __KRG_EXIT_H__

struct task_struct;

#ifdef CONFIG_KRG_EPM

#include <linux/types.h>
#include <kerrighed/sys/types.h>

struct children_kddm_object;
enum pid_type;
struct siginfo;
struct rusage;

struct remote_child {
	struct list_head sibling;
	struct list_head thread_group;
	pid_t pid;
	pid_t tgid;
	pid_t pgid;
	pid_t sid;
	pid_t parent;
	pid_t real_parent;
	int ptraced;
	int exit_signal;
	long exit_state;
};

/* do_wait() hook */
int krg_do_wait(struct children_kddm_object *obj, struct wait_opts *wo);

/* Used by krg_do_wait() */
int krg_wait_task_zombie(struct wait_opts *wo,
			 struct remote_child *child);

/* do_notify_parent() hook */
int krg_do_notify_parent(struct task_struct *task, struct siginfo *info);

/* Used by remote (zombie) child reparenting */
void notify_remote_child_reaper(pid_t zombie_pid);
/* Used by zombie migration/restart */
void krg_zombie_check_notify_child_reaper(struct task_struct *task,
					  struct children_kddm_object *parent_children_obj);

/* Delayed do_notify_parent() in release_task() */
int krg_delayed_notify_parent(struct task_struct *leader);

/* exit_ptrace() hooks */
struct children_kddm_object *
krg_prepare_exit_ptrace_task(struct task_struct *tracer,
			     struct task_struct *task)
	__acquires(tasklist_lock);
void krg_finish_exit_ptrace_task(struct task_struct *task,
				 struct children_kddm_object *obj,
				 bool dead)
	__releases(tasklist_lock);

#endif /* CONFIG_KRG_EPM */

#ifdef CONFIG_KRG_PROC

/* exit_notify() hooks */

void *krg_prepare_exit_notify(struct task_struct *task);
void krg_finish_exit_notify(struct task_struct *task, int signal, void *cookie);

#endif /* CONFIG_KRG_PROC */

#endif /* __KRG_EXIT_H__ */
