/** Dynamic CPU information management.
 *  @file dynamic_cpu_info_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/swap.h>
#include <linux/kernel_stat.h>
#include <linux/hardirq.h>

#include <kerrighed/cpu_id.h>
#include <kerrighed/workqueue.h>
#include <kddm/kddm.h>

#include <asm/cputime.h>

#include "dynamic_cpu_info_linker.h"
#include "static_cpu_info_linker.h"

#include <kerrighed/debug.h>

extern cputime64_t get_idle_time(int cpu);

struct kddm_set *dynamic_cpu_info_kddm_set;

/*****************************************************************************/
/*                                                                           */
/*                   DYNAMIC CPU INFO KDDM IO FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

/****************************************************************************/

/* Init the dynamic cpu info IO linker */

static struct iolinker_struct dynamic_cpu_info_io_linker = {
	.default_owner = cpu_info_default_owner,
	.linker_name = "dyn_cpu_nfo",
	.linker_id = DYNAMIC_CPU_INFO_LINKER,
};

static void update_dynamic_cpu_info_worker(struct work_struct *data);
static DECLARE_DELAYED_WORK(update_dynamic_cpu_info_work,
			    update_dynamic_cpu_info_worker);

/** Update dynamic CPU informations for all local CPU.
 *  @author Renaud Lottiaux
 */
static void update_dynamic_cpu_info_worker(struct work_struct *data)
{
	krg_dynamic_cpu_info_t *dynamic_cpu_info;
	int i, j, cpu_id;

	for_each_online_cpu(i) {
		cpu_id = krg_cpu_id(i);
		dynamic_cpu_info =
			_kddm_grab_object(dynamic_cpu_info_kddm_set, cpu_id);

		/* Compute data for stat proc file */

		dynamic_cpu_info->stat = kstat_cpu(i);
		dynamic_cpu_info->stat.cpustat.idle =
			cputime64_add(dynamic_cpu_info->stat.cpustat.idle,
				      get_idle_time(i));
		dynamic_cpu_info->sum_irq = 0;
		dynamic_cpu_info->sum_irq += kstat_cpu_irqs_sum(i);
		dynamic_cpu_info->sum_irq += arch_irq_stat_cpu(i);

		dynamic_cpu_info->sum_softirq = 0;
		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			dynamic_cpu_info->per_softirq_sums[j] += softirq_stat;
			dynamic_cpu_info->sum_softirq += softirq_stat;
		}

		_kddm_put_object(dynamic_cpu_info_kddm_set, cpu_id);
	}

	queue_delayed_work(krg_wq, &update_dynamic_cpu_info_work, HZ);
}

void init_dynamic_cpu_info_objects(void)
{
	update_dynamic_cpu_info_worker(&update_dynamic_cpu_info_work.work);
}

int dynamic_cpu_info_init(void)
{
	register_io_linker(DYNAMIC_CPU_INFO_LINKER,
			   &dynamic_cpu_info_io_linker);

	/* Create the CPU info container */

	dynamic_cpu_info_kddm_set =
		create_new_kddm_set(kddm_def_ns,
				    DYNAMIC_CPU_INFO_KDDM_ID,
				    DYNAMIC_CPU_INFO_LINKER,
				    KDDM_CUSTOM_DEF_OWNER,
				    sizeof(krg_dynamic_cpu_info_t),
				    0);
	if (IS_ERR(dynamic_cpu_info_kddm_set))
		OOM;

	init_dynamic_cpu_info_objects();
	return 0;
}
