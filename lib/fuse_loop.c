/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Implementation of the single-threaded FUSE session loop.

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#define _GNU_SOURCE

#include "config.h"
#include "fuse_lowlevel.h"
#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

void* fuse_session_loop_thread(void *__se_cpuid)
{
	int res = 0;
	struct fuse_buf fbuf = {
		.mem = NULL,
	};

	struct fuse_session_with_cpuid* se_cpuid = (struct fuse_session_with_cpuid*)__se_cpuid;
	struct fuse_session* se = se_cpuid->se;
	int cpuId = se_cpuid->cpuid;

	cpu_set_t cpuset = {0};
	cpuset.__bits[0] = (1 << cpuId);
	res = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	if (res != 0){
		return NULL;
	}

	printf("fuse_session_loop started on targetcpuid: %d, mycpu: %d, mypid: %d, mytid: %d\n", 
	cpuId, sched_getcpu(), getpid(), gettid());

	while (!fuse_session_exited(se)) {
		res = fuse_session_receive_buf_int(se, &fbuf, NULL);

		if (res == -EINTR)
			continue;
		if (res <= 0)
			break;

		fuse_session_process_buf_int(se, &fbuf, NULL);
	}

	free(fbuf.mem);
	if(res > 0)
		/* No error, just the length of the most recently read
		   request */
		res = 0;
	if(se->error != 0)
		res = se->error;
	fuse_session_reset(se);
	return NULL;
}

int fuse_session_loop(struct fuse_session *se)
{
	int i;
	int ret = 0;
	pthread_t *threads = NULL;
	struct fuse_session_with_cpuid *se_cpuids = NULL;
	//int N = sysconf(_SC_NPROCESSORS_ONLN);
	int N = 4;

	printf("Number of processors: %d\n", N);

	threads = malloc(sizeof(pthread_t) * N);
	if (!threads){
		ret = ENOMEM;
		goto Exit;
	}
	
	se_cpuids = malloc(sizeof(struct fuse_session_with_cpuid) * N);
	if (!se_cpuids){
		ret = ENOMEM;
		goto Exit;
	}

	for(i = 0; i < N; ++i){
		se_cpuids[i].cpuid = i;
		se_cpuids[i].se = se;
		pthread_create(&threads[i], NULL, fuse_session_loop_thread, (void *) &se_cpuids[i]);
	}

	while (!fuse_session_exited(se)) {
		sleep(1);
	}
    
	for(i = 0; i < N; ++i){
		pthread_cancel(threads[i]);
		pthread_join(threads[i],NULL);
	}

Exit:
	if(threads) free(threads);
	if(se_cpuids) free(se_cpuids);
	return ret;
}