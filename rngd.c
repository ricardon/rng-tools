/*
 * rngd.c -- Random Number Generator daemon
 *
 * rngd reads data from a hardware random number generator, verifies it
 * looks like random data, and adds it to /dev/random's entropy store.
 *
 * In theory, this should allow you to read very quickly from
 * /dev/random; rngd also adds bytes to the entropy store periodically
 * when it's full, which makes predicting the entropy store's contents
 * harder.
 *
 * Copyright (C) 2001 Philipp Rumpf
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>
#include <syslog.h>
#include <signal.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"
#include "rngd_linux.h"

/*
 * Globals
 */

/* Background/daemon mode */
int am_daemon;				/* Nonzero if we went daemon */

bool server_running = true;		/* set to false, to stop daemon */

/* Command line arguments and processing */
const char *argp_program_version =
	"rngd " VERSION "\n"
	"Copyright 2001-2004 Jeff Garzik\n"
	"Copyright (c) 2001 by Philipp Rumpf\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] =
	"Check and feed random data from hardware device to kernel entropy pool.\n";

static struct argp_option options[] = {
	{ "foreground",	'f', 0, 0, "Do not fork and become a daemon" },

	{ "background", 'b', 0, 0, "Become a daemon (default)" },

	{ "random-device", 'o', "file", 0,
	  "Kernel device used for random number output (default: /dev/random)" },

	{ "rng-device", 'r', "file", 0,
	  "Kernel device used for random number input (default: /dev/hw_random)" },

	{ "pid-file", 'p', "file", 0,
	  "File used for recording daemon PID, and multiple exclusion (default: /var/run/rngd.pid)" },

	{ "random-step", 's', "nnn", 0,
	  "Number of bytes written to random-device at a time (default: 64)" },

	{ "fill-watermark", 'W', "n", 0,
	  "Do not stop feeding entropy to random-device until at least n bits of entropy are available in the pool (default: 2048), 0 <= n <= 4096" },

	{ "quiet", 'q', 0, 0, "Suppress error messages" },

	{ "verbose" ,'v', 0, 0, "Report available entropy sources" },

	{ "timeout", 't', "nnn", 0,
	  "Interval written to random-device when the entropy pool is full, in seconds, or 0 to disable (default: 60)" },
	{ "no-tpm", 'n', "1|0", 0,
	  "do not use tpm as a source of random number input (default: 0)" },

	{ 0 },
};

static struct arguments default_arguments = {
	.random_name	= "/dev/random",
	.pid_file	= "/var/run/rngd.pid",
	.poll_timeout	= 60,
	.random_step	= 64,
	.fill_watermark	= 2048,
	.daemon		= 1,
	.enable_tpm	= 1,
	.quiet		= 0,
	.verbose	= 0,
};
struct arguments *arguments = &default_arguments;

static struct rng rng_default = {
	.rng_name	= "/dev/hw_random",
	.rng_fd		= -1,
	.xread		= xread,
};

static struct rng rng_tpm = {
	.rng_name	= "/dev/tpm0",
	.rng_fd		= -1,
	.xread		= xread_tpm,
};

struct rng *rng_list;

/*
 * command line processing
 */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'o':
		arguments->random_name = arg;
		break;
	case 'p':
		arguments->pid_file = arg;
		break;
	case 'r':
		rng_default.rng_name = arg;
		break;
	case 't': {
		float f;
		if (sscanf(arg, "%f", &f) == 0)
			argp_usage(state);
		else
			arguments->poll_timeout = f;
		break;
	}

	case 'f':
		arguments->daemon = 0;
		break;
	case 'b':
		arguments->daemon = 1;
		break;
	case 's':
		if (sscanf(arg, "%i", &arguments->random_step) == 0)
			argp_usage(state);
		break;
	case 'W': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 0) || (n > 4096))
			argp_usage(state);
		else
			arguments->fill_watermark = n;
		break;
	}
	case 'q':
		arguments->quiet = 1;
		break;
	case 'v':
		arguments->verbose = 1;
		break;
	case 'n': {
		int n;
		if ((sscanf(arg,"%i", &n) == 0) || ((n | 1)!=1))
			argp_usage(state);
		else
			arguments->enable_tpm = 0;
		break;
	}

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };


static int update_kernel_random(int random_step, double poll_timeout,
	unsigned char *buf, fips_ctx_t *fipsctx_in)
{
	unsigned char *p;
	int fips;

	fips = fips_run_rng_test(fipsctx_in, buf);
	if (fips) {
		if (!arguments->quiet)
			message(LOG_DAEMON|LOG_ERR, "failed fips test\n");
		return 1;
	}

	for (p = buf; p + random_step <= &buf[FIPS_RNG_BUFFER_SIZE];
		 p += random_step) {
		random_add_entropy(p, random_step);
		random_sleep(poll_timeout);
	}
	return 0;
}

static void do_loop(int random_step, double poll_timeout)
{
	unsigned char buf[FIPS_RNG_BUFFER_SIZE];
	int retval = 0;
	int no_work = 0;

	while (no_work < 100) {
		struct rng *iter;
		bool work_done;

		work_done = false;
		for (iter = rng_list; iter; iter = iter->next)
		{
			int rc;

			if (!server_running)
				return;

			if (iter->disabled)
				continue;	/* failed, no work */

			retval = iter->xread(buf, sizeof buf, iter);
			if (retval)
				continue;	/* failed, no work */

			work_done = true;

			rc = update_kernel_random(random_step,
					     poll_timeout, buf,
					     iter->fipsctx);
			if (rc == 0)
				continue;	/* succeeded, work done */

			iter->failures++;
			if (iter->failures == MAX_RNG_FAILURES) {
				if (!arguments->quiet)
					message(LOG_DAEMON|LOG_ERR,
					"too many FIPS failures, disabling entropy source\n");
				iter->disabled = true;
			}
		}

		if (!work_done)
			no_work++;
	}

	if (!arguments->quiet)
		message(LOG_DAEMON|LOG_ERR,
		"No entropy sources working, exiting rngd\n");
}

static void term_signal(int signo)
{
	server_running = false;
}

int main(int argc, char **argv)
{
	int rc_rng = 0;
	int rc_tpm = 0;
	int pid_fd = -1;

	openlog("rngd", 0, LOG_DAEMON);

	/* Parsing of commandline parameters */
	argp_parse(&argp, argc, argv, 0, 0, arguments);

	/* Init entropy sources, and open TRNG device */
	rc_rng = init_entropy_source(&rng_default);
	if (arguments->enable_tpm)
		rc_tpm = init_tpm_entropy_source(&rng_tpm);

	if (rc_rng && rc_tpm) {
		if (!arguments->quiet) {
			message(LOG_DAEMON|LOG_ERR,
				"can't open entropy source(tpm or intel/amd rng)");
			message(LOG_DAEMON|LOG_ERR,
				"Maybe RNG device modules are not loaded\n");
		}
		return 1;
	}

	if (arguments->verbose) {
		printf("Available entropy sources:\n");
		if (!rc_rng)
			printf("\tIntel/AMD hardware rng\n");
		if (!rc_tpm)
			printf("\tTPM\n");
	}

	if (rc_rng
		&& (rc_tpm || !arguments->enable_tpm)) {
		if (!arguments->quiet)
			message(LOG_DAEMON|LOG_ERR,
		"No entropy source available, shutting down\n");
		return 1;
	}

	/* Init entropy sink and open random device */
	init_kernel_rng(arguments->random_name);

	if (arguments->daemon) {
		am_daemon = 1;

		if (daemon(0, 0) < 0) {
			if(!arguments->quiet)
				fprintf(stderr, "can't daemonize: %s\n",
				strerror(errno));
			return 1;
		}

		/* require valid, locked PID file to proceed */
		pid_fd = write_pid_file(arguments->pid_file);
		if (pid_fd < 0)
			return 1;

		signal(SIGHUP, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		signal(SIGINT, term_signal);
		signal(SIGTERM, term_signal);
	}

	do_loop(arguments->random_step,
		arguments->poll_timeout ? : -1.0);

	if (pid_fd >= 0)
		unlink(arguments->pid_file);

	return 0;
}
