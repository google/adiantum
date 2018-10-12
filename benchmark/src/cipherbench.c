/*
 * Cryptographic benchmark program
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

static const struct cipher {
	const char *name;
	void (*test_func)(void);
} ciphers[] = {
	{ "Adiantum",		test_adiantum },
	{ "AES",		test_aes },
	{ "ChaCha",		test_chacha },
	{ "ChaCha-MEM",		test_chacha_mem },
	{ "CHAM",		test_cham },
	{ "Chaskey-LTS",	test_chaskey_lts },
	{ "HPolyC",		test_hpolyc },
	{ "LEA",		test_lea },
	{ "NH",			test_nh },
	{ "NOEKEON",		test_noekeon },
	{ "Poly1305",		test_poly1305 },
	{ "RC5",		test_rc5 },
	{ "RC6",		test_rc6 },
	{ "Speck",		test_speck },
	{ "XTEA",		test_xtea },
};

static const struct cipher *find_cipher(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ciphers); i++) {
		if (!strcasecmp(name, ciphers[i].name))
			return &ciphers[i];
	}
	return NULL;
}

static int get_num_cpus(void)
{
	static int ncpus;

	if (ncpus <= 0)
		ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (ncpus <= 0) {
		fprintf(stderr, "Unable to determine number of CPUs, assuming 1\n");
		ncpus = 1;
	}
	return ncpus;
}

static char saved_cpufreq_governor[65];

static void set_cpufreq_governor(const char *governor)
{
	int cpu, ncpus = get_num_cpus();

	for (cpu = 0; cpu < ncpus; cpu++) {
		char path[128];
		char cur_governor[64];
		int fd;
		int res;

		sprintf(path,
			"/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor",
			cpu);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Unable to open '%s' for reading: %s\n",
				path, strerror(errno));
			continue;
		}
		res = read(fd, cur_governor, sizeof(cur_governor) - 1);
		if (res < 0) {
			fprintf(stderr, "Error reading '%s': %s\n",
				path, strerror(errno));
			close(fd);
			continue;
		}
		close(fd);
		if (res > 0 && cur_governor[res - 1] == '\n')
			res--;
		cur_governor[res] = '\0';
		if (!strcmp(cur_governor, governor))
			continue;
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			if (errno == EACCES) {
				fprintf(stderr,
					"This program is not authorized to change the CPU frequency scaling governor (currently '%s').\n"
					"Recommend re-running with sudo or 'adb root'\n", cur_governor);
				break;
			}
			fprintf(stderr, "Unable to open '%s' for writing: %s\n",
				path, strerror(errno));
			break;
		}
		if (write(fd, governor, strlen(governor)) != strlen(governor)) {
			fprintf(stderr, "Error setting '%s' CPU frequency scaling governor: %s\n",
				governor, strerror(errno));
			close(fd);
			break;
		}
		if (strcmp(governor, saved_cpufreq_governor) != 0)
			strncpy(saved_cpufreq_governor, cur_governor,
				sizeof(saved_cpufreq_governor));
		close(fd);
	}
}

static u64 get_max_cpufreq(void)
{
	int cpu, ncpus = get_num_cpus();
	unsigned long long prev_freq = 0;

	for (cpu = 0; cpu < ncpus; cpu++) {
		char path[128];
		char buf[64];
		int fd;
		int res;
		unsigned long long freq;

		sprintf(path, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq",
			cpu);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Unable to query CPU frequency: %s\n",
				strerror(errno));
			continue;
		}
		memset(buf, 0, sizeof(buf));
		res = read(fd, buf, sizeof(buf));
		if (res < 0) {
			fprintf(stderr, "Error reading '%s': %s\n",
				path, strerror(errno));
			close(fd);
			continue;
		}
		close(fd);
		if (sscanf(buf, "%llu", &freq) != 1) {
			fprintf(stderr, "'%s' contained unexpected contents: '%s'\n",
				path, buf);
			continue;
		}
		if (prev_freq == 0) {
			prev_freq = freq;
		} else if (freq != prev_freq) {
			fprintf(stderr, "CPUs have different max frequencies.  Results may be unreliable.\n");
			freq = max(freq, prev_freq);
		}
	}

	return prev_freq;
}

u64 cpu_frequency_kHz;

static void configure_cpu(void)
{
	set_cpufreq_governor("performance");

	cpu_frequency_kHz = get_max_cpufreq();

	if (cpu_frequency_kHz != 0)
		printf("Detected max CPU frequency: %"PRIu64".%03"PRIu64" MHz\n",
		       cpu_frequency_kHz / 1000, cpu_frequency_kHz % 1000);
}

static void deconfigure_cpu(void)
{
	if (saved_cpufreq_governor[0])
		set_cpufreq_governor(saved_cpufreq_governor);
}

void show_result(const char *algname, const char *op, const char *impl,
		 u64 nbytes, u64 ns_elapsed)
{
	char hdr[strlen(algname) + strlen(op) + strlen(impl) + 10];

	sprintf(hdr, "%s %s (%s) ", algname, op, impl);

	printf("%-45s %6.3f cpb (%" PRIu64 " KB/s)\n",
	       hdr, cycles_per_byte(nbytes, ns_elapsed),
	       KB_per_s(nbytes, ns_elapsed));
	fflush(stdout);
}

__noreturn void assertion_failed(const char *expr, const char *file, int line)
{
	fflush(stdout);
	fprintf(stderr, "Assertion failed: %s at %s:%d", expr, file, line);
	abort();
}

struct cipherbench_params g_params = {
	.bufsize = 4096,
	.ntries = 5,
};

enum {
	OPT_BUFSIZE,
	OPT_NTRIES,
	OPT_TIME_INSNS,
	OPT_HELP,
};

static const struct option longopts[] = {
	{ "bufsize", required_argument, NULL, OPT_BUFSIZE },
	{ "ntries", required_argument, NULL, OPT_NTRIES },
	{ "time-insns", no_argument, NULL, OPT_TIME_INSNS },
	{ "help", no_argument, NULL, OPT_HELP },
	{ NULL, 0, NULL, 0 },
};

static void show_available_ciphers(void)
{
	int i;

	fprintf(stderr, "Available ciphers:");
	for (i = 0; i < ARRAY_SIZE(ciphers); i++)
		fprintf(stderr, " %s", ciphers[i].name);
	fprintf(stderr, "\n");
}

static void usage(void)
{
	static const char * const s =
"Usage: cipherbench [OPTION...] [CIPHER]...\n"
"Options:\n"
"  --bufsize=BUFSIZE\n"
"  --ntries=NTRIES\n"
"  --time-insns\n"
"  --help\n";

	fputs(s, stderr);
	show_available_ciphers();
	exit(1);
}

int main(int argc, char *argv[])
{
	int i;
	int c;
	bool time_insns = false;

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case OPT_BUFSIZE:
			g_params.bufsize = atoi(optarg);
			break;
		case OPT_NTRIES:
			g_params.ntries = atoi(optarg);
			break;
		case OPT_TIME_INSNS:
			time_insns = true;
			break;
		case OPT_HELP:
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		for (i = 0; i < argc; i++) {
			if (!find_cipher(argv[i])) {
				fprintf(stderr, "Unknown cipher: '%s'\n",
					argv[i]);
				show_available_ciphers();
				exit(1);
			}
		}
	}

	configure_cpu();

	if (time_insns) {
		do_insn_timing();
		goto out;
	}

	printf("Benchmark parameters:\n");
	printf("\tbufsize\t\t%d\n", g_params.bufsize);
	printf("\tntries\t\t%d\n", g_params.ntries);
	printf("\n");

	if (argc) {
		for (i = 0; i < argc; i++)
			find_cipher(argv[i])->test_func();
	} else {
		for (i = 0; i < ARRAY_SIZE(ciphers); i++)
			ciphers[i].test_func();
	}
out:
	deconfigure_cpu();
	return 0;
}
