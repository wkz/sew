#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct action {
	const char *name;

	int (*exec)(int argc, char **argv, void **buf, size_t *buflen);
} action_t;

static int action_exec(const action_t *acts, int argc, char **argv,
		       void **buf, size_t *buflen)
{
	const action_t *act;

	for (act = acts; act->name; act++) {
		if (strcmp(act->name, *argv))
			continue;

		return act->exec(argc - 1, argv + 1, buf, buflen);
	}

	errx(1, "unknown action '%s'", *argv);
	return -1;
}


void *add(void **buf, size_t *buflen, size_t len)
{
	void *start;

	*buf = realloc(*buf, *buflen + len);
	assert(*buf);

	start = *buf + *buflen;
	*buflen += len;
	return start;
}

int hex_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	char *data;

	if (!argc)
		return 0;

	for (data = add(buf, buflen, argc); argc; data++, argv++, argc--) {
		long int byte;

		byte = strtol(*argv, NULL, 16);
		if (byte < 0 || byte >= 0x100)
			errx(1, "hex: invalid byte '%s'", *argv);

		*data = byte;
	}

	return 0;
}

int pad_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	long int len;
	char *data;

	if (argc != 1)
		errx(1, "pad: expected one argument (len), got %d", argc);

	len = strtol(*argv, NULL, 0);
	if (len < 0)
		errx(1, "pad: invalid len '%s'", *argv);

	len = len - (*buflen % len);
	if (!len)
		return 0;

	data = add(buf, buflen, len);
	memset(data, 0, len);
	return 0;
}

int zero_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	long int len;
	char *data;

	if (argc != 1)
		errx(1, "zero: expected one argument (len), got %d", argc);

	len = strtol(*argv, NULL, 0);
	if (len < 0)
		errx(1, "zero: invalid len '%s'", *argv);

	data = add(buf, buflen, len);
	memset(data, 0, len);
	return 0;
}

#define MAC_FMT "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx"
#define MAC_LEN 6
int mac_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	char *mac = add(buf, buflen, MAC_LEN);
	int ret;

	if (argc != 1)
		errx(1, "mac: expected one argument (address), got %d", argc);

	if (!strcmp(*argv, "bc") || !strcmp(*argv, "broadcast")) {
		memset(mac, 0xff, MAC_LEN);
		return 0;
	}

	if (!strcmp(*argv, "random")) {
		int i;

		for (i = 0; i < MAC_LEN; i++)
			mac[i] = rand() & 0xff;

		/* clear multicast, set locally assigned */
		mac[0] &= ~1;
		mac[0] |=  2;
		return 0;
	}

	ret = sscanf(*argv, MAC_FMT,
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != MAC_LEN)
		errx(1, "mac: unknown address '%s'", *argv);

	return 0;
}

#define VLAN_HLEN  4
int vlan_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	char *vlan = add(buf, buflen, VLAN_HLEN);
	long int vid;

	if (argc != 1)
		errx(1, "vlan: expected one argument (vid), got %d", argc);

	vlan[0] = 0x81;
	vlan[1] = 0x00;

	vid = strtol(*argv, NULL, 0);
	if (vid < 0 || vid >= 4096)
		errx(1, "vlan: vid out of range, '%s'", *argv);

	vlan[2] = vid >> 8;
	vlan[3] = vid & 0xff;
	return 0;
}

static const action_t actions[] = {
	/* common */
	{ .name = "hex",  .exec = hex_exec },
	{ .name = "x",    .exec = hex_exec },
	{ .name = "pad",  .exec = pad_exec },
	{ .name = "zero", .exec = zero_exec },
	{ .name = "z",    .exec = zero_exec },

	/* ethernet */
	{ .name = "mac",  .exec = mac_exec },
	{ .name = "vlan", .exec = vlan_exec },

	/* term */
	{ .name = NULL }
};

int main(int argc, char **argv)
{
	void *buf = NULL;
	size_t buflen = 0;
	int error, aargc;

	srand(time(0));
	
	argc--;
	argv++;

	while (argc > 0) {
		for (aargc = 0; aargc < argc && strcmp(argv[aargc], "^"); aargc++);

		if (!aargc) {
			argc--;
			argv++;
			continue;
		}

		error = action_exec(actions, aargc, argv, &buf, &buflen);
		if (error)
			exit(1);

		argc -= aargc + 1;
		argv += aargc + 1;
	}

	if (buf) {
		if (fwrite(buf, buflen, 1, stdout) != 1)
			err(1, "unable to write packet to stdout");

		free(buf);
	}

	return 0;
}
