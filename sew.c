#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void fprintargv(FILE *fp, int argc, char **argv)
{
	fputs(*argv, fp);
	argc--;
	argv++;

	for (; argc; argc--, argv++) {
		fputc(' ', fp);
		fputs(*argv, fp);
	}
}


typedef struct action {
	const char *name;
	const char *usage;

	int (*exec)(int argc, char **argv, void **buf, size_t *buflen);
} action_t;

static void action_usage(const action_t *act)
{
	fprintf(stderr, "%s %s", act->name, act->usage);
}

static int action_exec(const action_t *acts, int argc, char **argv,
		       void **buf, size_t *buflen)
{
	const action_t *act;
	int err;

	for (act = acts; act->name; act++) {
		if (!strcmp(act->name, *argv))
			break;
	}

	if (!act->name) {
		fputs("unknown expression '", stderr);
		fprintargv(stderr, argc, argv);
		fputs("'\n", stderr);
		return -ENOENT;
	}

	err = act->exec(argc, argv, buf, buflen);
	if (err) {
		fputs("malformed expression '", stderr);
		fprintargv(stderr, argc, argv);
		fputs("'\nusage: ", stderr);
		action_usage(act);
		fputc('\n', stderr);
		return err;
	}

	return 0;
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

	argc--;
	argv++;
	if (!argc)
		return 0;

	for (data = add(buf, buflen, argc); argc; data++, argv++, argc--) {
		long int byte;

		byte = strtol(*argv, NULL, 16);
		if (byte < 0 || byte >= 0x100) {
			fprintf(stderr, "hex: invalid byte '%s'\n", *argv);
			return -EINVAL;
		}

		*data = byte;
	}

	return 0;
}

int pad_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	long int len;
	char *data;

	argc--;
	argv++;
	if (argc != 1)
		return -EINVAL;

	len = strtol(*argv, NULL, 0);
	if (len < 0)
		return -EINVAL;

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

	argc--;
	argv++;
	if (argc != 1)
		return -EINVAL;

	len = strtol(*argv, NULL, 0);
	if (len < 0)
		return -EINVAL;

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

	argc--;
	argv++;
	if (argc != 1)
		return -EINVAL;

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
		return -EINVAL;

	return 0;
}

#define VLAN_HLEN  4
int vlan_exec(int argc, char **argv, void **buf, size_t *buflen)
{
	char *vlan = add(buf, buflen, VLAN_HLEN);
	long int vid;

	argc--;
	argv++;
	if (argc != 1)
		return -EINVAL;

	vlan[0] = 0x81;
	vlan[1] = 0x00;

	vid = strtol(*argv, NULL, 0);
	if (vid < 0 || vid >= 4096)
		return -EINVAL;

	vlan[2] = vid >> 8;
	vlan[3] = vid & 0xff;
	return 0;
}

static const action_t actions[] = {
	/* common */
	{ .name = "hex",  .usage = "[<byte> ... ]",  .exec = hex_exec },
	{ .name = "x",    .usage = "[<byte> ... ]",  .exec = hex_exec },
	{ .name = "pad",  .usage = "<len> [<byte>]", .exec = pad_exec },
	{ .name = "zero", .usage = "<len>",          .exec = zero_exec },
	{ .name = "z",    .usage = "<len>",          .exec = zero_exec },

	/* ethernet */
	{ .name = "mac",  .usage = "bc | random | <mac>", .exec = mac_exec },
	{ .name = "vlan", .usage = "<vid>",               .exec = vlan_exec },

	/* term */
	{ .name = NULL }
};

int main(int argc, char **argv)
{
	void *buf = NULL;
	size_t buflen = 0;
	int err, aargc;

	srand(time(0));
	
	argc--;
	argv++;

	while (argc > 0) {
		for (aargc = 0; aargc < argc && strcmp(argv[aargc], "^");)
			aargc++;

		if (!aargc) {
			argc--;
			argv++;
			continue;
		}

		err = action_exec(actions, aargc, argv, &buf, &buflen);
		if (err)
			break;

		argc -= aargc + 1;
		argv += aargc + 1;
	}

	if (buf && !err && fwrite(buf, buflen, 1, stdout) != 1) {
		err = -EIO;
		fprintf(stderr, "err: unable to write bytes to stdout");
	}

	if (buf)
		free(buf);

	return err ? 1 : 0;
}
