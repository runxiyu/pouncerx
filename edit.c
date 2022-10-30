/* Copyright (C) 2022  June McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify this Program, or any covered work, by linking or
 * combining it with OpenSSL (or a modified version of that library),
 * containing parts covered by the terms of the OpenSSL License and the
 * original SSLeay license, the licensors of this Program grant you
 * additional permission to convey the resulting work. Corresponding
 * Source for a non-source form of such a combination shall include the
 * source code for the parts of OpenSSL used as well as that of the
 * covered work.
 */

#include <assert.h>
#include <err.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

char *configPath(char *buf, size_t cap, const char *path, int i);
FILE *configOpen(const char *path, const char *mode);

#define WS "\t "

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

struct Option {
	bool set;
	char *name;
	char *value;
};

struct Config {
	size_t cap, len;
	struct Option *opts;
};

static struct Option configGet(const struct Config *config, const char *name) {
	for (size_t i = 0; i < config->len; ++i) {
		if (!strcmp(config->opts[i].name, name)) return config->opts[i];
	}
	return (struct Option) { .set = false };
}

static void
configSet(struct Config *config, const char *name, const char *value) {
	for (size_t i = 0; i < config->len; ++i) {
		struct Option *opt = &config->opts[i];
		if (strcmp(opt->name, name)) continue;

		opt->set = true;
		free(opt->value);
		opt->value = NULL;
		if (value) {
			opt->value = strdup(value);
			if (!opt->value) err(EX_OSERR, "strdup");
		}
		return;
	}

	if (config->len == config->cap) {
		config->cap = (config->cap ? config->cap * 2 : 32);
		config->opts = realloc(
			config->opts, config->cap * sizeof(*config->opts)
		);
		if (!config->opts) err(EX_OSERR, "realloc");
	}

	struct Option *opt = &config->opts[config->len++];
	opt->set = true;
	opt->name = strdup(name);
	if (!opt->name) err(EX_OSERR, "strdup");

	opt->value = NULL;
	if (value) {
		opt->value = strdup(value);
		if (!opt->value) err(EX_OSERR, "strdup");
	}
}

static void configUnset(struct Config *config, const char *name) {
	for (size_t i = 0; i < config->len; ++i) {
		if (strcmp(config->opts[i].name, name)) continue;
		config->opts[i].set = false;
		break;
	}
}

static void configWrite(const struct Config *config, FILE *file) {
	int error = ftruncate(fileno(file), 0);
	if (error) err(EX_IOERR, "ftruncate");

	rewind(file);
	fprintf(file, "# written by pounce-edit\n");
	for (size_t i = 0; i < config->len; ++i) {
		if (!config->opts[i].set) continue;
		fprintf(file, "%s", config->opts[i].name);
		if (config->opts[i].value) {
			fprintf(file, " = %s", config->opts[i].value);
		}
		fprintf(file, "\n");
		if (ferror(file)) err(EX_IOERR, "writing configuration");
	}

	error = fflush(file);
	if (error) err(EX_IOERR, "writing configuration");
}

static void configParse(struct Config *config, const char *path) {
	FILE *file = configOpen(path, "r");
	if (!file) exit(EX_NOINPUT);

	ssize_t llen;
	size_t cap = 0;
	char *buf = NULL;
	for (size_t line = 1; 0 < (llen = getline(&buf, &cap, file)); ++line) {
		if (buf[llen-1] == '\n') buf[--llen] = '\0';

		char *name = buf + strspn(buf, WS);
		size_t len = strcspn(name, WS "=");
		if (!name[0] || name[0] == '#') continue;

		char *equal = &name[len] + strspn(&name[len], WS);
		if (*equal && *equal != '=') {
			name[len] = '\0';
			errx(
				EX_USAGE, "%s:%zu: option `%s' missing equals sign",
				path, line, name
			);
		}

		char *value = NULL;
		if (*equal) {
			value = &equal[1] + strspn(&equal[1], WS);
		}

		name[len] = '\0';
		configSet(config, name, value);
	}
	fclose(file);
}

static bool verbose;
static struct tls *client;

static void clientWrite(const char *ptr, size_t len) {
	while (len) {
		ssize_t ret = tls_write(client, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_write: %s", tls_error(client));
		ptr += ret;
		len -= ret;
	}
}

static void format(const char *format, ...)
__attribute__((format(printf, 1, 2)));
static void format(const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert((size_t)len < sizeof(buf));
	if (verbose) fprintf(stderr, "%s", buf);
	clientWrite(buf, len);
}

enum { ParamCap = 2 };
struct Message {
	char *nick;
	char *cmd;
	char *params[ParamCap];
};

static struct Message parse(char *line) {
	if (verbose) fprintf(stderr, "%s\n", line);
	struct Message msg = {0};
	if (line[0] == ':') {
		char *origin = 1 + strsep(&line, " ");
		msg.nick = strsep(&origin, "!");
	}
	msg.cmd = strsep(&line, " ");
	for (size_t i = 0; line && i < ParamCap; ++i) {
		if (line[0] == ':') {
			msg.params[i] = &line[1];
			break;
		}
		msg.params[i] = strsep(&line, " ");
	}
	return msg;
}

static void require(const struct Message *msg, bool nick, size_t len) {
	if (nick && !msg->nick) errx(EX_PROTOCOL, "%s missing origin", msg->cmd);
	for (size_t i = 0; i < len; ++i) {
		if (msg->params[i]) continue;
		errx(EX_PROTOCOL, "%s missing parameter %zu", msg->cmd, 1 + i);
	}
}

typedef void Handler(struct Message *msg);

static void handlePing(struct Message *msg) {
	require(msg, false, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static void handleError(struct Message *msg) {
	require(msg, false, 1);
	errx(EX_UNAVAILABLE, "%s", msg->params[0]);
}

static const char *Boolean[] = {
	"no-names", "no-sts", "palaver", "sasl-external", "verbose",
};

static const char *Integer[] = {
	"local-port", "port", "queue-interval", "size",
};

// FIXME: local-pass needs to be validated for hash
// FIXME: sasl-plain needs to be validated for colon
static const char *String[] = {
	"away", "bind", "blind-req", "client-cert", "client-priv", "host", "join",
	"local-ca", "local-cert", "local-host", "local-pass", "local-path",
	"local-priv", "mode", "nick", "pass", "quit", "real", "sasl-plain", "save",
	"trust", "user",
};

// TODO: nick, user aren't safe until pounce can fall back in case
// they're invalid
static const char *Safe[] = {
	"away", "join", "local-pass", "mode", "nick", "no-names", "no-sts",
	"palaver", "quit", "real", "user",
};

static bool allowUnsafe;
static bool safe(const char *name) {
	if (allowUnsafe) return true;
	for (size_t i = 0; i < ARRAY_LEN(Safe); ++i) {
		if (!strcmp(Safe[i], name)) return true;
	}
	return false;
}

static bool exists(const char *name) {
	for (size_t i = 0; i < ARRAY_LEN(Boolean); ++i) {
		if (!strcmp(Boolean[i], name)) return true;
	}
	for (size_t i = 0; i < ARRAY_LEN(Integer); ++i) {
		if (!strcmp(Integer[i], name)) return true;
	}
	for (size_t i = 0; i < ARRAY_LEN(String); ++i) {
		if (!strcmp(String[i], name)) return true;
	}
	return false;
}

static const char *validate(const char *name, const char *value) {
	for (size_t i = 0; i < ARRAY_LEN(Boolean); ++i) {
		if (strcmp(Boolean[i], name)) continue;
		if (!safe(name)) return "cannot be set";
		return (value ? "does not take a value" : NULL);
	}
	for (size_t i = 0; i < ARRAY_LEN(Integer); ++i) {
		if (strcmp(Integer[i], name)) continue;
		if (!safe(name)) return "cannot be set";
		if (!value) return "requires a value";
		char *end;
		size_t n = strtoull(value, &end, 10);
		if (!*value || *end) return "must be an integer";
		if (!strcmp(name, "size") && (!n || n & (n-1))) {
			return "must be a power of two";
		}
		return NULL;
	}
	for (size_t i = 0; i < ARRAY_LEN(String); ++i) {
		if (strcmp(String[i], name)) continue;
		if (!safe(name)) return "cannot be set";
		return (value ? NULL : "requires a value");
	}
	return "is not an option";
}

static FILE *config;
static struct Config over;
static struct Config under;

static void handlePrivmsg(struct Message *msg) {
	require(msg, true, 2);
	if (strcmp(msg->nick, msg->params[0])) return;

	char *cmd = strsep(&msg->params[1], " ");
	char *name = strsep(&msg->params[1], " ");
	char *value = msg->params[1];

	if (!strcmp(cmd, "get")) {
		if (!name) {
			format("NOTICE %s :set: ", msg->nick);
			for (size_t i = 0; i < over.len; ++i) {
				if (!over.opts[i].set) continue;
				format("%s\2%s\2", (i ? ", " : ""), over.opts[i].name);
			}
			format("\r\nNOTICE %s :inherited: ", msg->nick);
			for (size_t i = 0; i < under.len; ++i) {
				format("%s\2%s\2", (i ? ", " : ""), under.opts[i].name);
			}
			format("\r\n");
			return;
		}
		if (!exists(name)) {
			format("NOTICE %s :\2%s\2 is not an option\r\n", msg->nick, name);
			return;
		}

		struct Option opt = configGet(&over, name);
		if (!opt.set) opt = configGet(&under, name);
		if (opt.set && opt.value) {
			format("NOTICE %s :\2%s\2 = %s\r\n", msg->nick, name, opt.value);
		} else if (opt.set) {
			format("NOTICE %s :\2%s\2 is set\r\n", msg->nick, name);
		} else {
			format("NOTICE %s :\2%s\2 is unset\r\n", msg->nick, name);
		}

	} else if (!strcmp(cmd, "set")) {
		if (!name) {
			format("NOTICE %s :options: ", msg->nick);
			if (allowUnsafe) {
				for (size_t i = 0; i < ARRAY_LEN(Boolean); ++i) {
					format("%s\2%s\2", (i ? ", " : ""), Boolean[i]);
				}
				for (size_t i = 0; i < ARRAY_LEN(Integer); ++i) {
					format(", \2%s\2", Integer[i]);
				}
				for (size_t i = 0; i < ARRAY_LEN(String); ++i) {
					format(", \2%s\2", String[i]);
				}
			} else {
				for (size_t i = 0; i < ARRAY_LEN(Safe); ++i) {
					format("%s\2%s\2", (i ? ", " : ""), Safe[i]);
				}
			}
			format("\r\n");
			return;
		}

		const char *error = validate(name, value);
		if (error) {
			format("NOTICE %s :\2%s\2 %s\r\n", msg->nick, name, error);
			return;
		}
		configSet(&over, name, value);
		configWrite(&over, config);
		format("NOTICE %s :\2%s\2 set\r\n", msg->nick, name);

	} else if (!strcmp(cmd, "unset")) {
		if (!name) {
			format("NOTICE %s :set: ", msg->nick);
			for (size_t i = 0; i < over.len; ++i) {
				if (!over.opts[i].set) continue;
				format("%s\2%s\2", (i ? ", " : ""), over.opts[i].name);
			}
			format("\r\n");
			return;
		}
		if (!exists(name)) {
			format("NOTICE %s :\2%s\2 is not an option\r\n", msg->nick, name);
			return;
		}
		if (!safe(name)) {
			format("NOTICE %s :\2%s\2 cannot be unset\r\n", msg->nick, name);
			return;
		}

		configUnset(&over, name);
		configWrite(&over, config);
		struct Option opt = configGet(&under, name);
		format(
			"NOTICE %s :\2%s\2 %s\r\n",
			msg->nick, name, (opt.set ? "inherited" : "unset")
		);

	} else if (!strcmp(cmd, "restart")) {
		format("QUIT :$pounce reloading configuration\r\n");
	}
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "ERROR", handleError },
	{ "PING", handlePing },
	{ "PRIVMSG", handlePrivmsg },
};

static void handle(struct Message *msg) {
	if (!msg->cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg->cmd, Handlers[i].cmd)) continue;
		Handlers[i].fn(msg);
		break;
	}
}

static void quit(int sig) {
	(void)sig;
	format("QUIT\r\n");
	tls_close(client);
	_exit(EX_OK);
}

int main(int argc, char *argv[]) {
	bool insecure = false;
	const char *cert = NULL;
	const char *priv = NULL;
	const char *host = NULL;
	const char *port = NULL;
	const char *pass = NULL;
	const char *trust = NULL;
	const char *user = "pounce-edit";

	for (int opt; 0 < (opt = getopt(argc, argv, "!ac:h:k:p:t:u:vw:"));) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'a': allowUnsafe = true;
			break; case 'c': cert = optarg;
			break; case 'h': host = optarg;
			break; case 'k': priv = optarg;
			break; case 'p': port = optarg;
			break; case 't': trust = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
			break; default:  return EX_USAGE;
		}
	}
	if (optind == argc) errx(EX_USAGE, "config required");

	for (int i = optind; i < argc-1; ++i) {
		configParse(&under, argv[i]);
	}
	configParse(&over, argv[argc-1]);
	config = configOpen(argv[argc-1], "r+");
	if (!config) exit(EX_NOINPUT);

	if (!host) {
		struct Option opt = configGet(&over, "local-host");
		if (!opt.set) opt = configGet(&under, "local-host");
		if (!opt.set || !opt.value) errx(EX_USAGE, "host required");
		host = opt.value;
	}
	if (!port) {
		struct Option opt = configGet(&over, "local-port");
		if (!opt.set) opt = configGet(&under, "local-port");
		if (opt.set && opt.value) {
			port = opt.value;
		} else {
			port = "6697";
		}
	}

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	int error;
	char path[PATH_MAX];
	if (trust) {
		tls_config_insecure_noverifyname(config);
		for (int i = 0; configPath(path, sizeof(path), trust, i); ++i) {
			error = tls_config_set_ca_file(config, path);
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", trust, tls_config_error(config));
	}
	if (cert) {
		for (int i = 0; configPath(path, sizeof(path), cert, i); ++i) {
			if (priv) {
				error = tls_config_set_cert_file(config, path);
			} else {
				error = tls_config_set_keypair_file(config, path, path);
			}
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", cert, tls_config_error(config));
	}
	if (priv) {
		for (int i = 0; configPath(path, sizeof(path), priv, i); ++i) {
			error = tls_config_set_key_file(config, path);
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", priv, tls_config_error(config));
	}

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
	tls_config_free(config);

	error = tls_connect(client, host, port);
	if (error) errx(EX_UNAVAILABLE, "tls_connect: %s", tls_error(client));

	if (pass) format("PASS :%s\r\n", pass);
	format(
		"CAP REQ :causal.agency/passive\r\n"
		"CAP END\r\n"
		"NICK *\r\n"
		"USER %s 0 * :pounce-edit\r\n",
		user
	);

	signal(SIGINT, quit);
	signal(SIGTERM, quit);

	size_t len = 0;
	char buf[8191 + 512];
	for (;;) {
		ssize_t ret = tls_read(client, &buf[len], sizeof(buf) - len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_read: %s", tls_error(client));
		if (!ret) errx(EX_PROTOCOL, "server closed connection");
		len += ret;

		char *line = buf;
		for (;;) {
			char *crlf = memmem(line, &buf[len] - line, "\r\n", 2);
			if (!crlf) break;
			*crlf = '\0';
			struct Message msg = parse(line);
			handle(&msg);
			line = crlf + 2;
		}
		len -= line - buf;
		memmove(buf, line, len);
	}
}
