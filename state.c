/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "bounce.h"

static char *nick;

// TODO: Channels.

static struct {
	char *origin;
	char *welcome;
	char *yourHost;
	char *created;
	char *myInfo[4];
} intro;

enum { ISupportCap = 32 };
static struct {
	char *values[ISupportCap];
	size_t len;
} iSupport;

static void set(char **field, const char *value) {
	if (*field) free(*field);
	*field = strdup(value);
	if (!*field) err(EX_OSERR, "strdup");
}

static void iSupportSet(const char *value) {
	if (iSupport.len == ISupportCap) {
		warnx("truncating ISUPPORT value %s", value);
		return;
	}
	set(&iSupport.values[iSupport.len++], value);
}

bool stateReady(void) {
	return nick
		&& intro.origin
		&& intro.welcome
		&& intro.yourHost
		&& intro.created
		&& intro.myInfo[0]
		&& iSupport.len;
}

enum { ParamCap = 15 };
struct Command {
	const char *origin;
	const char *name;
	const char *params[ParamCap];
};
typedef void Handler(struct Command);

static void handleCap(struct Command cmd) {
	bool ack = cmd.params[1] && !strcmp(cmd.params[1], "ACK");
	bool sasl = cmd.params[2] && !strcmp(cmd.params[2], "sasl");
	if (!ack || !sasl) errx(EX_CONFIG, "server does not support SASL");
	serverAuth();
}

static void handleReplyWelcome(struct Command cmd) {
	if (!cmd.params[1]) errx(EX_PROTOCOL, "RPL_WELCOME without message");
	set(&intro.origin, cmd.origin);
	set(&nick, cmd.params[0]);
	set(&intro.welcome, cmd.params[1]);
}
static void handleReplyYourHost(struct Command cmd) {
	if (!cmd.params[1]) errx(EX_PROTOCOL, "RPL_YOURHOST without message");
	set(&intro.yourHost, cmd.params[1]);
}
static void handleReplyCreated(struct Command cmd) {
	if (!cmd.params[1]) errx(EX_PROTOCOL, "RPL_CREATED without message");
	set(&intro.created, cmd.params[1]);
}
static void handleReplyMyInfo(struct Command cmd) {
	if (!cmd.params[4]) errx(EX_PROTOCOL, "RPL_MYINFO without 4 parameters");
	set(&intro.myInfo[0], cmd.params[1]);
	set(&intro.myInfo[1], cmd.params[2]);
	set(&intro.myInfo[2], cmd.params[3]);
	set(&intro.myInfo[3], cmd.params[4]);
}

static void handleReplyISupport(struct Command cmd) {
	for (size_t i = 1; i < ParamCap; ++i) {
		if (!cmd.params[i] || strchr(cmd.params[i], ' ')) break;
		iSupportSet(cmd.params[i]);
	}
}

static void handleError(struct Command cmd) {
	errx(EX_UNAVAILABLE, "%s", cmd.params[0]);
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "001", handleReplyWelcome },
	{ "002", handleReplyYourHost },
	{ "003", handleReplyCreated },
	{ "004", handleReplyMyInfo },
	{ "005", handleReplyISupport },
	{ "CAP", handleCap },
	{ "ERROR", handleError },
};
static const size_t HandlersLen = sizeof(Handlers) / sizeof(Handlers[0]);

void stateParse(char *line) {
	struct Command cmd = {0};
	if (line[0] == ':') {
		cmd.origin = 1 + strsep(&line, " ");
		if (!line) errx(EX_PROTOCOL, "eof after origin");
	}

	cmd.name = strsep(&line, " ");
	for (size_t i = 0; line && i < ParamCap; ++i) {
		if (line[0] == ':') {
			cmd.params[i] = line;
			break;
		}
		cmd.params[i] = strsep(&line, " ");
	}

	for (size_t i = 0; i < HandlersLen; ++i) {
		if (strcmp(cmd.name, Handlers[i].cmd)) continue;
		Handlers[i].fn(cmd);
		break;
	}
}
