/* Copyright (C) 2019  June McEnroe <june@causal.agency>
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>

#include "bounce.h"

bool stateNoNames;
enum Cap stateCaps;
char *stateAccount;
bool stateAway;

typedef void Handler(struct Message *msg);

static void require(const struct Message *msg, bool origin, size_t len) {
	if (origin && !msg->origin) {
		errx(EX_PROTOCOL, "%s missing origin", msg->cmd);
	}
	for (size_t i = 0; i < len; ++i) {
		if (msg->params[i]) continue;
		errx(EX_PROTOCOL, "%s missing parameter %zu", msg->cmd, 1 + i);
	}
}

// Maximum size of one AUTHENTICATE message.
enum { AuthLen = 299 };
static char plainBase64[BASE64_SIZE(AuthLen)];

void stateLogin(
	const char *pass, enum Cap blind, const char *plain,
	const char *nick, const char *user, const char *real
) {
	if (plain) {
		byte buf[AuthLen] = {0};
		size_t len = 1 + strlen(plain);
		if (len > sizeof(buf)) errx(EX_USAGE, "SASL PLAIN too long");
		memcpy(&buf[1], plain, len - 1);
		byte *sep = memchr(buf, ':', len);
		if (!sep) errx(EX_USAGE, "SASL PLAIN missing colon");
		*sep = 0;
		base64(plainBase64, buf, len);
		explicit_bzero(buf, len);
	}

	serverFormat("CAP LS 302\r\n");
	if (pass) serverFormat("PASS :%s\r\n", pass);
	if (blind) serverFormat("CAP REQ :%s\r\n", capList(blind, NULL));
	serverFormat("NICK %s\r\n", nick);
	serverFormat("USER %s 0 * :%s\r\n", user, real);
}

static const enum Cap DontReq = 0
	| CapConsumer
	| CapPalaverApp
	| CapPassive
	| CapReadMarker
	| CapSASL
	| CapSTS
	| CapUnsupported;

static void handleCap(struct Message *msg) {
	require(msg, false, 3);
	enum Cap caps;
	if (!strcmp(msg->params[2], "*") && msg->params[3]) {
		caps = capParse(msg->params[3], NULL);
	} else {
		caps = capParse(msg->params[2], NULL);
	}

	if (!strcmp(msg->params[1], "LS") || !strcmp(msg->params[1], "NEW")) {
		caps &= ~DontReq;
		if (caps & CapEchoMessage && !(caps & CapLabeledResponse)) {
			caps &= ~CapEchoMessage;
		}
		if (caps) {
			serverFormat("CAP REQ :%s\r\n", capList(caps, NULL));
		} else {
			if (!(stateCaps & CapSASL)) serverFormat("CAP END\r\n");
		}

	} else if (!strcmp(msg->params[1], "ACK")) {
		stateCaps |= caps;
		if (caps & CapSASL) {
			serverFormat(
				"AUTHENTICATE %s\r\n", (plainBase64[0] ? "PLAIN" : "EXTERNAL")
			);
		}
		if (!(stateCaps & CapSASL)) serverFormat("CAP END\r\n");

	} else if (!strcmp(msg->params[1], "DEL")) {
		stateCaps &= ~caps;

	} else if (!strcmp(msg->params[1], "NAK")) {
		errx(EX_CONFIG, "server does not support %s", msg->params[2]);
	}
}

static void handleAuthenticate(struct Message *msg) {
	(void)msg;
	if (plainBase64[0]) {
		serverFormat("AUTHENTICATE %s\r\n", plainBase64);
		explicit_bzero(plainBase64, sizeof(plainBase64));
	} else {
		serverFormat("AUTHENTICATE +\r\n");
	}
}

static void handleReplyLoggedIn(struct Message *msg) {
	require(msg, false, 3);
	set(&stateAccount, msg->params[2]);
	serverFormat("CAP END\r\n");
}

static void handleErrorSASLFail(struct Message *msg) {
	require(msg, false, 2);
	errx(EX_CONFIG, "%s", msg->params[1]);
}

static struct {
	char *nick;
	char *origin;
} self;

static struct {
	char *origin;
	char *welcome;
	char *yourHost;
	char *created;
	char *myInfo[5];
} intro;

const char *stateNick(void) {
	return (self.nick ? self.nick : "*");
}

const char *stateEcho(void) {
	return (self.origin ? self.origin : stateNick());
}

bool stateReady(void) {
	return self.nick
		&& intro.origin
		&& intro.welcome
		&& intro.yourHost
		&& intro.created
		&& intro.myInfo[0];
}

static void handleErrorNicknameInUse(struct Message *msg) {
	if (self.nick) return;
	require(msg, false, 2);
	serverFormat("NICK %s_\r\n", msg->params[1]);
}

static void handleReplyWelcome(struct Message *msg) {
	require(msg, true, 2);
	set(&intro.origin, msg->origin);
	set(&self.nick, msg->params[0]);
	set(&intro.welcome, msg->params[1]);
}

static void handleReplyYourHost(struct Message *msg) {
	require(msg, false, 2);
	set(&intro.yourHost, msg->params[1]);
}

static void handleReplyCreated(struct Message *msg) {
	require(msg, false, 2);
	set(&intro.created, msg->params[1]);
}

static void handleReplyMyInfo(struct Message *msg) {
	require(msg, false, 5);
	set(&intro.myInfo[0], msg->params[1]);
	set(&intro.myInfo[1], msg->params[2]);
	set(&intro.myInfo[2], msg->params[3]);
	set(&intro.myInfo[3], msg->params[4]);
	if (msg->params[5]) set(&intro.myInfo[4], msg->params[5]);
}

static struct {
	bool done;
	char **tokens;
	size_t cap, len;
} support;

static void supportAdd(const char *token) {
	if (support.len == support.cap) {
		support.cap = (support.cap ? support.cap * 2 : 8);
		support.tokens = realloc(support.tokens, sizeof(char *) * support.cap);
		if (!support.tokens) err(EX_OSERR, "realloc");
	}
	support.tokens[support.len] = strdup(token);
	if (!support.tokens[support.len]) err(EX_OSERR, "strdup");
	support.len++;
}

static void handleReplyISupport(struct Message *msg) {
	require(msg, false, 1);
	if (support.done) return;
	for (size_t i = 1; i < ParamCap; ++i) {
		if (!msg->params[i] || strchr(msg->params[i], ' ')) break;
		supportAdd(msg->params[i]);
	}
}

static void handleReplyMOTDStart(struct Message *msg) {
	(void)msg;
	support.done = true;
}

struct Channel {
	char *name;
	char *topic;
};

static struct {
	struct Channel *ptr;
	size_t cap, len;
} chans;

static void chanAdd(const char *name) {
	if (chans.len == chans.cap) {
		chans.cap = (chans.cap ? chans.cap * 2 : 8);
		chans.ptr = realloc(chans.ptr, sizeof(*chans.ptr) * chans.cap);
		if (!chans.ptr) err(EX_OSERR, "realloc");
	}
	struct Channel *chan = &chans.ptr[chans.len++];
	chan->name = strdup(name);
	if (!chan->name) err(EX_OSERR, "strdup");
	chan->topic = NULL;
}

static void chanTopic(const char *name, const char *topic) {
	for (size_t i = 0; i < chans.len; ++i) {
		if (strcmp(chans.ptr[i].name, name)) continue;
		set(&chans.ptr[i].topic, topic);
		break;
	}
}

static void chanRemove(const char *name) {
	for (size_t i = 0; i < chans.len; ++i) {
		if (strcmp(chans.ptr[i].name, name)) continue;
		free(chans.ptr[i].name);
		free(chans.ptr[i].topic);
		chans.ptr[i] = chans.ptr[--chans.len];
		break;
	}
}

static bool originSelf(const char *origin) {
	if (!self.nick) return false;

	size_t len = strlen(self.nick);
	if (strlen(origin) < len) return false;
	if (strncmp(origin, self.nick, len)) return false;
	if (origin[len] && origin[len] != '!') return false;

	if (origin[len] && (!self.origin || strcmp(self.origin, origin))) {
		set(&self.origin, origin);
	}
	return true;
}

static void handleNick(struct Message *msg) {
	require(msg, true, 1);
	if (!originSelf(msg->origin)) return;
	set(&self.nick, msg->params[0]);

	if (!self.origin) return;
	char *rest = strchr(self.origin, '!');
	assert(rest);
	size_t size = strlen(self.nick) + strlen(rest) + 1;
	char *origin = malloc(size);
	if (!origin) err(EX_OSERR, "malloc");
	snprintf(origin, size, "%s%s", self.nick, rest);
	free(self.origin);
	self.origin = origin;
}

static void handleJoin(struct Message *msg) {
	require(msg, true, 1);
	if (originSelf(msg->origin)) chanAdd(msg->params[0]);
}

static void handlePart(struct Message *msg) {
	require(msg, true, 1);
	if (originSelf(msg->origin)) chanRemove(msg->params[0]);
}

static void handleKick(struct Message *msg) {
	require(msg, false, 2);
	if (self.nick && !strcmp(msg->params[1], self.nick)) {
		chanRemove(msg->params[0]);
	}
}

static void handleTopic(struct Message *msg) {
	require(msg, false, 2);
	chanTopic(msg->params[0], msg->params[1]);
}

static void handleReplyTopic(struct Message *msg) {
	require(msg, false, 3);
	chanTopic(msg->params[1], msg->params[2]);
}

static void handleReplyUnaway(struct Message *msg) {
	(void)msg;
	stateAway = false;
}

static void handleReplyNowAway(struct Message *msg) {
	(void)msg;
	stateAway = true;
}

static void handleError(struct Message *msg) {
	require(msg, false, 1);
	errx(EX_UNAVAILABLE, "%s", msg->params[0]);
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
	{ "305", handleReplyUnaway },
	{ "306", handleReplyNowAway },
	{ "332", handleReplyTopic },
	{ "375", handleReplyMOTDStart },
	{ "422", handleReplyMOTDStart },
	{ "433", handleErrorNicknameInUse },
	{ "437", handleErrorNicknameInUse },
	{ "900", handleReplyLoggedIn },
	{ "904", handleErrorSASLFail },
	{ "905", handleErrorSASLFail },
	{ "906", handleErrorSASLFail },
	{ "AUTHENTICATE", handleAuthenticate },
	{ "CAP", handleCap },
	{ "ERROR", handleError },
	{ "JOIN", handleJoin },
	{ "KICK", handleKick },
	{ "NICK", handleNick },
	{ "PART", handlePart },
	{ "TOPIC", handleTopic },
};

void stateParse(char *line) {
	struct Message msg = parse(line);
	if (!msg.cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		Handlers[i].fn(&msg);
		break;
	}
}

void stateSync(struct Client *client) {
	assert(stateReady());

	clientFormat(
		client,
		":%s NOTICE %s :"
		"pounce is GPLv3 fwee softwawe ^w^  code is avaiwable fwom %s\r\n",
		clientOrigin, self.nick, SOURCE_URL
	);

	if (stateAccount) {
		clientFormat(
			client, ":%s 900 %s %s %s :You are now logged in as %s\r\n",
			clientOrigin, self.nick, stateEcho(), stateAccount, stateAccount
		);
	}

	clientFormat(
		client, ":%s 001 %s :%s\r\n",
		intro.origin, self.nick, intro.welcome
	);
	clientFormat(
		client, ":%s 002 %s :%s\r\n",
		intro.origin, self.nick, intro.yourHost
	);
	clientFormat(
		client, ":%s 003 %s :%s\r\n",
		intro.origin, self.nick, intro.created
	);
	clientFormat(
		client, ":%s 004 %s %s %s %s %s%s%s\r\n",
		intro.origin, self.nick,
		intro.myInfo[0], intro.myInfo[1], intro.myInfo[2], intro.myInfo[3],
		(intro.myInfo[4] ? " " : ""), (intro.myInfo[4] ? intro.myInfo[4] : "")
	);

	size_t i;
	for (i = 0; support.len - i >= 13; i += 13) {
		clientFormat(
			client,
			":%s 005 %s"
			" %s %s %s %s %s %s %s %s %s %s %s %s %s"
			" :are supported by this server\r\n",
			intro.origin, self.nick,
			support.tokens[i + 0], support.tokens[i + 1],
			support.tokens[i + 2], support.tokens[i + 3],
			support.tokens[i + 4], support.tokens[i + 5],
			support.tokens[i + 6], support.tokens[i + 7],
			support.tokens[i + 8], support.tokens[i + 9],
			support.tokens[i + 10], support.tokens[i + 11],
			support.tokens[i + 12]
		);
	}
	if (i < support.len) {
		char buf[512], *ptr = buf, *end = &buf[sizeof(buf)];
		ptr = seprintf(ptr, end, ":%s 005 %s", intro.origin, self.nick);
		for (; i < support.len; ++i) {
			ptr = seprintf(ptr, end, " %s", support.tokens[i]);
		}
		ptr = seprintf(ptr, end, " :are supported by this server\r\n");
		clientSend(client, buf, ptr - buf);
	}

	clientFormat(
		client, ":%s 422 %s :MOTD File is missing\r\n",
		clientOrigin, self.nick
	);

	if (chans.len) assert(self.origin);
	for (size_t i = 0; i < chans.len; ++i) {
		const struct Channel *chan = &chans.ptr[i];
		clientFormat(client, ":%s JOIN %s\r\n", self.origin, chan->name);
		if (chan->topic) {
			clientFormat(
				client, ":%s 332 %s %s :%s\r\n",
				clientOrigin, self.nick, chan->name, chan->topic
			);
		}
		if (client->caps & CapReadMarker) {
			clientGetMarker(client, chan->name);
		}
		if (stateNoNames) continue;
		serverEnqueue("NAMES %s\r\n", chan->name);
	}
}
