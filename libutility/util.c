/*
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <unistd.h>
#include <sys/time.h>
#include <float.h>
#include <stdint.h>
#include <errno.h>

#include "util.h"
#include "sha1.h"
#include <linux/tcp.h>

void print_buf(char *buf, int len)
{
	//return;
	int idx = 0;
	//print_info("buf len:%d\n", len);
	printf("buf len:%d\n", len);
	for (idx = 0; idx < len; idx++)
	{
		if (idx % 16 == 0)
		{
			//print_info("\n");
			printf("\n");
		}
		//print_info("0x%02X ", (unsigned char)buf[idx]);
		printf("0x%02X ", (unsigned char)buf[idx]);
	}
	//print_info("\n");
	printf("\n");
}

void os_thread_sleep(unsigned int tm)
{
#ifdef __WIN__
	Sleep((DWORD) tm / 1000);
#elif defined(__NETWARE__)
	delay(tm / 1000);
#else
	struct timeval  t;
	t.tv_sec = tm / 1000000;
	t.tv_usec = tm % 1000000;
	select(0, NULL, NULL, NULL, &t);
#endif
}

void trim(char ** s)
{
	char * begin = * s;
	char * end = * s + strlen(* s) - 1;

	while ((* begin == ' ') || (* begin == '\t'))
		begin ++;
	while ((* end == ' ') || (* end == '\t') || (* end == '\r') || (* end == '\n'))
		end --;
	* (end + 1) = 0;
	* s = begin;
}

bool str2mac(const char * str, unsigned char * mac)
{
	int bits;
	int i;

	memset(mac, 0, 6);
	for (i = 0;i < 12;i++)
	{
		bits = (i % 2)?0:4;
		if ((str[i] >= 48) && (str[i] <= 57))
			mac[i/2] |= ((str[i] - 48) << bits);
		else if ((str[i] >= 65) && (str[i] <= 70))
			mac[i/2] |= ((str[i] - 55) << bits);
		else if ((str[i] >= 97) && (str[i] <= 102))
			mac[i/2] |= ((str[i] - 87) << bits);
		else
			return false;
	}

	if (mac[0] & 0x01)
		return false;

	return true;
}

//	socket
static inline void set_socket_timeout(int s, unsigned int w_timeout, unsigned int r_timeout)
{
	struct timeval tv;
	tv.tv_sec = w_timeout;
	tv.tv_usec = 0;
	setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char *)&tv,sizeof(tv));
	tv.tv_sec = r_timeout;
	setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&tv,sizeof(tv));
}

static inline void set_socket_buff_size(int s, unsigned int w_size, unsigned int r_size)
{
	setsockopt(s,SOL_SOCKET,SO_SNDBUF,(char *)&w_size,sizeof(int));
	setsockopt(s,SOL_SOCKET,SO_RCVBUF,(char *)&r_size,sizeof(int));
}

static inline void disable_socket_linger(int s)
{
	struct linger linger;
	linger.l_onoff = 1;
	linger.l_linger = 0;
	setsockopt(s,SOL_SOCKET, SO_LINGER,(const char *)&linger,sizeof(linger));
}

static inline void set_socket_reuseaddr(int s)
{
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt));
}

static inline void set_socket_broadcast(int s)
{
	int opt = 1;
	setsockopt(s,SOL_SOCKET,SO_BROADCAST,(char *)&opt,sizeof(int));
}

static inline void set_socket_nodelay(int s)
{
	int opt = 1;
	int ret = -1;
	ret = setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&opt,sizeof(int));

	if (ret < 0)
	{
		printf("Couldn't setsockopt(TCP_NODELAY).\n");
	}
}

static inline void set_socket_nonblock(int s)
{
	fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
}

static inline void set_socket_ttl(int s, unsigned int ttl)
{
	setsockopt(s,IPPROTO_IP,IP_TTL,(char *)&ttl,sizeof(int));
}

static inline void set_socket_multicast(int s, unsigned char ttl, unsigned long ip)
{
	setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,(char *)&ttl,sizeof(ttl));
	setsockopt(s,IPPROTO_IP,IP_MULTICAST_IF,(char *)&ip,sizeof(int));
}

bool is_socket_writeable(int s, unsigned int ms)
{
	fd_set fds;
	struct timeval t;
	t.tv_sec = ms / 1000;
	t.tv_usec = ms % 1000;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	if (1 != select(s + 1, NULL, &fds, NULL, &t))
		return false;
	
	return true;
}

bool is_socket_readable(int s, unsigned int ms)
{
	fd_set fds;
	struct timeval t;
	t.tv_sec = ms / 1000;
	t.tv_usec = ms % 1000;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	if (1 != select(s + 1, &fds, NULL, NULL, &t))
		return false;
	
	return true;
}

unsigned long my_gethostbyname(const char * server)
{
	unsigned long ip;
	struct hostent host, * lphost;
	char * dnsbuffer;
	int rc;

	if (INADDR_NONE != (ip = inet_addr(server)))
		return ip;
	if (NULL == (dnsbuffer = (char *)zmalloc(8192)))
		return INADDR_NONE;
	if (gethostbyname_r(server, &host, dnsbuffer, 8192, &lphost, &rc) || (! lphost))
	{
		res_init();
		if (gethostbyname_r(server, &host, dnsbuffer, 8192, &lphost, &rc) || (! lphost))
		{
			printf("can not resolve ip of %s\n", server);
			ip = INADDR_NONE;
		}
		else
		{
			ip = ((struct in_addr *)(lphost->h_addr))->s_addr;
		}
	}
	else
	{
		ip = ((struct in_addr *)(lphost->h_addr))->s_addr;
	}

	zfree(dnsbuffer);
	return ip;
}

bool socket_connect(int s, const char * host, unsigned short port, unsigned int timeout)
{
	struct sockaddr_in addr;
	//struct hostent * lphost;
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (INADDR_NONE == (addr.sin_addr.s_addr = my_gethostbyname(host)))
		return false;
	/*if (INADDR_NONE == (addr.sin_addr.s_addr = inet_addr(host)))
	{
		lphost = gethostbyname(host);
		if (lphost != NULL)
		{
			addr.sin_addr.s_addr = ((struct in_addr *)(lphost->h_addr))->s_addr;
		}
		else
		{
			printf("%s: can not resolve ip of %s\n", __func__, host);
			return false;
		}
	}*/
	
	if (0 > connect(s, (struct sockaddr *)&addr, sizeof(addr))) 
	{
		printf("%s: can not connect to %s:%d\n", __func__, host, port);
		return false;
	}
	
	return true;
}

bool socket_send(int s, const char * data, unsigned int len)
{
	unsigned int offset = 0;
	int ret;
	
	while (len)
	{
		if (0 > (ret = send(s, data + offset, len, 0)))
		{
			printf("%s: error %d\n", __func__, ret);
			return false;
		}
		offset += ret;
		len -= ret;
	}
	
	return true;
}

bool socket_recv(int s, char * data, unsigned int len)
{
	unsigned int offset = 0;
	int ret;
	
	while (len)
	{
		if (0 > (ret = recv(s, data + offset, len, 0)))
		{
			printf("%s: error %d\n", __func__, ret);
			return false;
		}
		offset += ret;
		len -= ret;
	}
	
	return true;
}


bool create_msg_queue(MSG_CONTEXT * c, unsigned int size)
{
	int ls;
	struct sockaddr_in host;
	int len = sizeof(host);

	memset(c, 0, sizeof(MSG_CONTEXT));

	if (0 > (ls = socket(AF_INET, SOCK_STREAM, 0)))
	{
		printf("%s: can not create socket %d\n", __func__, ls);
		return false;
	}
	set_socket_reuseaddr(ls);
	host.sin_family = AF_INET;
	host.sin_addr.s_addr = inet_addr("127.0.0.1");
	host.sin_port = 0;
	if (0 > bind(ls,(struct sockaddr *)&host,sizeof(host)))
	{
		printf("%s: can not bind socket\n", __func__);
		close(ls);
		return false;
	}
	if (0 > getsockname(ls,(struct sockaddr *)&host,&len))
	{
		printf("%s: getsockname error\n", __func__);
		close(ls);
		return false;
	}
	listen(ls, 1);

	if (0 > (c->s_r = socket(AF_INET, SOCK_STREAM, 0)))
	{
		printf("%s: can not create socket %d\n", __func__, c->s_r);
		close(ls);
		return false;
	}
	set_socket_nonblock(c->s_r);
	connect(c->s_r, (const struct sockaddr *)&host, len);
	if (0 > (c->s_w = accept(ls, (struct sockaddr *)&host,&len)))
	{
		printf("%s: accept error %d\n", __func__, c->s_w);
		close(ls);
		close(c->s_r);
		return false;
	}
	close(ls);
	set_socket_buff_size(c->s_r, 1024, size);
	set_socket_buff_size(c->s_w, size, 1024);
	pthread_mutex_init(&c->mutex, NULL);

	return true;
}

void destroy_msg_queue(MSG_CONTEXT * c)
{
	pthread_mutex_destroy(&c->mutex);
	close(c->s_r);
	close(c->s_w);
	memset(c, 0, sizeof(MSG_CONTEXT));
}

bool post_msg(MSG_CONTEXT * c, MSG * msg)
{
	msg->magic = MSG_MAGIC;		
	pthread_mutex_lock(&c->mutex);
	if (! is_socket_writeable(c->s_w, 0))
	{
		pthread_mutex_unlock(&c->mutex);
		return false;
	}
	if (! socket_send(c->s_w, (const char *)msg, sizeof(MSG)))
	{
		pthread_mutex_unlock(&c->mutex);
		return false;
	}
	pthread_mutex_unlock(&c->mutex);
	return true;
}

bool send_msg(MSG_CONTEXT * c, MSG * msg)
{
	msg->magic = MSG_MAGIC;		
	pthread_mutex_lock(&c->mutex);
	if (! socket_send(c->s_w, (const char *)msg, sizeof(MSG)))
	{
		pthread_mutex_unlock(&c->mutex);
		return false;
	}
	pthread_mutex_unlock(&c->mutex);
	return true;
}

bool recv_msg(MSG_CONTEXT * c, MSG * msg)
{
	int ret, offset;
	unsigned int magic = MSG_MAGIC;

	if (0 > (ret = recv(c->s_r, c->buffer + c->len, sizeof(MSG) - c->len, 0)))
		return false;

	c->len += ret;
	if (c->len != sizeof(MSG))
		return false;

	for (offset = 0; offset < sizeof(MSG) - 4; offset ++)
	{
		if (0 == memcmp(c->buffer + offset, &magic, 4))
			break;
	}
	if (offset)
	{
		c->len -= offset;
		memcpy(c->buffer, c->buffer + offset, c->len);
		return false;
	}

	memcpy((char *)msg, c->buffer, sizeof(MSG));
	c->len = 0;
	return true;
}



/* Glob-style pattern matching. */
int stringmatchlen(const char *pattern, int patternLen,const char *string, int stringLen, int nocase)
{
    while(patternLen) {
        switch(pattern[0]) {
        case '*':
            while (pattern[1] == '*') {
                pattern++;
                patternLen--;
            }
            if (patternLen == 1)
                return 1; /* match */
            while(stringLen) {
                if (stringmatchlen(pattern+1, patternLen-1,
                            string, stringLen, nocase))
                    return 1; /* match */
                string++;
                stringLen--;
            }
            return 0; /* no match */
            break;
        case '?':
            if (stringLen == 0)
                return 0; /* no match */
            string++;
            stringLen--;
            break;
        case '[':
        {
            int not, match;

            pattern++;
            patternLen--;
            not = pattern[0] == '^';
            if (not) {
                pattern++;
                patternLen--;
            }
            match = 0;
            while(1) {
                if (pattern[0] == '\\') {
                    pattern++;
                    patternLen--;
                    if (pattern[0] == string[0])
                        match = 1;
                } else if (pattern[0] == ']') {
                    break;
                } else if (patternLen == 0) {
                    pattern--;
                    patternLen++;
                    break;
                } else if (pattern[1] == '-' && patternLen >= 3) {
                    int start = pattern[0];
                    int end = pattern[2];
                    int c = string[0];
                    if (start > end) {
                        int t = start;
                        start = end;
                        end = t;
                    }
                    if (nocase) {
                        start = tolower(start);
                        end = tolower(end);
                        c = tolower(c);
                    }
                    pattern += 2;
                    patternLen -= 2;
                    if (c >= start && c <= end)
                        match = 1;
                } else {
                    if (!nocase) {
                        if (pattern[0] == string[0])
                            match = 1;
                    } else {
                        if (tolower((int)pattern[0]) == tolower((int)string[0]))
                            match = 1;
                    }
                }
                pattern++;
                patternLen--;
            }
            if (not)
                match = !match;
            if (!match)
                return 0; /* no match */
            string++;
            stringLen--;
            break;
        }
        case '\\':
            if (patternLen >= 2) {
                pattern++;
                patternLen--;
            }
            /* fall through */
        default:
            if (!nocase) {
                if (pattern[0] != string[0])
                    return 0; /* no match */
            } else {
                if (tolower((int)pattern[0]) != tolower((int)string[0]))
                    return 0; /* no match */
            }
            string++;
            stringLen--;
            break;
        }
        pattern++;
        patternLen--;
        if (stringLen == 0) {
            while(*pattern == '*') {
                pattern++;
                patternLen--;
            }
            break;
        }
    }
    if (patternLen == 0 && stringLen == 0)
        return 1;
    return 0;
}

int stringmatch(const char *pattern, const char *string, int nocase) 
{
    return stringmatchlen(pattern,strlen(pattern),string,strlen(string),nocase);
}

/* Convert a string representing an amount of memory into the number of
 * bytes, so for instance memtoll("1Gb") will return 1073741824 that is
 * (1024*1024*1024).
 *
 * On parsing error, if *err is not NULL, it's set to 1, otherwise it's
 * set to 0. On error the function return value is 0, regardless of the
 * fact 'err' is NULL or not. */
long long memtoll(const char *p, int *err) {
    const char *u;
    char buf[128];
    long mul; /* unit multiplier */
    long long val;
    unsigned int digits;

    if (err) *err = 0;

    /* Search the first non digit character. */
    u = p;
    if (*u == '-') u++;
    while(*u && isdigit(*u)) u++;
    if (*u == '\0' || !strcasecmp(u,"b")) {
        mul = 1;
    } else if (!strcasecmp(u,"k")) {
        mul = 1000;
    } else if (!strcasecmp(u,"kb")) {
        mul = 1024;
    } else if (!strcasecmp(u,"m")) {
        mul = 1000*1000;
    } else if (!strcasecmp(u,"mb")) {
        mul = 1024*1024;
    } else if (!strcasecmp(u,"g")) {
        mul = 1000L*1000*1000;
    } else if (!strcasecmp(u,"gb")) {
        mul = 1024L*1024*1024;
    } else {
        if (err) *err = 1;
        return 0;
    }

    /* Copy the digits into a buffer, we'll use strtoll() to convert
     * the digit (without the unit) into a number. */
    digits = u-p;
    if (digits >= sizeof(buf)) {
        if (err) *err = 1;
        return 0;
    }
    memcpy(buf,p,digits);
    buf[digits] = '\0';

    char *endptr;
    errno = 0;
    val = strtoll(buf,&endptr,10);
    if ((val == 0 && errno == EINVAL) || *endptr != '\0') {
        if (err) *err = 1;
        return 0;
    }
    return val*mul;
}

/* Return the number of digits of 'v' when converted to string in radix 10.
 * See ll2string() for more information. */
uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

/* Like digits10() but for signed values. */
uint32_t sdigits10(int64_t v) {
    if (v < 0) {
        /* Abs value of LLONG_MIN requires special handling. */
        uint64_t uv = (v != LLONG_MIN) ?
                      (uint64_t)-v : ((uint64_t) LLONG_MAX)+1;
        return digits10(uv)+1; /* +1 for the minus. */
    } else {
        return digits10(v);
    }
}

/* Convert a long long into a string. Returns the number of
 * characters needed to represent the number.
 * If the buffer is not big enough to store the string, 0 is returned.
 *
 * Based on the following article (that apparently does not provide a
 * novel approach but only publicizes an already used technique):
 *
 * https://www.facebook.com/notes/facebook-engineering/three-optimization-tips-for-c/10151361643253920
 *
 * Modified in order to handle signed integers since the original code was
 * designed for unsigned integers. */
int ll2string(char* dst, size_t dstlen, long long svalue) {
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    int negative;
    unsigned long long value;

    /* The main loop works with 64bit unsigned integers for simplicity, so
     * we convert the number here and remember if it is negative. */
    if (svalue < 0) {
        if (svalue != LLONG_MIN) {
            value = -svalue;
        } else {
            value = ((unsigned long long) LLONG_MAX)+1;
        }
        negative = 1;
    } else {
        value = svalue;
        negative = 0;
    }

    /* Check length. */
    uint32_t const length = digits10(value)+negative;
    if (length >= dstlen) return 0;

    /* Null term. */
    uint32_t next = length;
    dst[next] = '\0';
    next--;
    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits. */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    } else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }

    /* Add sign. */
    if (negative) dst[0] = '-';
    return length;
}

/* Convert a string into a long long. Returns 1 if the string could be parsed
 * into a (non-overflowing) long long, 0 otherwise. The value will be set to
 * the parsed value when appropriate. */
int string2ll(const char *s, size_t slen, long long *value) {
    const char *p = s;
    size_t plen = 0;
    int negative = 0;
    unsigned long long v;

    if (plen == slen)
        return 0;

    /* Special case: first and only digit is 0. */
    if (slen == 1 && p[0] == '0') {
        if (value != NULL) *value = 0;
        return 1;
    }

    if (p[0] == '-') {
        negative = 1;
        p++; plen++;

        /* Abort on only a negative sign. */
        if (plen == slen)
            return 0;
    }

    /* First digit should be 1-9, otherwise the string should just be 0. */
    if (p[0] >= '1' && p[0] <= '9') {
        v = p[0]-'0';
        p++; plen++;
    } else if (p[0] == '0' && slen == 1) {
        *value = 0;
        return 1;
    } else {
        return 0;
    }

    while (plen < slen && p[0] >= '0' && p[0] <= '9') {
        if (v > (ULLONG_MAX / 10)) /* Overflow. */
            return 0;
        v *= 10;

        if (v > (ULLONG_MAX - (p[0]-'0'))) /* Overflow. */
            return 0;
        v += p[0]-'0';

        p++; plen++;
    }

    /* Return if not all bytes were used. */
    if (plen < slen)
        return 0;

    if (negative) {
        if (v > ((unsigned long long)(-(LLONG_MIN+1))+1)) /* Overflow. */
            return 0;
        if (value != NULL) *value = -v;
    } else {
        if (v > LLONG_MAX) /* Overflow. */
            return 0;
        if (value != NULL) *value = v;
    }
    return 1;
}

/* Convert a string into a long. Returns 1 if the string could be parsed into a
 * (non-overflowing) long, 0 otherwise. The value will be set to the parsed
 * value when appropriate. */
int string2l(const char *s, size_t slen, long *lval) {
    long long llval;

    if (!string2ll(s,slen,&llval))
        return 0;

    if (llval < LONG_MIN || llval > LONG_MAX)
        return 0;

    *lval = (long)llval;
    return 1;
}

/* Convert a double to a string representation. Returns the number of bytes
 * required. The representation should always be parsable by strtod(3). */
int d2string(char *buf, size_t len, double value) {
    if (isnan(value)) {
        len = snprintf(buf,len,"nan");
    } else if (isinf(value)) {
        if (value < 0)
            len = snprintf(buf,len,"-inf");
        else
            len = snprintf(buf,len,"inf");
    } else if (value == 0) {
        /* See: http://en.wikipedia.org/wiki/Signed_zero, "Comparisons". */
        if (1.0/value < 0)
            len = snprintf(buf,len,"-0");
        else
            len = snprintf(buf,len,"0");
    } else {
#if (DBL_MANT_DIG >= 52) && (LLONG_MAX == 0x7fffffffffffffffLL)
        /* Check if the float is in a safe range to be casted into a
         * long long. We are assuming that long long is 64 bit here.
         * Also we are assuming that there are no implementations around where
         * double has precision < 52 bit.
         *
         * Under this assumptions we test if a double is inside an interval
         * where casting to long long is safe. Then using two castings we
         * make sure the decimal part is zero. If all this is true we use
         * integer printing function that is much faster. */
        double min = -4503599627370495; /* (2^52)-1 */
        double max = 4503599627370496; /* -(2^52) */
        if (value > min && value < max && value == ((double)((long long)value)))
            len = ll2string(buf,len,(long long)value);
        else
#endif
            len = snprintf(buf,len,"%.17g",value);
    }

    return len;
}

/* Generate the Redis "Run ID", a SHA1-sized random number that identifies a
 * given execution of Redis, so that if you are talking with an instance
 * having run_id == A, and you reconnect and it has run_id == B, you can be
 * sure that it is either a different instance or it was restarted. */
void getRandomHexChars(char *p, unsigned int len) {
    char *charset = "0123456789abcdef";
    unsigned int j;

    /* Global state. */
    static int seed_initialized = 0;
    static unsigned char seed[20]; /* The SHA1 seed, from /dev/urandom. */
    static uint64_t counter = 0; /* The counter we hash with the seed. */

    if (!seed_initialized) {
        /* Initialize a seed and use SHA1 in counter mode, where we hash
         * the same seed with a progressive counter. For the goals of this
         * function we just need non-colliding strings, there are no
         * cryptographic security needs. */
        FILE *fp = fopen("/dev/urandom","r");
        if (fp && fread(seed,sizeof(seed),1,fp) == 1)
            seed_initialized = 1;
        if (fp) fclose(fp);
    }

    if (seed_initialized) {
        while(len) {
            unsigned char digest[20];
            SHA1_CTX ctx;
            unsigned int copylen = len > 20 ? 20 : len;

            SHA1Init(&ctx);
            SHA1Update(&ctx, seed, sizeof(seed));
            SHA1Update(&ctx, (unsigned char*)&counter,sizeof(counter));
            SHA1Final(digest, &ctx);
            counter++;

            memcpy(p,digest,copylen);
            /* Convert to hex digits. */
            for (j = 0; j < copylen; j++) p[j] = charset[p[j] & 0x0F];
            len -= copylen;
            p += copylen;
        }
    } else {
        /* If we can't read from /dev/urandom, do some reasonable effort
         * in order to create some entropy, since this function is used to
         * generate run_id and cluster instance IDs */
        char *x = p;
        unsigned int l = len;
        struct timeval tv;
        pid_t pid = getpid();

        /* Use time and PID to fill the initial array. */
        gettimeofday(&tv,NULL);
        if (l >= sizeof(tv.tv_usec)) {
            memcpy(x,&tv.tv_usec,sizeof(tv.tv_usec));
            l -= sizeof(tv.tv_usec);
            x += sizeof(tv.tv_usec);
        }
        if (l >= sizeof(tv.tv_sec)) {
            memcpy(x,&tv.tv_sec,sizeof(tv.tv_sec));
            l -= sizeof(tv.tv_sec);
            x += sizeof(tv.tv_sec);
        }
        if (l >= sizeof(pid)) {
            memcpy(x,&pid,sizeof(pid));
            l -= sizeof(pid);
            x += sizeof(pid);
        }
        /* Finally xor it with rand() output, that was already seeded with
         * time() at startup, and convert to hex digits. */
        for (j = 0; j < len; j++) {
            p[j] ^= rand();
            p[j] = charset[p[j] & 0x0F];
        }
    }
}

/* Given the filename, return the absolute path as an SDS string, or NULL
 * if it fails for some reason. Note that "filename" may be an absolute path
 * already, this will be detected and handled correctly.
 *
 * The function does not try to normalize everything, but only the obvious
 * case of one or more "../" appearning at the start of "filename"
 * relative path. */
sds getAbsolutePath(char *filename) {
    char cwd[1024];
    sds abspath;
    sds relpath = sdsnew(filename);

    relpath = sdstrim(relpath," \r\n\t");
    if (relpath[0] == '/') return relpath; /* Path is already absolute. */

    /* If path is relative, join cwd and relative path. */
    if (getcwd(cwd,sizeof(cwd)) == NULL) {
        sdsfree(relpath);
        return NULL;
    }
    abspath = sdsnew(cwd);
    if (sdslen(abspath) && abspath[sdslen(abspath)-1] != '/')
        abspath = sdscat(abspath,"/");

    /* At this point we have the current path always ending with "/", and
     * the trimmed relative path. Try to normalize the obvious case of
     * trailing ../ elements at the start of the path.
     *
     * For every "../" we find in the filename, we remove it and also remove
     * the last element of the cwd, unless the current cwd is "/". */
    while (sdslen(relpath) >= 3 &&
           relpath[0] == '.' && relpath[1] == '.' && relpath[2] == '/')
    {
        sdsrange(relpath,3,-1);
        if (sdslen(abspath) > 1) {
            char *p = abspath + sdslen(abspath)-2;
            int trimlen = 1;

            while(*p != '/') {
                p--;
                trimlen++;
            }
            sdsrange(abspath,0,-(trimlen+1));
        }
    }

    /* Finally glue the two parts together. */
    abspath = sdscatsds(abspath,relpath);
    sdsfree(relpath);
    return abspath;
}

/* Return true if the specified path is just a file basename without any
 * relative or absolute path. This function just checks that no / or \
 * character exists inside the specified path, that's enough in the
 * environments where Redis runs. */
int pathIsBaseName(char *path) {
    return strchr(path,'/') == NULL && strchr(path,'\\') == NULL;
}

#ifdef MY_TEST
#include <assert.h>

static void test_string2ll(void) {
    char buf[32];
    long long v;

    /* May not start with +. */
    strcpy(buf,"+1");
    assert(string2ll(buf,strlen(buf),&v) == 0);

    /* Leading space. */
    strcpy(buf," 1");
    assert(string2ll(buf,strlen(buf),&v) == 0);

    /* Trailing space. */
    strcpy(buf,"1 ");
    assert(string2ll(buf,strlen(buf),&v) == 0);

    /* May not start with 0. */
    strcpy(buf,"01");
    assert(string2ll(buf,strlen(buf),&v) == 0);

    strcpy(buf,"-1");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == -1);

    strcpy(buf,"0");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == 0);

    strcpy(buf,"1");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == 1);

    strcpy(buf,"99");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == 99);

    strcpy(buf,"-99");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == -99);

    strcpy(buf,"-9223372036854775808");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == LLONG_MIN);

    strcpy(buf,"-9223372036854775809"); /* overflow */
    assert(string2ll(buf,strlen(buf),&v) == 0);

    strcpy(buf,"9223372036854775807");
    assert(string2ll(buf,strlen(buf),&v) == 1);
    assert(v == LLONG_MAX);

    strcpy(buf,"9223372036854775808"); /* overflow */
    assert(string2ll(buf,strlen(buf),&v) == 0);
}

static void test_string2l(void) {
    char buf[32];
    long v;

    /* May not start with +. */
    strcpy(buf,"+1");
    assert(string2l(buf,strlen(buf),&v) == 0);

    /* May not start with 0. */
    strcpy(buf,"01");
    assert(string2l(buf,strlen(buf),&v) == 0);

    strcpy(buf,"-1");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == -1);

    strcpy(buf,"0");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == 0);

    strcpy(buf,"1");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == 1);

    strcpy(buf,"99");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == 99);

    strcpy(buf,"-99");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == -99);

#if LONG_MAX != LLONG_MAX
    strcpy(buf,"-2147483648");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == LONG_MIN);

    strcpy(buf,"-2147483649"); /* overflow */
    assert(string2l(buf,strlen(buf),&v) == 0);

    strcpy(buf,"2147483647");
    assert(string2l(buf,strlen(buf),&v) == 1);
    assert(v == LONG_MAX);

    strcpy(buf,"2147483648"); /* overflow */
    assert(string2l(buf,strlen(buf),&v) == 0);
#endif
}

static void test_ll2string(void) {
    char buf[32];
    long long v;
    int sz;

    v = 0;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 1);
    assert(!strcmp(buf, "0"));

    v = -1;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 2);
    assert(!strcmp(buf, "-1"));

    v = 99;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 2);
    assert(!strcmp(buf, "99"));

    v = -99;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 3);
    assert(!strcmp(buf, "-99"));

    v = -2147483648;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 11);
    assert(!strcmp(buf, "-2147483648"));

    v = LLONG_MIN;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 20);
    assert(!strcmp(buf, "-9223372036854775808"));

    v = LLONG_MAX;
    sz = ll2string(buf, sizeof buf, v);
    assert(sz == 19);
    assert(!strcmp(buf, "9223372036854775807"));
}

#define UNUSED(x) (void)(x)
int utilTest(int argc, char **argv) {
    UNUSED(argc);
    UNUSED(argv);

    test_string2ll();
    test_string2l();
    test_ll2string();
    return 0;
}
#endif
