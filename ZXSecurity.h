#ifndef ZX_SECURITY_H
#define ZX_SECURITY_H

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

static inline NSString *ZXDeobf(const uint8_t *enc, size_t len, uint8_t key) {
    if (!enc || len == 0) return @"";
    char *buf = (char *)malloc(len + 1);
    if (!buf) return @"";
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)(enc[i] ^ key ^ (uint8_t)((i * 7) & 0xFF));
    }
    buf[len] = '\0';
    NSString *res = [[NSString alloc] initWithBytes:buf length:len encoding:NSUTF8StringEncoding];
    memset(buf, 0, len);
    free(buf);
    return res ?: @"";
}

// XOR-encoded "http://138.249.138.78:9009" (key = 0x5A)
static inline NSString *ZXServerBaseURL(void) {
    static const uint8_t enc[] = {
        0x32, 0x29, 0x20, 0x3f, 0x7c, 0x56, 0x5f, 0x5a, 0x51, 0x5d, 0x32, 0x25, 0x3a, 0x38, 0x16, 0x02,
        0x19, 0x15, 0x0a, 0xe8, 0xee, 0xf3, 0xf9, 0xcb, 0xc2, 0xcc
    };
    return ZXDeobf(enc, sizeof(enc), 0x5A);
}

// XOR-encoded "http://138.249.138.78:9009/config" (key = 0x5A)
static inline NSString *ZXServerConfigURL(void) {
    static const uint8_t enc[] = {
        0x32, 0x29, 0x20, 0x3f, 0x7c, 0x56, 0x5f, 0x5a, 0x51, 0x5d, 0x32, 0x25, 0x3a, 0x38, 0x16, 0x02,
        0x19, 0x15, 0x0a, 0xe8, 0xee, 0xf3, 0xf9, 0xcb, 0xc2, 0xcc, 0xc3, 0x84, 0xf1, 0xff, 0xee, 0xea, 0xdd
    };
    return ZXDeobf(enc, sizeof(enc), 0x5A);
}

// XOR-encoded fallback key (key = 0x5A)
static inline NSString *ZXFallbackAuthKey(void) {
    static const uint8_t enc[] = {
        0x00,0x18,0x0c,0x62,0x0b,0x38,0x23,0x3f,0x27,0x37,0x31,0x2e,0x37,0x38,0x01,0x1e,
        0x78,0x62,0x6b,0x8b
    };
    return ZXDeobf(enc, sizeof(enc), 0x5A);
}

static inline BOOL ZXIsBeingDebugged(void) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if ((info.kp_proc.p_flag & 0x00000800) != 0) { // P_TRACED
            return YES;
        }
    }
    return NO;
}

static inline BOOL ZXHasTamperDylib(void) {
    const char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env && (strcasestr(env, "frida") || strcasestr(env, "substrate") ||
                strcasestr(env, "substitute") || strcasestr(env, "ellekit") ||
                strcasestr(env, "sslkillswitch") || strcasestr(env, "cycript"))) {
        return YES;
    }
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strcasestr(name, "frida") || strcasestr(name, "cycript") ||
            strcasestr(name, "sslkillswitch") || strcasestr(name, "objection") ||
            strcasestr(name, "cynject") || strcasestr(name, "libhooker") ||
            strcasestr(name, "ellekit") || strcasestr(name, "mobilesubstrate") ||
            strcasestr(name, "substitute") || strcasestr(name, "flexdecrypt")) {
            return YES;
        }
    }
    return NO;
}

static inline void ZXEnforceAntiTamper(void) {
    typedef int (*ptrace_fn)(int, pid_t, caddr_t, int);
    ptrace_fn fn_ptrace = (ptrace_fn)dlsym(RTLD_DEFAULT, "ptrace");
    if (fn_ptrace) {
        fn_ptrace(31, 0, 0, 0); // PT_DENY_ATTACH
    }
    if (ZXIsBeingDebugged() || ZXHasTamperDylib()) {
        _exit(0);
    }
}

static inline NSURLSession *ZXSecureSession(void) {
    static NSURLSession *session = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.connectionProxyDictionary = @{};
        cfg.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        cfg.URLCache = nil;
        session = [NSURLSession sessionWithConfiguration:cfg];
    });
    return session;
}

#endif
