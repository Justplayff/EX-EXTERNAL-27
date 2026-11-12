#import "ZEXFileService.h"
#import "FFKernelExploit.h"
#import "FFWorseQuery.h"

@implementation ZEXFileService

+ (instancetype)shared {
    static ZEXFileService *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [ZEXFileService new]; });
    return inst;
}

- (instancetype)init {
    self = [super init];
    BOOL prepared = NO;
    if (FFWorseQuerySupported()) {
        prepared = FFWorseQueryPrepare();
    }
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    _virtualRoot = [docs stringByAppendingPathComponent:@"ZEXVirtualRoot"];
    _ready = prepared || FFKernelExploitHasSandboxAccess();
    return self;
}

- (void)createDirectories {
    if (FFWorseQuerySupported()) {
        FFWorseQueryPrepare();
    }
    if (!_virtualRoot.length) return;
    NSFileManager *fm = NSFileManager.defaultManager;
    for (NSString *dir in @[
        _virtualRoot,
        [_virtualRoot stringByAppendingPathComponent:@"[MHA-C2] App Data"],
        [_virtualRoot stringByAppendingPathComponent:@"[MHA-C12] System Data"],
    ]) {
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    }
}

@end
