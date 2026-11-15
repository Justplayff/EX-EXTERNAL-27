#import "AppDelegate.h"
#import "FFKernelExploit.h"
#import "FFWorseQuery.h"
#import "ZEXFileService.h"
#import "ZEXInjectorVC.h"
#import "ZXSecurity.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    ZXEnforceAntiTamper();
    
    // Initialize new worse_query / FFKernelExploit backend
    FFKernelExploitPrepareAsync();
    ZXPrewarmContainersAsync();
    
    UIColor *bg = [UIColor colorWithRed:.04 green:.01 blue:.02 alpha:1];
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.backgroundColor = bg;
    ZEXInjectorVC *vc = [[ZEXInjectorVC alloc] init];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    self.window.backgroundColor = bg;
    return YES;
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    ZXEnforceAntiTamper();
}

@end
