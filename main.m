#import <UIKit/UIKit.h>
#import "ZXSecurity.h"

int main(int argc, char *argv[]) {
    ZXEnforceAntiTamper();
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, @"AppDelegate");
    }
}
