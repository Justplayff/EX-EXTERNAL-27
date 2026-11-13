#import "ZEXInjectorVC.h"
#import "ZEXFileService.h"
#import "FFKernelExploit.h"
#import "FFWorseQuery.h"
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <QuartzCore/QuartzCore.h>
#import <ImageIO/ImageIO.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <zlib.h>

static NSString *const kServerBase    = @"http://213.199.53.54:9009";
static NSString *const kCfgURL        = @"http://213.199.53.54:9009/config";
static NSString *const kSavedKey      = @"zex_auth_key_v1";
static NSString *const kSaveKeyToggle = @"zex_save_key_toggle";
static NSString *const kKeyCreatedAt  = @"zex_key_created_at";
static NSString *const kKeyExpiresAt  = @"zex_key_expires_at";

static NSString* ZXGetHWID(void) {
    NSString *k = @"com.bankai.injector.hwid";
    NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:k];
    if (saved.length) return saved;
    NSString *vendor = [UIDevice currentDevice].identifierForVendor.UUIDString;
    if (!vendor.length) vendor = [[NSUUID UUID] UUIDString];
    NSString *hwid = [vendor stringByReplacingOccurrencesOfString:@"-" withString:@""].lowercaseString;
    [[NSUserDefaults standardUserDefaults] setObject:hwid forKey:k];
    [[NSUserDefaults standardUserDefaults] synchronize];
    return hwid;
}

#define ZXBg      [UIColor colorWithRed:.02 green:.02 blue:.03 alpha:1]
#define ZXRed     [UIColor colorWithRed:.95 green:.09 blue:.27 alpha:1]
#define ZXRedDim  [UIColor colorWithRed:.95 green:.09 blue:.27 alpha:.12]
#define ZXGlass   [UIColor colorWithWhite:1 alpha:.05]
#define ZXBorder  [UIColor colorWithWhite:1 alpha:.08]
#define ZXGray    [UIColor colorWithWhite:.5 alpha:1]
#define ZXGreen   [UIColor colorWithRed:.18 green:.84 blue:.40 alpha:1]

static NSMutableDictionary<NSString*,AVAudioPlayer*>*_gAudio;
static void ZXPlay(NSString*n){
    if(!_gAudio)_gAudio=[NSMutableDictionary dictionary];
    NSString*p=[[NSBundle mainBundle]pathForResource:n ofType:@"wav"];
    if(p){
        NSError*e=nil;AVAudioPlayer*pl=[[AVAudioPlayer alloc]initWithContentsOfURL:[NSURL fileURLWithPath:p] error:&e];
        if(pl&&!e){pl.volume=1;[_gAudio setObject:pl forKey:n];[pl play];return;}
    }
    if([n isEqualToString:@"remove"])AudioServicesPlaySystemSound(1104);
    else if([n isEqualToString:@"activate"])AudioServicesPlaySystemSound(1100);
    else AudioServicesPlaySystemSound(1057);
}
static UIView* ZXGlassView(CGFloat r){
    UIView*v=[UIView new];v.backgroundColor=ZXGlass;v.layer.cornerRadius=r;
    v.layer.masksToBounds=YES;v.layer.borderWidth=.7;v.layer.borderColor=ZXBorder.CGColor;return v;
}
static void ZXRedGlow(UIView*v,CGFloat r){
    v.layer.shadowColor=ZXRed.CGColor;v.layer.shadowOpacity=.3;
    v.layer.shadowRadius=r;v.layer.shadowOffset=CGSizeZero;
}
static void ZXAddTouchAnimation(UIButton *btn) {
    if (!btn) return;
    objc_setAssociatedObject(btn, "ZXTouchAnim", @"1", OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static BOOL ZXExtractZipFile(NSString *zipPath, NSString *destDir) {
    NSData *data = [NSData dataWithContentsOfFile:zipPath];
    if (!data || data.length < 22) return NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;
    
    // Find End of Central Directory (EOCD) signature 0x06054b50
    NSUInteger eocdPos = 0;
    for (NSInteger i = (NSInteger)len - 22; i >= 0; i--) {
        if (bytes[i] == 0x50 && bytes[i+1] == 0x4b && bytes[i+2] == 0x05 && bytes[i+3] == 0x06) {
            eocdPos = (NSUInteger)i;
            break;
        }
    }
    if (eocdPos == 0) return NO;
    
    uint16_t entriesCount = bytes[eocdPos + 10] | (bytes[eocdPos + 11] << 8);
    uint32_t cdOffset = bytes[eocdPos + 16] | (bytes[eocdPos + 17] << 8) | (bytes[eocdPos + 18] << 16) | (bytes[eocdPos + 19] << 24);
    
    NSUInteger curr = cdOffset;
    BOOL extractedAny = NO;
    for (uint16_t idx = 0; idx < entriesCount; idx++) {
        if (curr + 46 > len) break;
        if (bytes[curr] != 0x50 || bytes[curr+1] != 0x4b || bytes[curr+2] != 0x01 || bytes[curr+3] != 0x02) break;
        
        uint16_t compMethod = bytes[curr + 10] | (bytes[curr + 11] << 8);
        uint32_t compSize = bytes[curr + 20] | (bytes[curr + 21] << 8) | (bytes[curr + 22] << 16) | (bytes[curr + 23] << 24);
        uint32_t uncompSize = bytes[curr + 24] | (bytes[curr + 25] << 8) | (bytes[curr + 26] << 16) | (bytes[curr + 27] << 24);
        uint16_t nameLen = bytes[curr + 28] | (bytes[curr + 29] << 8);
        uint16_t extraLen = bytes[curr + 30] | (bytes[curr + 31] << 8);
        uint16_t commentLen = bytes[curr + 32] | (bytes[curr + 33] << 8);
        uint32_t localHeaderOffset = bytes[curr + 42] | (bytes[curr + 43] << 8) | (bytes[curr + 44] << 16) | (bytes[curr + 45] << 24);
        
        if (curr + 46 + nameLen > len) break;
        NSString *fileName = [[NSString alloc] initWithBytes:&bytes[curr + 46] length:nameLen encoding:NSUTF8StringEncoding];
        if (!fileName) fileName = [[NSString alloc] initWithBytes:&bytes[curr + 46] length:nameLen encoding:NSASCIIStringEncoding];
        
        curr += 46 + nameLen + extraLen + commentLen;
        
        if (!fileName.length || [fileName hasSuffix:@"/"] || [fileName containsString:@"__MACOSX"]) continue;
        
        // Locate local file header
        NSUInteger locHeader = localHeaderOffset;
        if (locHeader + 30 > len) continue;
        if (bytes[locHeader] != 0x50 || bytes[locHeader+1] != 0x4b || bytes[locHeader+2] != 0x03 || bytes[locHeader+3] != 0x04) continue;
        
        uint16_t locNameLen = bytes[locHeader + 26] | (bytes[locHeader + 27] << 8);
        uint16_t locExtraLen = bytes[locHeader + 28] | (bytes[locHeader + 29] << 8);
        NSUInteger fileDataPos = locHeader + 30 + locNameLen + locExtraLen;
        
        if (fileDataPos + compSize > len) continue;
        
        NSData *extractedData = nil;
        if (compMethod == 0) {
            extractedData = [NSData dataWithBytes:&bytes[fileDataPos] length:compSize];
        } else if (compMethod == 8) {
            NSMutableData *decomp = [NSMutableData dataWithLength:uncompSize];
            z_stream strm;
            memset(&strm, 0, sizeof(strm));
            strm.next_in = (Bytef *)&bytes[fileDataPos];
            strm.avail_in = (uInt)compSize;
            strm.next_out = (Bytef *)decomp.mutableBytes;
            strm.avail_out = (uInt)uncompSize;
            
            if (inflateInit2(&strm, -MAX_WBITS) == Z_OK) {
                int ret = inflate(&strm, Z_FINISH);
                inflateEnd(&strm);
                if (ret == Z_STREAM_END || ret == Z_OK) {
                    extractedData = decomp;
                }
            }
        }
        
        if (extractedData && extractedData.length > 0) {
            NSString *cleanName = fileName.lastPathComponent;
            NSString *outFilePath = [destDir stringByAppendingPathComponent:cleanName];
            BOOL wOk = [extractedData writeToFile:outFilePath options:NSDataWritingAtomic error:nil];
            if (!wOk) {
                wOk = [extractedData writeToFile:outFilePath options:0 error:nil];
            }
            if (wOk && [fm fileExistsAtPath:outFilePath]) {
                extractedAny = YES;
            }
        }
    }
    return extractedAny;
}

@interface ZXSlot : NSObject
@property NSInteger slotId;
@property NSString *name,*desc,*fileUrl,*fileName,*imageUrl;
@property NSString *ffthPath,*ffmaxPath,*subPath,*directPath;
@property BOOL locked;
@end
@implementation ZXSlot @end

@interface ZXConfig : NSObject
@property NSString *version,*telegram,*appName;
@property NSString *opt1Name,*opt2Name,*opt3Name,*opt4Name,*opt5Name;
@property NSString *rm1Name,*rm2Name,*rm1ffth,*rm1ffmax,*rm2ffth,*rm2ffmax;
@property NSArray<ZXSlot*>*opt1,*opt2,*opt3,*opt4,*opt5;
@property BOOL maintenance;
@property NSString *maintMsg;
@property NSString *officialChannel;
@property BOOL opt1Locked, opt2Locked, opt3Locked, opt4Locked, opt5Locked;
+(void)fetch:(void(^)(ZXConfig*,NSError*))cb;
@end
@implementation ZXConfig
+(ZXSlot*)slotFrom:(NSDictionary*)d{
    ZXSlot*s=[ZXSlot new];
    s.slotId=[d[@"id"]integerValue];
    s.name=d[@"name"]?:@"Slot";s.desc=d[@"description"]?:@"";
    
    NSString *rawFileUrl = d[@"fileUrl"]?:@"";
    if (rawFileUrl.length > 0) {
        rawFileUrl = [rawFileUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9008" withString:kServerBase];
        rawFileUrl = [rawFileUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9009" withString:kServerBase];
        rawFileUrl = [rawFileUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169" withString:kServerBase];
    }
    s.fileUrl = rawFileUrl;
    s.fileName=d[@"fileName"]?:@"file";
    
    NSString *rawImgUrl = d[@"imageUrl"]?:@"";
    if (rawImgUrl.length > 0) {
        rawImgUrl = [rawImgUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9008" withString:kServerBase];
        rawImgUrl = [rawImgUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9009" withString:kServerBase];
        rawImgUrl = [rawImgUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169" withString:kServerBase];
    }
    s.imageUrl = rawImgUrl;
    
    s.ffthPath=d[@"ffthPath"]?:@"";s.ffmaxPath=d[@"ffmaxPath"]?:@"";
    s.subPath=d[@"subPath"]?:@"";s.directPath=d[@"directPath"]?:@"";
    s.locked=[d[@"locked"]boolValue];
    return s;
}
+(void)fetch:(void(^)(ZXConfig*,NSError*))cb{
    NSString *tsUrl = [NSString stringWithFormat:@"%@?t=%ld", kCfgURL, (long)[[NSDate date] timeIntervalSince1970]];
    NSMutableURLRequest*req=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:tsUrl]];
    [req setCachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData];
    [req setValue:@"no-cache, no-store, must-revalidate" forHTTPHeaderField:@"Cache-Control"];
    [req setValue:@"no-cache" forHTTPHeaderField:@"Pragma"];
    [[[NSURLSession sharedSession]dataTaskWithRequest:req completionHandler:^(NSData*d,NSURLResponse*r,NSError*e){
        if(!d||e){dispatch_async(dispatch_get_main_queue(),^{cb(nil,e);});return;}
        NSDictionary*j=[NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if(!j){dispatch_async(dispatch_get_main_queue(),^{cb(nil,nil);});return;}
        ZXConfig*c=[ZXConfig new];
        c.version=j[@"version"]?:@"1.0";c.telegram=j[@"telegram"]?:@"";
        c.appName=j[@"appName"]?:@"ZEX EXTERNAL";
        c.opt1Name=j[@"option1Name"]?:@"OPTION 1";
        c.opt2Name=j[@"option2Name"]?:@"LOCATION";
        c.opt3Name=j[@"option3Name"]?:@"OPTION 3";
        c.opt4Name=j[@"option4Name"]?:@"OPTION 4";
        c.opt5Name=j[@"option5Name"]?:@"EXTRA";
        c.maintenance=[j[@"maintenance"]boolValue];
        c.maintMsg=j[@"maintenanceMessage"]?:j[@"message"]?:@"ipa is on maintenance wait for fix";
        c.officialChannel=j[@"officialChannel"]?:j[@"telegram"]?:@"https://whatsapp.com/channel/0029Vb7UASL3bbV7CzGzUb04";
        c.opt1Locked=[j[@"option1Locked"]boolValue];
        c.opt2Locked=[j[@"option2Locked"]boolValue];
        c.opt3Locked=[j[@"option3Locked"]boolValue];
        c.opt4Locked=[j[@"option4Locked"]boolValue];
        c.opt5Locked=[j[@"option5Locked"]boolValue];
        NSDictionary*r1=j[@"remove1"]?:@{};NSDictionary*r2=j[@"remove2"]?:@{};
        c.rm1Name=r1[@"name"]?:j[@"remove1Name"]?:@"RESTORE 1";
        c.rm2Name=r2[@"name"]?:j[@"remove2Name"]?:@"RESTORE 2";
        c.rm1ffth=r1[@"ffthPath"]?:@"";c.rm1ffmax=r1[@"ffmaxPath"]?:@"";
        c.rm2ffth=r2[@"ffthPath"]?:@"";c.rm2ffmax=r2[@"ffmaxPath"]?:@"";
        NSMutableArray*o1=[NSMutableArray array],*o2=[NSMutableArray array],*o3=[NSMutableArray array],*o4=[NSMutableArray array],*o5=[NSMutableArray array];
        for(NSDictionary*dd in j[@"option1Slots"]?:@[])[o1 addObject:[self slotFrom:dd]];
        for(NSDictionary*dd in j[@"option2Slots"]?:@[])[o2 addObject:[self slotFrom:dd]];
        for(NSDictionary*dd in j[@"option3Slots"]?:@[])[o3 addObject:[self slotFrom:dd]];
        for(NSDictionary*dd in j[@"option4Slots"]?:@[])[o4 addObject:[self slotFrom:dd]];
        for(NSDictionary*dd in j[@"option5Slots"]?:@[])[o5 addObject:[self slotFrom:dd]];
        c.opt1=o1;c.opt2=o2;c.opt3=o3;c.opt4=o4;c.opt5=o5;
        dispatch_async(dispatch_get_main_queue(),^{cb(c,nil);});
    }]resume];
}
@end

// ── ZXSlotCell ────────────────────────────────────────────────────
@interface ZXSlotCell : UITableViewCell
-(void)configure:(ZXSlot*)s idx:(NSInteger)idx;
-(void)setStatus:(NSString*)st color:(UIColor*)c;
@property (copy) void(^onToggle)(BOOL);
@property UISwitch*sw;
@property UILabel*statusLbl;
@end
@implementation ZXSlotCell {
    UILabel *_num, *_name, *_desc;
    UIView *_card, *_accentStrip, *_numBadge;
}
-(instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString*)r {
    self = [super initWithStyle:s reuseIdentifier:r];
    self.backgroundColor = UIColor.clearColor;
    self.selectionStyle = UITableViewCellSelectionStyleNone;
    
    _card = [UIView new];
    _card.translatesAutoresizingMaskIntoConstraints = NO;
    _card.layer.cornerRadius = 16;
    _card.layer.masksToBounds = NO;
    [self.contentView addSubview:_card];
    
    _accentStrip = [UIView new];
    _accentStrip.translatesAutoresizingMaskIntoConstraints = NO;
    _accentStrip.layer.cornerRadius = 2;
    _accentStrip.clipsToBounds = YES;
    [_card addSubview:_accentStrip];
    
    _numBadge = [UIView new];
    _numBadge.translatesAutoresizingMaskIntoConstraints = NO;
    _numBadge.layer.cornerRadius = 8;
    _numBadge.layer.borderWidth = 0.8;
    [_card addSubview:_numBadge];
    
    _num = [UILabel new];
    _num.translatesAutoresizingMaskIntoConstraints = NO;
    _num.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    [_numBadge addSubview:_num];
    
    _name = [UILabel new];
    _name.translatesAutoresizingMaskIntoConstraints = NO;
    _name.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    _name.textColor = UIColor.whiteColor;
    [_card addSubview:_name];
    
    _desc = [UILabel new];
    _desc.translatesAutoresizingMaskIntoConstraints = NO;
    _desc.font = [UIFont systemFontOfSize:11 weight:UIFontWeightRegular];
    _desc.textColor = [UIColor colorWithWhite:0.65 alpha:1.0];
    [_card addSubview:_desc];
    
    self.statusLbl = [UILabel new];
    self.statusLbl.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLbl.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    self.statusLbl.textColor = ZXGray;
    self.statusLbl.numberOfLines = 2;
    [_card addSubview:self.statusLbl];
    
    self.sw = [UISwitch new];
    self.sw.translatesAutoresizingMaskIntoConstraints = NO;
    self.sw.transform = CGAffineTransformMakeScale(0.78, 0.78);
    [self.sw addTarget:self action:@selector(swCh:) forControlEvents:UIControlEventValueChanged];
    [_card addSubview:self.sw];
    
    [NSLayoutConstraint activateConstraints:@[
        [_card.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:5],
        [_card.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-5],
        [_card.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:2],
        [_card.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-2],
        
        [_accentStrip.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:10],
        [_accentStrip.centerYAnchor constraintEqualToAnchor:_card.centerYAnchor],
        [_accentStrip.widthAnchor constraintEqualToConstant:4],
        [_accentStrip.heightAnchor constraintEqualToAnchor:_card.heightAnchor multiplier:0.65],
        
        [_numBadge.topAnchor constraintEqualToAnchor:_card.topAnchor constant:12],
        [_numBadge.trailingAnchor constraintEqualToAnchor:self.sw.leadingAnchor constant:-12],
        [_num.topAnchor constraintEqualToAnchor:_numBadge.topAnchor],
        [_num.bottomAnchor constraintEqualToAnchor:_numBadge.bottomAnchor],
        [_num.leadingAnchor constraintEqualToAnchor:_numBadge.leadingAnchor],
        [_num.trailingAnchor constraintEqualToAnchor:_numBadge.trailingAnchor],
        
        [_name.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:14],
        [_name.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
        [_name.trailingAnchor constraintEqualToAnchor:_numBadge.leadingAnchor constant:-6],
        
        [_desc.leadingAnchor constraintEqualToAnchor:_name.leadingAnchor],
        [_desc.topAnchor constraintEqualToAnchor:_name.bottomAnchor constant:2],
        [_desc.trailingAnchor constraintEqualToAnchor:self.sw.leadingAnchor constant:-8],
        
        [self.statusLbl.leadingAnchor constraintEqualToAnchor:_name.leadingAnchor],
        [self.statusLbl.topAnchor constraintEqualToAnchor:_desc.bottomAnchor constant:2],
        [self.statusLbl.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor constant:-8],
        
        [self.sw.centerYAnchor constraintEqualToAnchor:_card.centerYAnchor],
        [self.sw.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
    ]];
    return self;
}
-(void)configure:(ZXSlot*)s idx:(NSInteger)idx {
    _num.text = @"";
    _name.text = s.name;
    _desc.text = s.desc;
    self.sw.on = NO;
    self.sw.enabled = !s.locked;
    self.sw.alpha = s.locked ? 0.35 : 1.0;
    self.statusLbl.text = s.locked ? @"Locked" : @"";
    self.statusLbl.textColor = s.locked ? [UIColor colorWithRed:0.95 green:0.25 blue:0.35 alpha:1.0] : ZXGray;
    
    _accentStrip.hidden = YES;
    _card.backgroundColor = s.locked ? [UIColor colorWithRed:0.08 green:0.01 blue:0.02 alpha:0.75] : [UIColor colorWithRed:0.04 green:0.01 blue:0.02 alpha:0.65];
    _card.layer.borderColor = s.locked ? [UIColor colorWithRed:0.95 green:0.1 blue:0.25 alpha:0.4].CGColor : [UIColor colorWithWhite:1.0 alpha:0.08].CGColor;
    _card.layer.borderWidth = 0.8;
    _card.layer.cornerRadius = 18;
    _card.layer.shadowOpacity = 0.0;
    
    _numBadge.hidden = YES;
    _name.textColor = s.locked ? [UIColor colorWithWhite:0.6 alpha:1.0] : UIColor.whiteColor;
    self.sw.onTintColor = ZXRed;
}
-(void)setStatus:(NSString*)st color:(UIColor*)c{self.statusLbl.text=st;self.statusLbl.textColor=c?:ZXGray;}
-(void)swCh:(UISwitch*)s{if(self.onToggle)self.onToggle(s.isOn);}
@end

static UIImage* ZXFixOrientation(UIImage* src) {
    if (!src) return nil;
    if (src.imageOrientation == UIImageOrientationUp) return src;
    UIGraphicsBeginImageContextWithOptions(src.size, NO, src.scale);
    [src drawInRect:CGRectMake(0, 0, src.size.width, src.size.height)];
    UIImage *normalized = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return normalized ?: src;
}

// ── ZXPhotoCell ───────────────────────────────────────────────────
@interface ZXPhotoCell : UITableViewCell
-(void)configure:(ZXSlot*)s idx:(NSInteger)idx;
-(void)setStatus:(NSString*)st color:(UIColor*)c;
@property (copy) void(^onToggle)(BOOL);
@property UISwitch*sw;
@property UILabel*statusLbl;
@end
@implementation ZXPhotoCell{UILabel*_name,*_desc,*_num;UIImageView*_photo;UIView*_card;}
-(instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString*)r{
    self=[super initWithStyle:s reuseIdentifier:r];
    self.backgroundColor=UIColor.clearColor;self.selectionStyle=0;
    _card=ZXGlassView(14);_card.translatesAutoresizingMaskIntoConstraints=NO;
    ZXRedGlow(_card,8);[self.contentView addSubview:_card];
    _num=[UILabel new];_num.translatesAutoresizingMaskIntoConstraints=NO;
    _num.font=[UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    _num.textColor=[UIColor colorWithWhite:1 alpha:.15];[_card addSubview:_num];
    _name=[UILabel new];_name.translatesAutoresizingMaskIntoConstraints=NO;
    _name.font=[UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];_name.textColor=UIColor.whiteColor;[_card addSubview:_name];
    _desc=[UILabel new];_desc.translatesAutoresizingMaskIntoConstraints=NO;
    _desc.font=[UIFont systemFontOfSize:12];_desc.textColor=ZXGray;[_card addSubview:_desc];
    self.statusLbl=[UILabel new];self.statusLbl.translatesAutoresizingMaskIntoConstraints=NO;
    self.statusLbl.font=[UIFont systemFontOfSize:11];self.statusLbl.textColor=ZXGray;[_card addSubview:self.statusLbl];
    self.sw=[UISwitch new];self.sw.translatesAutoresizingMaskIntoConstraints=NO;
    self.sw.onTintColor=ZXRed;self.sw.transform=CGAffineTransformMakeScale(.75,.75);
    [self.sw addTarget:self action:@selector(swCh:) forControlEvents:UIControlEventValueChanged];[_card addSubview:self.sw];
    _photo=[UIImageView new];_photo.translatesAutoresizingMaskIntoConstraints=NO;
    _photo.contentMode=UIViewContentModeScaleAspectFit;_photo.clipsToBounds=YES;
    _photo.layer.cornerRadius=10;_photo.backgroundColor=[UIColor colorWithWhite:.05 alpha:1];[_card addSubview:_photo];
    [NSLayoutConstraint activateConstraints:@[
        [_card.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_card.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
        [_card.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor],
        [_card.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor],
        [_num.topAnchor constraintEqualToAnchor:_card.topAnchor constant:8],
        [_num.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
        [_name.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:14],
        [_name.topAnchor constraintEqualToAnchor:_card.topAnchor constant:12],
        [_name.trailingAnchor constraintEqualToAnchor:self.sw.leadingAnchor constant:-8],
        [_desc.leadingAnchor constraintEqualToAnchor:_name.leadingAnchor],
        [_desc.topAnchor constraintEqualToAnchor:_name.bottomAnchor constant:2],
        [self.statusLbl.leadingAnchor constraintEqualToAnchor:_name.leadingAnchor],
        [self.statusLbl.topAnchor constraintEqualToAnchor:_desc.bottomAnchor constant:2],
        [self.sw.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
        [self.sw.topAnchor constraintEqualToAnchor:_card.topAnchor constant:12],
        [_photo.topAnchor constraintEqualToAnchor:self.statusLbl.bottomAnchor constant:8],
        [_photo.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:12],
        [_photo.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
        [_photo.heightAnchor constraintEqualToConstant:170],
        [_photo.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor constant:-12],
    ]];
    return self;
}
-(void)configure:(ZXSlot*)s idx:(NSInteger)idx{
    _num.text=[NSString stringWithFormat:@"%02ld",(long)(idx+1)];
    _num.hidden=NO;
    _name.text = [NSString stringWithFormat:@"%02ld. %@", (long)(idx+1), s.name];
    _desc.text=s.desc;
    self.sw.on=NO;
    self.sw.enabled = !s.locked;
    self.sw.alpha = s.locked ? 0.35 : 1.0;
    self.statusLbl.text = s.locked ? @"Locked" : @"";
    self.statusLbl.textColor = s.locked ? [UIColor colorWithRed:0.95 green:0.25 blue:0.35 alpha:1.0] : ZXGray;
    _photo.image=nil;
    NSString *imgUrlStr = s.imageUrl ?: @"";
    if ([imgUrlStr containsString:@"144.172.105.169"]) {
        imgUrlStr = [imgUrlStr stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9008" withString:kServerBase];
        imgUrlStr = [imgUrlStr stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9009" withString:kServerBase];
    }
    if (imgUrlStr.length > 0 && ![imgUrlStr hasPrefix:@"http://"] && ![imgUrlStr hasPrefix:@"https://"]) {
        if (![imgUrlStr hasPrefix:@"/"]) {
            imgUrlStr = [NSString stringWithFormat:@"%@/%@", kServerBase, imgUrlStr];
        } else {
            imgUrlStr = [NSString stringWithFormat:@"%@%@", kServerBase, imgUrlStr];
        }
    }
    if (!imgUrlStr.length && s.slotId > 0) {
        imgUrlStr = [NSString stringWithFormat:@"%@/slot-cover/3/%ld", kServerBase, (long)s.slotId];
    }
    if (imgUrlStr.length) {
        NSMutableURLRequest *imgReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:imgUrlStr]];
        [imgReq setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
        imgReq.timeoutInterval = 15.0;
        [imgReq setValue:[[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey] ?: @"" forHTTPHeaderField:@"X-Auth-Key"];
        [imgReq setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
        [imgReq setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
        [[[NSURLSession sharedSession] dataTaskWithRequest:imgReq completionHandler:^(NSData*d, NSURLResponse*r, NSError*e){
            if(d && d.length > 100){
                UIImage*raw=[UIImage imageWithData:d];
                UIImage*img=ZXFixOrientation(raw);
                if(img)dispatch_async(dispatch_get_main_queue(),^{self->_photo.image=img;});
            }
        }] resume];
    }
}
-(void)setStatus:(NSString*)st color:(UIColor*)c{self.statusLbl.text=st;self.statusLbl.textColor=c?:ZXGray;}
-(void)swCh:(UISwitch*)s{if(self.onToggle)self.onToggle(s.isOn);}
@end

// ── Animated GIF Decoder (ImageIO Native with Caching) ───────────────
static NSCache *ZXGetGIFCache(void) {
    static NSCache *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [[NSCache alloc] init];
        cache.countLimit = 10;
    });
    return cache;
}

static UIImage *ZXLoadAnimatedGIF(NSString *name) {
    if (!name.length) return nil;
    UIImage *cached = [ZXGetGIFCache() objectForKey:name];
    if (cached) return cached;

    NSData *data = nil;
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:name ofType:nil];
    if(!bundlePath) bundlePath = [[NSBundle mainBundle] pathForResource:name ofType:@"gif"];
    if(!bundlePath) {
        NSString *clean = [name stringByReplacingOccurrencesOfString:@" " withString:@"_"];
        bundlePath = [[NSBundle mainBundle] pathForResource:clean ofType:nil];
        if(!bundlePath) bundlePath = [[NSBundle mainBundle] pathForResource:clean ofType:@"gif"];
    }
    if(!bundlePath && [name containsString:@"main"]) {
        bundlePath = [[NSBundle mainBundle] pathForResource:@"main_bg" ofType:@"gif"];
        if(!bundlePath) bundlePath = [[NSBundle mainBundle] pathForResource:@"main bg" ofType:@"gif"];
    }
    if(!bundlePath && [name containsString:@"Creative"]) {
        bundlePath = [[NSBundle mainBundle] pathForResource:@"logo" ofType:@"gif"];
        if(!bundlePath) bundlePath = [[NSBundle mainBundle] pathForResource:@"GIF by Chandelier Creative" ofType:@"gif"];
    }
    
    if(bundlePath) {
        data = [NSData dataWithContentsOfFile:bundlePath];
    }
    if(!data) {
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *docPath = [doc stringByAppendingPathComponent:name];
        if([[NSFileManager defaultManager] fileExistsAtPath:docPath]) {
            data = [NSData dataWithContentsOfFile:docPath];
        }
    }
    if(!data) return nil;
    
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)data, NULL);
    if (!source) return nil;
    
    size_t count = CGImageSourceGetCount(source);
    if (count <= 1) {
        CFRelease(source);
        UIImage *img = [UIImage imageWithData:data];
        if (img) [ZXGetGIFCache() setObject:img forKey:name];
        return img;
    }
    
    NSMutableArray *images = [NSMutableArray arrayWithCapacity:count];
    NSTimeInterval duration = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        CGImageRef image = CGImageSourceCreateImageAtIndex(source, i, NULL);
        if (!image) continue;
        
        [images addObject:[UIImage imageWithCGImage:image scale:[UIScreen mainScreen].scale orientation:UIImageOrientationUp]];
        CGImageRelease(image);
        
        CFDictionaryRef properties = CGImageSourceCopyPropertiesAtIndex(source, i, NULL);
        if (properties) {
            CFDictionaryRef gifProperties = CFDictionaryGetValue(properties, kCGImagePropertyGIFDictionary);
            if (gifProperties) {
                NSNumber *delayTime = CFDictionaryGetValue(gifProperties, kCGImagePropertyGIFUnclampedDelayTime);
                if (!delayTime || [delayTime floatValue] <= 0) {
                    delayTime = CFDictionaryGetValue(gifProperties, kCGImagePropertyGIFDelayTime);
                }
                if ([delayTime floatValue] > 0) {
                    duration += [delayTime doubleValue];
                } else {
                    duration += 0.1;
                }
            } else {
                duration += 0.1;
            }
            CFRelease(properties);
        }
    }
    CFRelease(source);
    
    if (duration <= 0.0) duration = (1.0 / 10.0) * count;
    UIImage *anim = [UIImage animatedImageWithImages:images duration:duration];
    if (anim) [ZXGetGIFCache() setObject:anim forKey:name];
    return anim;
}

// ── Main Background with Loop Muted MP4 Video / GIF ─────────────────
static void ZXAddModernBackground(UIView *view) {
    view.backgroundColor = [UIColor colorWithRed:0.04 green:0.01 blue:0.02 alpha:1.0];
    CGRect screenBounds = [UIScreen mainScreen].bounds;
    
    // Translucent dark overlay for crisp foreground legibility
    UIView *dimOverlay = [[UIView alloc] initWithFrame:screenBounds];
    dimOverlay.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    dimOverlay.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.35];
    [view insertSubview:dimOverlay atIndex:0];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        NSString *videoPath = [[NSBundle mainBundle] pathForResource:@"bg" ofType:@"mp4"];
        if (videoPath) {
            NSURL *videoURL = [NSURL fileURLWithPath:videoPath];
            AVPlayerItem *playerItem = [AVPlayerItem playerItemWithURL:videoURL];
            AVQueuePlayer *player = [AVQueuePlayer queuePlayerWithItems:@[playerItem]];
            player.volume = 0.0; // Mute audio
            
            AVPlayerLooper *looper = [AVPlayerLooper playerLooperWithPlayer:player templateItem:playerItem];
            
            dispatch_async(dispatch_get_main_queue(), ^{
                objc_setAssociatedObject(view, "ZXPlayerLooperKey", looper, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                objc_setAssociatedObject(view, "ZXPlayerKey", player, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                
                AVPlayerLayer *playerLayer = [AVPlayerLayer playerLayerWithPlayer:player];
                playerLayer.frame = screenBounds;
                playerLayer.videoGravity = AVLayerVideoGravityResizeAspectFill;
                [view.layer insertSublayer:playerLayer atIndex:0];
                [player play];
                
                __weak AVQueuePlayer *weakPlayer = player;
                id obs = [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification * _Nonnull note) {
                    [weakPlayer play];
                }];
                objc_setAssociatedObject(view, "ZXFgObsKey", obs, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            });
        } else {
            UIImage *gifImg = ZXLoadAnimatedGIF(@"main bg.gif");
            if (gifImg) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    UIImageView *bgGifView = [[UIImageView alloc] initWithFrame:screenBounds];
                    bgGifView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
                    bgGifView.contentMode = UIViewContentModeScaleAspectFill;
                    bgGifView.clipsToBounds = YES;
                    bgGifView.image = gifImg;
                    [view insertSubview:bgGifView atIndex:0];
                });
            }
        }
    });
}

// ── Falling Particle Effect (CAEmitterLayer) ───────────────────────
static void ZXAddFallingParticles(UIView *view) {
    CAEmitterLayer *emitter = [CAEmitterLayer layer];
    emitter.emitterPosition = CGPointMake(UIScreen.mainScreen.bounds.size.width / 2.0, -10);
    emitter.emitterShape  = kCAEmitterLayerLine;
    emitter.emitterSize   = CGSizeMake(UIScreen.mainScreen.bounds.size.width, 1);
    emitter.renderMode    = kCAEmitterLayerAdditive;

    // Draw a soft glow circle
    CGFloat sz = 14;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(sz, sz), NO, 0);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGContextSetFillColorWithColor(ctx, [UIColor whiteColor].CGColor);
    CGContextFillEllipseInRect(ctx, CGRectMake(1, 1, sz-2, sz-2));
    UIImage *dotImg = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();

    // Red glowing dot cell
    CAEmitterCell *redDot = [CAEmitterCell emitterCell];
    redDot.birthRate       = 3.5;
    redDot.lifetime        = 9.0;
    redDot.lifetimeRange   = 3.0;
    redDot.velocity        = 85;
    redDot.velocityRange   = 50;
    redDot.emissionLongitude = M_PI;
    redDot.emissionRange   = 0.18;
    redDot.scale           = 0.25;
    redDot.scaleRange      = 0.18;
    redDot.scaleSpeed      = -0.012;
    redDot.alphaSpeed      = -0.06;
    redDot.alphaRange      = 0.4;
    redDot.color           = [UIColor colorWithRed:0.95 green:0.10 blue:0.28 alpha:0.75].CGColor;
    redDot.contents        = (id)dotImg.CGImage;
    redDot.magnificationFilter = kCAFilterLinear;

    // Dim pink spark cell
    CAEmitterCell *sparkDot = [CAEmitterCell emitterCell];
    sparkDot.birthRate       = 1.8;
    sparkDot.lifetime        = 12.0;
    sparkDot.lifetimeRange   = 4.0;
    sparkDot.velocity        = 55;
    sparkDot.velocityRange   = 35;
    sparkDot.emissionLongitude = M_PI;
    sparkDot.emissionRange   = 0.4;
    sparkDot.scale           = 0.10;
    sparkDot.scaleRange      = 0.06;
    sparkDot.scaleSpeed      = -0.006;
    sparkDot.alphaSpeed      = -0.04;
    sparkDot.alphaRange      = 0.3;
    sparkDot.color           = [UIColor colorWithRed:1.0 green:0.6 blue:0.7 alpha:0.45].CGColor;
    sparkDot.contents        = (id)dotImg.CGImage;

    emitter.emitterCells = @[redDot, sparkDot];
    [view.layer addSublayer:emitter];
}

// ── String Obfuscation Macros ─────────────────────────────────────────
#define ZX_OBFUSCATE_STR(s) [NSString stringWithUTF8String:(const char[]){ \
    (char)s, 0 }]

static void ZXApplyGlowPulse(UIView *view) {
    CABasicAnimation *pulse = [CABasicAnimation animationWithKeyPath:@"shadowOpacity"];
    pulse.duration = 1.2;
    pulse.fromValue = @(0.35);
    pulse.toValue = @(0.85);
    pulse.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
    pulse.autoreverses = YES;
    pulse.repeatCount = HUGE_VALF;
    [view.layer addAnimation:pulse forKey:@"zx_glow_pulse"];
}

static void ZXApplyModernButton(UIButton *btn) {
    btn.layer.cornerRadius = 16;
    btn.clipsToBounds = NO;
    btn.layer.masksToBounds = NO;
    btn.layer.shadowColor = [UIColor colorWithRed:0.95 green:0.12 blue:0.28 alpha:1.0].CGColor;
    btn.layer.shadowOffset = CGSizeZero;
    btn.layer.shadowRadius = 12;
    btn.layer.shadowOpacity = 0.5;
    
    UIView *gradContainer = [UIView new];
    gradContainer.frame = btn.bounds;
    gradContainer.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    gradContainer.layer.cornerRadius = 16;
    gradContainer.clipsToBounds = YES;
    gradContainer.userInteractionEnabled = NO;
    [btn insertSubview:gradContainer atIndex:0];
    
    CAGradientLayer *btnGrad = [CAGradientLayer layer];
    btnGrad.frame = CGRectMake(0, 0, 600, 60);
    btnGrad.colors = @[
        (id)[UIColor colorWithRed:0.98 green:0.12 blue:0.35 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:0.75 green:0.02 blue:0.18 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:0.98 green:0.20 blue:0.40 alpha:1.0].CGColor
    ];
    btnGrad.startPoint = CGPointMake(0, 0);
    btnGrad.endPoint = CGPointMake(1, 1);
    btnGrad.cornerRadius = 16;
    [gradContainer.layer addSublayer:btnGrad];
    
    CABasicAnimation *gradAnim = [CABasicAnimation animationWithKeyPath:@"colors"];
    gradAnim.fromValue = btnGrad.colors;
    gradAnim.toValue = @[
        (id)[UIColor colorWithRed:0.75 green:0.02 blue:0.18 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:0.98 green:0.20 blue:0.40 alpha:1.0].CGColor,
        (id)[UIColor colorWithRed:0.98 green:0.12 blue:0.35 alpha:1.0].CGColor
    ];
    gradAnim.duration = 2.5;
    gradAnim.autoreverses = YES;
    gradAnim.repeatCount = HUGE_VALF;
    [btnGrad addAnimation:gradAnim forKey:@"zx_grad_shift"];
    
    ZXApplyGlowPulse(btn);
}

// ── ZXAuthVC (Sleek Modern Login Screen) ───────────────────────────
@interface ZXAuthVC : UIViewController
@property (copy) void(^onAuth)(void);
@end
@implementation ZXAuthVC{
    UITextField*_f;
    UILabel*_msg;
    UIButton*_btn;
    UIActivityIndicatorView*_sp;
    UIView*_card;
}
-(UIStatusBarStyle)preferredStatusBarStyle{return UIStatusBarStyleLightContent;}
-(void)viewDidLoad{
    [super viewDidLoad];
    if (FFKernelExploitSupported()) {
        FFKernelExploitPrepareAsync();
    }
    self.view.backgroundColor = [UIColor blackColor];
    ZXAddModernBackground(self.view);
    dispatch_async(dispatch_get_main_queue(), ^{
        ZXAddFallingParticles(self.view);
    });

    // Clean Pill Badge (Photo 3 design: Pink Border Pill containing ZEX EXTERNAL)
    UIView*badge=ZXGlassView(14);badge.translatesAutoresizingMaskIntoConstraints=NO;
    badge.backgroundColor=[UIColor colorWithRed:0.14 green:0.02 blue:0.04 alpha:0.85];
    badge.layer.cornerRadius=14;badge.layer.borderColor=[UIColor colorWithRed:1.0 green:0.25 blue:0.4 alpha:0.65].CGColor;
    badge.layer.borderWidth=1.0;
    [self.view addSubview:badge];
    
    UILabel*badgeLbl=[UILabel new];badgeLbl.translatesAutoresizingMaskIntoConstraints=NO;
    NSMutableAttributedString*badgeAtt=[[NSMutableAttributedString alloc]initWithString:@"ZEX EXTERNAL"];
    [badgeAtt addAttribute:NSForegroundColorAttributeName value:[UIColor whiteColor] range:NSMakeRange(0, 12)];
    [badgeAtt addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:17 weight:UIFontWeightBlack] range:NSMakeRange(0, 12)];
    [badgeAtt addAttribute:NSKernAttributeName value:@2.5 range:NSMakeRange(0, 12)];
    badgeLbl.attributedText=badgeAtt;
    badgeLbl.textAlignment=NSTextAlignmentCenter;
    [badge addSubview:badgeLbl];
    
    // Green Sub-text line (Photo 3 design: 📱 IPHONE • ESIGN • HWID LOCKED)
    UILabel*devInfo=[UILabel new];devInfo.translatesAutoresizingMaskIntoConstraints=NO;
    devInfo.text=@"📱 IPHONE • ESIGN • HWID LOCKED";
    devInfo.font=[UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    devInfo.textColor=[UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:0.95];
    devInfo.textAlignment=NSTextAlignmentCenter;
    [self.view addSubview:devInfo];
    
    // Modern Clean Login Card
    _card = [UIView new];_card.translatesAutoresizingMaskIntoConstraints=NO;
    _card.backgroundColor = [UIColor colorWithRed:0.06 green:0.02 blue:0.035 alpha:0.92];
    _card.layer.cornerRadius = 18;
    _card.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.1].CGColor;
    _card.layer.borderWidth = 1.0;
    _card.layer.shadowColor = UIColor.blackColor.CGColor;
    _card.layer.shadowOffset = CGSizeMake(0, 10);
    _card.layer.shadowRadius = 20;
    _card.layer.shadowOpacity = 0.6;
    [self.view addSubview:_card];
    
    UILabel*lbl=[UILabel new];lbl.translatesAutoresizingMaskIntoConstraints=NO;
    lbl.text=@"ENTER LICENSE KEY";lbl.font=[UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightBold];
    lbl.textColor=[UIColor colorWithRed:1.0 green:0.35 blue:0.5 alpha:1.0];[_card addSubview:lbl];
    
    NSString *hwid = ZXGetHWID();
    UILabel*hwidLbl=[UILabel new];hwidLbl.translatesAutoresizingMaskIntoConstraints=NO;
    hwidLbl.text=[NSString stringWithFormat:@"HWID: %@...", [hwid substringToIndex:MIN(10, hwid.length)].uppercaseString];
    hwidLbl.font=[UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    hwidLbl.textColor=[UIColor colorWithWhite:1 alpha:0.4];[_card addSubview:hwidLbl];
    
    UIView*inBox=[UIView new];inBox.translatesAutoresizingMaskIntoConstraints=NO;
    inBox.backgroundColor=[UIColor colorWithWhite:0 alpha:0.6];
    inBox.layer.cornerRadius=12;inBox.layer.borderWidth=1.0;
    inBox.layer.borderColor=[UIColor colorWithWhite:1 alpha:0.12].CGColor;
    [_card addSubview:inBox];
    
    _f=[UITextField new];_f.translatesAutoresizingMaskIntoConstraints=NO;
    _f.textColor=UIColor.whiteColor;_f.textAlignment=NSTextAlignmentLeft;
    _f.font=[UIFont monospacedSystemFontOfSize:13.5 weight:UIFontWeightBold];
    _f.autocorrectionType=UITextAutocorrectionTypeNo;
    _f.autocapitalizationType=UITextAutocapitalizationTypeAllCharacters;
    _f.keyboardAppearance=UIKeyboardAppearanceDark;
    _f.attributedPlaceholder=[[NSAttributedString alloc]initWithString:@"XXX"
        attributes:@{NSForegroundColorAttributeName:[UIColor colorWithWhite:.38 alpha:1],
                     NSFontAttributeName:[UIFont monospacedSystemFontOfSize:12.5 weight:UIFontWeightMedium]}];
    
    NSString *savedKey = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
    if(savedKey.length) {
        _f.text = savedKey;
    }
    [inBox addSubview:_f];
    
    UIButton*pasteBtn=[UIButton buttonWithType:UIButtonTypeSystem];pasteBtn.translatesAutoresizingMaskIntoConstraints=NO;
    [pasteBtn setTitle:@"PASTE" forState:0];
    [pasteBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.4 blue:0.55 alpha:1.0] forState:0];
    pasteBtn.titleLabel.font=[UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightBold];
    pasteBtn.backgroundColor=[UIColor colorWithRed:1.0 green:0.15 blue:0.3 alpha:0.15];
    pasteBtn.layer.cornerRadius=8;
    [pasteBtn addTarget:self action:@selector(pasteKey) forControlEvents:UIControlEventTouchUpInside];
    [inBox addSubview:pasteBtn];
    
    UIView*remRow=[UIView new];remRow.translatesAutoresizingMaskIntoConstraints=NO;
    [_card addSubview:remRow];
    
    UILabel*remLbl=[UILabel new];remLbl.translatesAutoresizingMaskIntoConstraints=NO;
    remLbl.text=@"REMEMBER KEY ON DEVICE";
    remLbl.font=[UIFont monospacedSystemFontOfSize:9.5 weight:UIFontWeightBold];
    remLbl.textColor=[UIColor colorWithWhite:1 alpha:0.75];
    [remRow addSubview:remLbl];
    
    UISwitch*remSw=[UISwitch new];remSw.translatesAutoresizingMaskIntoConstraints=NO;
    remSw.onTintColor=ZXRed;
    remSw.transform=CGAffineTransformMakeScale(0.78, 0.78);
    BOOL shouldRem = [[NSUserDefaults standardUserDefaults] objectForKey:kSaveKeyToggle] ? [[NSUserDefaults standardUserDefaults] boolForKey:kSaveKeyToggle] : YES;
    [remSw setOn:shouldRem animated:NO];
    remSw.tag = 888;
    [remRow addSubview:remSw];
    
    _btn=[UIButton buttonWithType:UIButtonTypeSystem];_btn.translatesAutoresizingMaskIntoConstraints=NO;
    NSMutableAttributedString *btnTitle = [[NSMutableAttributedString alloc] initWithString:@"⚡ AUTHENTICATE & ENTER"];
    [btnTitle addAttribute:NSForegroundColorAttributeName value:UIColor.whiteColor range:NSMakeRange(0, btnTitle.length)];
    [btnTitle addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:14.5 weight:UIFontWeightHeavy] range:NSMakeRange(0, btnTitle.length)];
    [btnTitle addAttribute:NSKernAttributeName value:@1.2 range:NSMakeRange(0, btnTitle.length)];
    [_btn setAttributedTitle:btnTitle forState:UIControlStateNormal];
    _btn.backgroundColor=ZXRed;_btn.layer.cornerRadius=16;
    [_btn addTarget:self action:@selector(btnTouchDown) forControlEvents:UIControlEventTouchDown];
    [_btn addTarget:self action:@selector(btnTouchUp) forControlEvents:UIControlEventTouchUpInside|UIControlEventTouchUpOutside|UIControlEventTouchCancel];
    [_btn addTarget:self action:@selector(activate) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_btn];
    ZXApplyModernButton(_btn);
    
    _msg=[UILabel new];_msg.translatesAutoresizingMaskIntoConstraints=NO;
    _msg.textAlignment=NSTextAlignmentCenter;_msg.font=[UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    _msg.numberOfLines=2;[self.view addSubview:_msg];
    
    _sp=[[UIActivityIndicatorView alloc]initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _sp.translatesAutoresizingMaskIntoConstraints=NO;_sp.color=ZXRed;_sp.hidesWhenStopped=YES;[self.view addSubview:_sp];
    
    UILabel*foot=[UILabel new];foot.translatesAutoresizingMaskIntoConstraints=NO;
    foot.text=@"STATUS: ENCRYPTED  •  TLS-AES256  •  1-DEVICE SECURE";
    foot.font=[UIFont monospacedSystemFontOfSize:8.5 weight:UIFontWeightBold];
    foot.textColor=[UIColor colorWithWhite:1 alpha:0.45];foot.textAlignment=NSTextAlignmentCenter;
    
    UIView*footBadge=ZXGlassView(14);footBadge.translatesAutoresizingMaskIntoConstraints=NO;
    footBadge.backgroundColor=[UIColor colorWithRed:0.12 green:0.02 blue:0.04 alpha:0.75];
    footBadge.layer.cornerRadius=14;footBadge.layer.borderColor=[UIColor colorWithRed:1.0 green:0.25 blue:0.4 alpha:0.35].CGColor;
    footBadge.layer.borderWidth=0.8;
    [footBadge addSubview:foot];
    [self.view addSubview:footBadge];
    
    [NSLayoutConstraint activateConstraints:@[
        [_card.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:22],
        [_card.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-22],
        [_card.bottomAnchor constraintEqualToAnchor:_btn.topAnchor constant:-16],
        
        [devInfo.bottomAnchor constraintEqualToAnchor:_card.topAnchor constant:-14],
        [devInfo.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        
        [badge.bottomAnchor constraintEqualToAnchor:devInfo.topAnchor constant:-10],
        [badge.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        
        [badgeLbl.topAnchor constraintEqualToAnchor:badge.topAnchor constant:7],
        [badgeLbl.bottomAnchor constraintEqualToAnchor:badge.bottomAnchor constant:-7],
        [badgeLbl.leadingAnchor constraintEqualToAnchor:badge.leadingAnchor constant:22],
        [badgeLbl.trailingAnchor constraintEqualToAnchor:badge.trailingAnchor constant:-22],
        
        [lbl.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:16],
        [lbl.topAnchor constraintEqualToAnchor:_card.topAnchor constant:15],
        [hwidLbl.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-16],
        [hwidLbl.centerYAnchor constraintEqualToAnchor:lbl.centerYAnchor],
        
        [inBox.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:12],
        [inBox.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
        [inBox.topAnchor constraintEqualToAnchor:lbl.bottomAnchor constant:12],
        [inBox.heightAnchor constraintEqualToConstant:46],
        
        [_f.leadingAnchor constraintEqualToAnchor:inBox.leadingAnchor constant:12],
        [_f.trailingAnchor constraintEqualToAnchor:pasteBtn.leadingAnchor constant:-6],
        [_f.topAnchor constraintEqualToAnchor:inBox.topAnchor],
        [_f.bottomAnchor constraintEqualToAnchor:inBox.bottomAnchor],
        
        [pasteBtn.trailingAnchor constraintEqualToAnchor:inBox.trailingAnchor constant:-6],
        [pasteBtn.centerYAnchor constraintEqualToAnchor:inBox.centerYAnchor],
        [pasteBtn.widthAnchor constraintEqualToConstant:54],
        [pasteBtn.heightAnchor constraintEqualToConstant:32],
        
        [remRow.topAnchor constraintEqualToAnchor:inBox.bottomAnchor constant:10],
        [remRow.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor constant:14],
        [remRow.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-14],
        [remRow.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor constant:-12],
        [remRow.heightAnchor constraintEqualToConstant:32],
        
        [remLbl.leadingAnchor constraintEqualToAnchor:remRow.leadingAnchor],
        [remLbl.centerYAnchor constraintEqualToAnchor:remRow.centerYAnchor],
        [remSw.trailingAnchor constraintEqualToAnchor:remRow.trailingAnchor],
        [remSw.centerYAnchor constraintEqualToAnchor:remRow.centerYAnchor],
        
        [_btn.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor],
        [_btn.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor],
        [_btn.bottomAnchor constraintEqualToAnchor:footBadge.topAnchor constant:-18],
        [_btn.heightAnchor constraintEqualToConstant:50],
        
        [_msg.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_msg.topAnchor constraintEqualToAnchor:_btn.bottomAnchor constant:4],
        [_msg.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor],
        [_msg.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor],
        
        [_sp.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_sp.centerYAnchor constraintEqualToAnchor:_btn.centerYAnchor],
        
        [footBadge.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [footBadge.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-14],
        
        [foot.topAnchor constraintEqualToAnchor:footBadge.topAnchor constant:7],
        [foot.bottomAnchor constraintEqualToAnchor:footBadge.bottomAnchor constant:-7],
        [foot.leadingAnchor constraintEqualToAnchor:footBadge.leadingAnchor constant:16],
        [foot.trailingAnchor constraintEqualToAnchor:footBadge.trailingAnchor constant:-16],
    ]];
}
-(void)btnTouchDown{
    [UIView animateWithDuration:0.15 animations:^{
        self->_btn.transform = CGAffineTransformMakeScale(0.96, 0.96);
    }];
}
-(void)btnTouchUp{
    [UIView animateWithDuration:0.25 delay:0 usingSpringWithDamping:0.6 initialSpringVelocity:0.5 options:0 animations:^{
        self->_btn.transform = CGAffineTransformIdentity;
    } completion:nil];
}
-(void)shakeCard{
    AudioServicesPlaySystemSound(1521);
    CAKeyframeAnimation *shake = [CAKeyframeAnimation animationWithKeyPath:@"position.x"];
    shake.values = @[@(0), @(-12), @(12), @(-8), @(8), @(-4), @(4), @(0)];
    shake.keyTimes = @[@0, @0.15, @0.3, @0.45, @0.6, @0.75, @0.9, @1];
    shake.duration = 0.45;
    shake.additive = YES;
    [_card.layer addAnimation:shake forKey:@"card_shake"];
}
-(void)pasteKey{
    NSString*pb=[UIPasteboard generalPasteboard].string;
    if(pb.length){
        _f.text=[pb stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
    }
}
-(void)activate{
    NSString*key=[_f.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet].uppercaseString;
    if(!key.length){
        [self shakeCard];
        _msg.text=@"> Error: Enter license key";_msg.textColor=[UIColor systemYellowColor];return;
    }
    
    UISwitch*remSw = (UISwitch*)[self.view viewWithTag:888];
    BOOL isRemember = remSw ? remSw.isOn : YES;

    
    NSString*hwid = ZXGetHWID();
    [_sp startAnimating];_btn.enabled=NO;_msg.text=@"> Verifying license on auth node...";_msg.textColor=ZXGray;
    NSString*url=[NSString stringWithFormat:@"%@/verify?key=%@&device=%@",kServerBase,
        [key stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet], hwid];
    [[[NSURLSession sharedSession]dataTaskWithURL:[NSURL URLWithString:url] completionHandler:^(NSData*d,NSURLResponse*r,NSError*e){
        dispatch_async(dispatch_get_main_queue(),^{
            [self->_sp stopAnimating];self->_btn.enabled=YES;
            if(!d||e){
                [self shakeCard];
                self->_msg.text=@"> Server connection failed";self->_msg.textColor=UIColor.systemRedColor;return;
            }
            NSDictionary*j=[NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if([j[@"valid"]boolValue]){
                if(isRemember) {
                    [[NSUserDefaults standardUserDefaults]setObject:key forKey:kSavedKey];
                    [[NSUserDefaults standardUserDefaults]setBool:YES forKey:kSaveKeyToggle];
                } else {
                    [[NSUserDefaults standardUserDefaults]removeObjectForKey:kSavedKey];
                    [[NSUserDefaults standardUserDefaults]setBool:NO forKey:kSaveKeyToggle];
                }
                [[NSUserDefaults standardUserDefaults]setObject:j[@"created_at"]?:@"N/A" forKey:kKeyCreatedAt];
                [[NSUserDefaults standardUserDefaults]setObject:j[@"expires_at"]?:@"PERMANENT" forKey:kKeyExpiresAt];
                [[NSUserDefaults standardUserDefaults]synchronize];
                
                self->_msg.text=@"> Access Granted: Verified!";self->_msg.textColor=ZXGreen;ZXPlay(@"Welcome_Baby");
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,600*NSEC_PER_MSEC),dispatch_get_main_queue(),^{if(self.onAuth)self.onAuth();});
            } else {
                [self shakeCard];
                NSString *reason = j[@"reason"] ?: @"Invalid or expired key";
                self->_msg.text=[NSString stringWithFormat:@"> Access Denied: %@", reason];self->_msg.textColor=UIColor.systemRedColor;
            }
        });
    }]resume];
}
@end

// ── ZXMainVC ──────────────────────────────────────────────────────
@interface ZXMainVC : UIViewController<UITableViewDataSource,UITableViewDelegate>
@property (nonatomic, strong) NSString *selectedGameMode;
@property (nonatomic, copy) NSString *lastTargetError;
@end
@implementation ZXMainVC{
    ZXConfig*_cfg;NSInteger _tab;
    UILabel*_connLbl,*_verLbl,*_headerConn;
    UITableView*_tv;
    NSArray<UIButton*>*_tabBtns;
    UIView *_modeOverlay;
    UIView *_typeContainer;
    UIView *_accountContainer;
    UILabel *_modeBadgeLbl;
}
-(UIStatusBarStyle)preferredStatusBarStyle{return UIStatusBarStyleLightContent;}
-(NSArray<ZXSlot*>*)currentSlots{
    if(!_cfg)return @[];
    NSArray<ZXSlot*>*raw = _tab==0?_cfg.opt1:_tab==1?_cfg.opt2:_tab==2?_cfg.opt3:_tab==3?_cfg.opt4:_cfg.opt5;
    NSMutableArray<ZXSlot*>*filtered = [NSMutableArray array];
    BOOL isMax = [self.selectedGameMode isEqualToString:@"FFMAX"];
    for(ZXSlot* s in raw){
        NSString *sName = s.name ? s.name.uppercaseString : @"";
        NSString *sDesc = s.desc ? s.desc.uppercaseString : @"";
        
        // Strict game mode exclusion by slot name and description
        if (isMax) {
            if ([sName containsString:@"FFTH"] || [sName containsString:@"NORMAL"] ||
                [sDesc containsString:@"FFTH"] || [sDesc containsString:@"NORMAL"]) continue;
            if (s.ffthPath.length > 0 && s.ffmaxPath.length == 0) continue;
        } else {
            if ([sName containsString:@"FFMAX"] || [sName containsString:@" MAX"] || [sName hasSuffix:@"MAX"] ||
                [sDesc containsString:@"FFMAX"] || [sDesc containsString:@" MAX"] || [sDesc hasSuffix:@"MAX"]) continue;
            if (s.ffmaxPath.length > 0 && s.ffthPath.length == 0) continue;
        }
        
        [filtered addObject:s];
    }
    return filtered;
}
static NSString *ZXContainerPathViaCM(NSString *bundleId) {
    if (!bundleId.length) return nil;
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_LAZY);
    if (!mgr) return nil;
    void *(*q_create)(void) = dlsym(mgr, "container_query_create");
    void (*q_set_class)(void *, uint64_t) = dlsym(mgr, "container_query_set_class");
    void (*q_set_ids)(void *, void *) = dlsym(mgr, "container_query_set_identifiers");
    void *(*q_single)(void *) = dlsym(mgr, "container_query_get_single_result");
    const char *(*c_get_path)(void *) = dlsym(mgr, "container_get_path");
    void (*q_free)(void *) = dlsym(mgr, "container_query_free");
    void *(*xpc_str)(const char *) = dlsym(RTLD_DEFAULT, "xpc_string_create");
    void (*xpc_rel)(void *) = dlsym(RTLD_DEFAULT, "xpc_release");
    if (!q_create || !q_set_class || !q_set_ids || !q_single || !c_get_path || !q_free || !xpc_str || !xpc_rel) return nil;
    void *q = q_create();
    if (!q) return nil;
    q_set_class(q, 2); // Application Data container
    void *ident = xpc_str(bundleId.UTF8String);
    if (!ident) { q_free(q); return nil; }
    q_set_ids(q, ident);
    void *res = q_single(q);
    NSString *outPath = nil;
    if (res) {
        const char *p = c_get_path(res);
        if (p && p[0]) {
            outPath = [NSString stringWithUTF8String:p];
            if ([outPath hasPrefix:@"/var/"]) outPath = [@"/private" stringByAppendingString:outPath];
        }
    }
    xpc_rel(ident);
    q_free(q);
    return outPath;
}

static NSString *ZXFindContainerForMode(NSString *gameId, NSString *mode, NSString **debugOut) {
    NSString *c = FFWorseQueryDataContainerCandidate(gameId);
    if (c.length > 0) return c;
    c = ZXContainerPathViaCM(gameId);
    if (c.length > 0) return c;
    Class wsClass = NSClassFromString(@"LSApplicationWorkspace");
    SEL defSel = NSSelectorFromString(@"defaultWorkspace");
    SEL allSel = NSSelectorFromString(@"allApplications");
    BOOL wantMax = [mode isEqualToString:@"FFMAX"];
    if ([wsClass respondsToSelector:defSel]) {
        id ws = ((id (*)(id, SEL))objc_msgSend)(wsClass, defSel);
        if ([ws respondsToSelector:allSel]) {
            NSArray *apps = ((id (*)(id, SEL))objc_msgSend)(ws, allSel);
            for (id proxy in apps) {
                SEL idSel = NSSelectorFromString(@"applicationIdentifier");
                if (![proxy respondsToSelector:idSel]) continue;
                NSString *appId = ((id (*)(id, SEL))objc_msgSend)(proxy, idSel);
                if (![appId isKindOfClass:NSString.class]) continue;
                NSString *low = appId.lowercaseString;
                if ([low containsString:@"freefire"]) {
                    if (wantMax && ![low containsString:@"max"]) continue;
                    if (!wantMax && [low containsString:@"max"]) continue;
                    NSString *cand = FFWorseQueryDataContainerCandidate(appId);
                    if (cand.length > 0) return cand;
                }
            }
        }
    }
    // Fallback for iOS 26/27 when LSApplicationProxy hides dataContainerURL:
    // grant /private/var/mobile/Containers/Data/Application and scan MCM metadata plists.
    NSString *appsRoot = @"/private/var/mobile/Containers/Data/Application";
    int64_t rootGrant = FFWorseQueryGrantPath(appsRoot, NO);
    if (rootGrant >= 0) {
        NSFileManager *fm = NSFileManager.defaultManager;
        NSArray<NSString *> *uuids = [fm contentsOfDirectoryAtPath:appsRoot error:nil];
        NSString *fuzzyMatch = nil;
        for (NSString *uuid in uuids) {
            if (uuid.length < 16) continue;
            NSString *cDir = [appsRoot stringByAppendingPathComponent:uuid];
            NSString *metaPath = [cDir stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
            NSString *ident = [meta[@"MCMMetadataIdentifier"] isKindOfClass:NSString.class] ? meta[@"MCMMetadataIdentifier"] : nil;
            if ([ident isEqualToString:gameId]) {
                return cDir;
            }
            if (!fuzzyMatch && ident.length > 0) {
                NSString *low = ident.lowercaseString;
                if ([low containsString:@"freefire"] && ((wantMax && [low containsString:@"max"]) || (!wantMax && ![low containsString:@"max"]))) {
                    fuzzyMatch = cDir;
                }
            }
            NSString *prefPath = [cDir stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Preferences/%@.plist", gameId]];
            if ([fm fileExistsAtPath:prefPath]) {
                return cDir;
            }
        }
        if (fuzzyMatch.length > 0) return fuzzyMatch;
        if (debugOut) *debugOut = [NSString stringWithFormat:@"Game not found in %lu containers (%@)", (unsigned long)uuids.count, gameId];
    } else if (debugOut) {
        *debugOut = [NSString stringWithFormat:@"Game not found (%@ / rootGrant=%lld)", gameId, (long long)rootGrant];
    }
    return nil;
}

-(NSString*)targetPathForSubPath:(NSString*)relPath gameMode:(NSString*)mode {
    self.lastTargetError = nil;
    if (!relPath.length) {
        self.lastTargetError = @"Empty target path";
        return nil;
    }
    NSString *clean = relPath;
    if ([clean hasPrefix:@"/"]) clean = [clean substringFromIndex:1];
    
    // Normalize target identifier
    BOOL isMax = [mode isEqualToString:@"FFMAX"];
    NSString *gameId = isMax ? @"com.dts.freefiremax" : @"com.dts.freefireth";
    
    // Strip leading identifier (or any [MHA-C2] prefix before it) if present in relative path
    NSString *subPart = clean;
    NSRange rTh = [subPart rangeOfString:@"com.dts.freefireth/"];
    NSRange rMax = [subPart rangeOfString:@"com.dts.freefiremax/"];
    if (rTh.location != NSNotFound) {
        subPart = [subPart substringFromIndex:NSMaxRange(rTh)];
    } else if (rMax.location != NSNotFound) {
        subPart = [subPart substringFromIndex:NSMaxRange(rMax)];
    } else if ([subPart isEqualToString:@"com.dts.freefireth"] || [subPart isEqualToString:@"com.dts.freefiremax"]) {
        subPart = @"";
    }
    while ([subPart hasPrefix:@"/"]) subPart = [subPart substringFromIndex:1];
    
    if (!FFWorseQuerySupported()) {
        self.lastTargetError = @"iOS version not supported";
        return nil;
    }
    if (!FFWorseQueryPrepare()) {
        self.lastTargetError = FFWorseQueryFailureReason();
        return nil;
    }
    NSString *findErr = nil;
    NSString *directContainer = ZXFindContainerForMode(gameId, mode, &findErr);
    if (!directContainer.length) {
        self.lastTargetError = findErr.length ? findErr : [NSString stringWithFormat:@"Game not found (%@)", gameId];
        return nil;
    }
    int64_t grantHandle = FFWorseQueryGrantPath(directContainer, YES);
    if (grantHandle < 0) {
        self.lastTargetError = [NSString stringWithFormat:@"Grant failed (%lld)", (long long)grantHandle];
        return nil;
    }
    NSString *fullPath = [directContainer stringByAppendingPathComponent:subPart];
    FFWorseQueryGrantPath(fullPath, YES);
    return fullPath;
}

-(NSString*)mcmBase{
    if (FFWorseQuerySupported() && FFWorseQueryPrepare()) {
        NSString *gameId = [self.selectedGameMode isEqualToString:@"FFMAX"] ? @"com.dts.freefiremax" : @"com.dts.freefireth";
        NSString *candidate = ZXFindContainerForMode(gameId, self.selectedGameMode, nil);
        if (candidate.length > 0 && FFWorseQueryGrantPath(candidate, YES) >= 0) {
            return candidate;
        }
    }
    return nil;
}
-(void)viewDidLoad{
    [super viewDidLoad];_tab=0;self.view.backgroundColor=ZXBg;
    if(!self.selectedGameMode) self.selectedGameMode = @"FFTH";
    [self buildBackground];[self buildUI];[self loadConfig];
    [self showGameModeSelectionWithInitialTab:0];
}
-(void)showGameModeSelection {
    [self showGameModeSelectionWithInitialTab:0];
}
-(void)showGameModeSelectionWithInitialTab:(NSInteger)initialTab{
    if (_modeOverlay && _modeOverlay.superview) {
        UIButton *targetBtn = (UIButton*)[_modeOverlay viewWithTag:(initialTab == 1 ? 502 : 501)];
        if (targetBtn) [self modeNavTabTap:targetBtn];
        return;
    }
    
    UIView *overlay = [[UIView alloc] initWithFrame:self.view.bounds];
    overlay.backgroundColor = [UIColor colorWithRed:0.04 green:0.01 blue:0.02 alpha:0.98];
    overlay.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _modeOverlay = overlay;
    
    ZXAddModernBackground(overlay);
    
    // Type Container View
    UIView *typeView = [UIView new];
    typeView.translatesAutoresizingMaskIntoConstraints = NO;
    _typeContainer = typeView;
    [overlay addSubview:typeView];
    
    UILabel*brand=[UILabel new];brand.translatesAutoresizingMaskIntoConstraints=NO;
    NSMutableAttributedString*bAtt=[[NSMutableAttributedString alloc]initWithString:@"ZEX EXTERNAL"];
    [bAtt addAttribute:NSForegroundColorAttributeName value:ZXRed range:NSMakeRange(0,3)];
    [bAtt addAttribute:NSForegroundColorAttributeName value:UIColor.whiteColor range:NSMakeRange(3,9)];
    [bAtt addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:26 weight:UIFontWeightBlack] range:NSMakeRange(0,12)];
    [bAtt addAttribute:NSKernAttributeName value:@2.5 range:NSMakeRange(0,12)];
    brand.attributedText=bAtt;
    brand.textAlignment = NSTextAlignmentCenter;
    [typeView addSubview:brand];
    
    UILabel *headerSub = [UILabel new];
    headerSub.translatesAutoresizingMaskIntoConstraints = NO;
    headerSub.text = @"GAME EDITION SELECTOR";
    headerSub.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    headerSub.textColor = ZXRed;
    headerSub.textAlignment = NSTextAlignmentCenter;
    [typeView addSubview:headerSub];
    
    UILabel *titleLbl = [UILabel new];
    titleLbl.translatesAutoresizingMaskIntoConstraints = NO;
    titleLbl.text = @"CHOOSE INSTALLED EDITION";
    titleLbl.font = [UIFont systemFontOfSize:15 weight:UIFontWeightHeavy];
    titleLbl.textColor = [UIColor colorWithWhite:0.85 alpha:1.0];
    titleLbl.textAlignment = NSTextAlignmentCenter;
    [typeView addSubview:titleLbl];
    
    UIButton *btnNormal = [UIButton buttonWithType:UIButtonTypeCustom];
    btnNormal.translatesAutoresizingMaskIntoConstraints = NO;
    btnNormal.backgroundColor = [UIColor colorWithRed:0.07 green:0.025 blue:0.04 alpha:0.92];
    btnNormal.layer.cornerRadius = 16;
    btnNormal.layer.borderWidth = 1.2;
    btnNormal.layer.borderColor = [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:0.65].CGColor;
    btnNormal.tag = 100;
    [btnNormal addTarget:self action:@selector(selectGameModeTap:) forControlEvents:UIControlEventTouchUpInside];
    [typeView addSubview:btnNormal];
    
    UILabel *lblNormalTitle = [UILabel new];
    lblNormalTitle.translatesAutoresizingMaskIntoConstraints = NO;
    lblNormalTitle.text = @"FREE FIRE NORMAL";
    lblNormalTitle.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBlack];
    lblNormalTitle.textColor = UIColor.whiteColor;
    lblNormalTitle.textAlignment = NSTextAlignmentCenter;
    [btnNormal addSubview:lblNormalTitle];
    
    UIButton *btnMax = [UIButton buttonWithType:UIButtonTypeCustom];
    btnMax.translatesAutoresizingMaskIntoConstraints = NO;
    btnMax.backgroundColor = [UIColor colorWithRed:0.07 green:0.025 blue:0.04 alpha:0.92];
    btnMax.layer.cornerRadius = 16;
    btnMax.layer.borderWidth = 1.2;
    btnMax.layer.borderColor = [UIColor colorWithRed:1.0 green:0.55 blue:0.15 alpha:0.65].CGColor;
    btnMax.tag = 200;
    [btnMax addTarget:self action:@selector(selectGameModeTap:) forControlEvents:UIControlEventTouchUpInside];
    [typeView addSubview:btnMax];
    
    UILabel *lblMaxTitle = [UILabel new];
    lblMaxTitle.translatesAutoresizingMaskIntoConstraints = NO;
    lblMaxTitle.text = @"FREE FIRE MAX";
    lblMaxTitle.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBlack];
    lblMaxTitle.textColor = UIColor.whiteColor;
    lblMaxTitle.textAlignment = NSTextAlignmentCenter;
    [btnMax addSubview:lblMaxTitle];
    
    [NSLayoutConstraint activateConstraints:@[
        [typeView.topAnchor constraintEqualToAnchor:overlay.topAnchor],
        [typeView.leadingAnchor constraintEqualToAnchor:overlay.leadingAnchor],
        [typeView.trailingAnchor constraintEqualToAnchor:overlay.trailingAnchor],
        [typeView.bottomAnchor constraintEqualToAnchor:overlay.bottomAnchor constant:-80],
        
        [brand.topAnchor constraintEqualToAnchor:typeView.safeAreaLayoutGuide.topAnchor constant:40],
        [brand.centerXAnchor constraintEqualToAnchor:typeView.centerXAnchor],
        
        [headerSub.topAnchor constraintEqualToAnchor:brand.bottomAnchor constant:10],
        [headerSub.centerXAnchor constraintEqualToAnchor:typeView.centerXAnchor],
        
        [titleLbl.topAnchor constraintEqualToAnchor:headerSub.bottomAnchor constant:45],
        [titleLbl.centerXAnchor constraintEqualToAnchor:typeView.centerXAnchor],
        
        [btnNormal.topAnchor constraintEqualToAnchor:titleLbl.bottomAnchor constant:30],
        [btnNormal.leadingAnchor constraintEqualToAnchor:typeView.leadingAnchor constant:24],
        [btnNormal.trailingAnchor constraintEqualToAnchor:typeView.trailingAnchor constant:-24],
        [btnNormal.heightAnchor constraintEqualToConstant:76],
        
        [lblNormalTitle.centerXAnchor constraintEqualToAnchor:btnNormal.centerXAnchor],
        [lblNormalTitle.centerYAnchor constraintEqualToAnchor:btnNormal.centerYAnchor],
        
        [btnMax.topAnchor constraintEqualToAnchor:btnNormal.bottomAnchor constant:20],
        [btnMax.leadingAnchor constraintEqualToAnchor:typeView.leadingAnchor constant:24],
        [btnMax.trailingAnchor constraintEqualToAnchor:typeView.trailingAnchor constant:-24],
        [btnMax.heightAnchor constraintEqualToConstant:76],
        
        [lblMaxTitle.centerXAnchor constraintEqualToAnchor:btnMax.centerXAnchor],
        [lblMaxTitle.centerYAnchor constraintEqualToAnchor:btnMax.centerYAnchor],
    ]];
    
    // Account Container View
    UIView *accView = [self buildAccountView];
    _accountContainer = accView;
    _accountContainer.hidden = YES;
    [overlay addSubview:accView];
    
    [NSLayoutConstraint activateConstraints:@[
        [accView.topAnchor constraintEqualToAnchor:overlay.safeAreaLayoutGuide.topAnchor constant:10],
        [accView.leadingAnchor constraintEqualToAnchor:overlay.leadingAnchor],
        [accView.trailingAnchor constraintEqualToAnchor:overlay.trailingAnchor],
        [accView.bottomAnchor constraintEqualToAnchor:overlay.bottomAnchor constant:-80],
    ]];
    
    // Bottom Floating Navigation Bar
    UIView *navBar = ZXGlassView(24);
    navBar.translatesAutoresizingMaskIntoConstraints = NO;
    navBar.backgroundColor = [UIColor colorWithRed:0.04 green:0.01 blue:0.02 alpha:0.95];
    navBar.layer.borderColor = [UIColor colorWithRed:0.95 green:0.12 blue:0.28 alpha:0.4].CGColor;
    navBar.layer.borderWidth = 1.0;
    [overlay addSubview:navBar];
    
    UIButton *typeTabBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    typeTabBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [typeTabBtn setTitle:@"Type" forState:UIControlStateNormal];
    typeTabBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    typeTabBtn.tag = 501;
    [typeTabBtn addTarget:self action:@selector(modeNavTabTap:) forControlEvents:UIControlEventTouchUpInside];
    [navBar addSubview:typeTabBtn];
    
    UIButton *accountTabBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    accountTabBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [accountTabBtn setTitle:@"Account" forState:UIControlStateNormal];
    accountTabBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    accountTabBtn.tag = 502;
    [accountTabBtn addTarget:self action:@selector(modeNavTabTap:) forControlEvents:UIControlEventTouchUpInside];
    [navBar addSubview:accountTabBtn];
    
    [NSLayoutConstraint activateConstraints:@[
        [navBar.bottomAnchor constraintEqualToAnchor:overlay.safeAreaLayoutGuide.bottomAnchor constant:-10],
        [navBar.centerXAnchor constraintEqualToAnchor:overlay.centerXAnchor],
        [navBar.widthAnchor constraintEqualToAnchor:overlay.widthAnchor multiplier:0.88],
        [navBar.heightAnchor constraintEqualToConstant:54],
        
        [typeTabBtn.leadingAnchor constraintEqualToAnchor:navBar.leadingAnchor constant:6],
        [typeTabBtn.topAnchor constraintEqualToAnchor:navBar.topAnchor constant:6],
        [typeTabBtn.bottomAnchor constraintEqualToAnchor:navBar.bottomAnchor constant:-6],
        [typeTabBtn.widthAnchor constraintEqualToAnchor:navBar.widthAnchor multiplier:0.48],
        
        [accountTabBtn.trailingAnchor constraintEqualToAnchor:navBar.trailingAnchor constant:-6],
        [accountTabBtn.topAnchor constraintEqualToAnchor:navBar.topAnchor constant:6],
        [accountTabBtn.bottomAnchor constraintEqualToAnchor:navBar.bottomAnchor constant:-6],
        [accountTabBtn.widthAnchor constraintEqualToAnchor:navBar.widthAnchor multiplier:0.48],
    ]];
    
    ZXAddFallingParticles(overlay);
    
    overlay.alpha = 0;
    [self.view addSubview:overlay];
    [UIView animateWithDuration:0.35 animations:^{
        overlay.alpha = 1.0;
    }];
    
    [self modeNavTabTap:(initialTab == 1 ? accountTabBtn : typeTabBtn)];
}

-(void)modeNavTabTap:(UIButton*)btn {
    UIButton *typeBtn = (UIButton*)[_modeOverlay viewWithTag:501];
    UIButton *accountBtn = (UIButton*)[_modeOverlay viewWithTag:502];
    
    [UIView animateWithDuration:0.25 delay:0 usingSpringWithDamping:0.75 initialSpringVelocity:0.5 options:0 animations:^{
        if (btn.tag == 501) {
            self->_typeContainer.hidden = NO;
            self->_accountContainer.hidden = YES;
            
            typeBtn.backgroundColor = [UIColor colorWithRed:0.95 green:0.12 blue:0.28 alpha:0.9];
            typeBtn.layer.cornerRadius = 18;
            typeBtn.transform = CGAffineTransformMakeScale(1.02, 1.02);
            [typeBtn setTitleColor:UIColor.whiteColor forState:0];
            
            accountBtn.backgroundColor = UIColor.clearColor;
            accountBtn.transform = CGAffineTransformIdentity;
            [accountBtn setTitleColor:[UIColor colorWithWhite:0.55 alpha:1.0] forState:0];
        } else {
            self->_typeContainer.hidden = YES;
            self->_accountContainer.hidden = NO;
            
            accountBtn.backgroundColor = [UIColor colorWithRed:0.08 green:0.45 blue:0.95 alpha:0.9];
            accountBtn.layer.cornerRadius = 18;
            accountBtn.transform = CGAffineTransformMakeScale(1.02, 1.02);
            [accountBtn setTitleColor:UIColor.whiteColor forState:0];
            
            typeBtn.backgroundColor = UIColor.clearColor;
            typeBtn.transform = CGAffineTransformIdentity;
            [typeBtn setTitleColor:[UIColor colorWithWhite:0.55 alpha:1.0] forState:0];
        }
    } completion:nil];
}

-(UIView*)buildAccountView {
    UIScrollView *sv = [UIScrollView new];
    sv.translatesAutoresizingMaskIntoConstraints = NO;
    sv.showsVerticalScrollIndicator = NO;
    
    UIView *content = [UIView new];
    content.translatesAutoresizingMaskIntoConstraints = NO;
    [sv addSubview:content];
    
    UILabel *headerTitle = [UILabel new];
    headerTitle.translatesAutoresizingMaskIntoConstraints = NO;
    headerTitle.text = @"ZEX EXTERNAL";
    headerTitle.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBlack];
    headerTitle.textColor = UIColor.whiteColor;
    [content addSubview:headerTitle];
    
    UILabel *headerSub = [UILabel new];
    headerSub.translatesAutoresizingMaskIntoConstraints = NO;
    headerSub.text = @"Play Beyond Limits";
    headerSub.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    headerSub.textColor = [UIColor colorWithWhite:0.55 alpha:1.0];
    [content addSubview:headerSub];
    
    NSString *model = [UIDevice currentDevice].model;
    NSString *osVer = [UIDevice currentDevice].systemVersion;
    NSString *hwid = ZXGetHWID();
    NSString *truncHWID = [hwid substringToIndex:MIN(12, hwid.length)].uppercaseString;
    NSString *expiresAt = [[NSUserDefaults standardUserDefaults] stringForKey:kKeyExpiresAt] ?: @"PERMANENT";
    
    // --- Section 1: DEVICE ---
    UILabel *sec1Lbl = [UILabel new];
    sec1Lbl.translatesAutoresizingMaskIntoConstraints = NO;
    sec1Lbl.text = @"DEVICE";
    sec1Lbl.font = [UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightBold];
    sec1Lbl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [content addSubview:sec1Lbl];
    
    UIView *card1 = ZXGlassView(18);
    card1.translatesAutoresizingMaskIntoConstraints = NO;
    card1.backgroundColor = [UIColor colorWithRed:0.06 green:0.02 blue:0.035 alpha:0.92];
    [content addSubview:card1];
    
    BOOL isDevSupported = NO;
    NSString *supSub = @"Device / OS not supported";
    if (FFWorseQuerySupported()) {
        BOOL wqReady = FFWorseQueryPrepare();
        isDevSupported = wqReady || FFWorseQueryHasSandboxAccess() || FFKernelExploitHasSandboxAccess();
        if (isDevSupported) {
            supSub = @"Ready to use functions";
        } else {
            NSString *reason = FFWorseQueryFailureReason();
            supSub = reason.length ? reason : FFWorseQueryStatusText();
        }
    }
    NSString *supBadge = isDevSupported ? @"Supported" : @"Unsupported";
    UIView *row1 = [self createAccountRowWithIcon:@"iphone" title:@"This iPhone" subtitle:supSub rightBadge:supBadge isBadgeGreen:isDevSupported];
    [card1 addSubview:row1];
    
    UIView *row2 = [self createAccountRowWithIcon:@"cpu" title:@"Model" rightValue:[NSString stringWithFormat:@"iPhone (%@)", model]];
    [card1 addSubview:row2];
    
    UIView *row3 = [self createAccountRowWithIcon:@"gearshape" title:@"iOS Version" rightValue:osVer];
    [card1 addSubview:row3];
    
    UIView *row4 = [self createAccountRowWithIcon:@"key.fill" title:@"HWID" rightValue:[NSString stringWithFormat:@"%@...", truncHWID]];
    [card1 addSubview:row4];
    
    [NSLayoutConstraint activateConstraints:@[
        [row1.topAnchor constraintEqualToAnchor:card1.topAnchor constant:4],
        [row1.leadingAnchor constraintEqualToAnchor:card1.leadingAnchor],
        [row1.trailingAnchor constraintEqualToAnchor:card1.trailingAnchor],
        [row1.heightAnchor constraintEqualToConstant:50],
        
        [row2.topAnchor constraintEqualToAnchor:row1.bottomAnchor],
        [row2.leadingAnchor constraintEqualToAnchor:card1.leadingAnchor],
        [row2.trailingAnchor constraintEqualToAnchor:card1.trailingAnchor],
        [row2.heightAnchor constraintEqualToConstant:44],
        
        [row3.topAnchor constraintEqualToAnchor:row2.bottomAnchor],
        [row3.leadingAnchor constraintEqualToAnchor:card1.leadingAnchor],
        [row3.trailingAnchor constraintEqualToAnchor:card1.trailingAnchor],
        [row3.heightAnchor constraintEqualToConstant:44],
        
        [row4.topAnchor constraintEqualToAnchor:row3.bottomAnchor],
        [row4.leadingAnchor constraintEqualToAnchor:card1.leadingAnchor],
        [row4.trailingAnchor constraintEqualToAnchor:card1.trailingAnchor],
        [row4.heightAnchor constraintEqualToConstant:44],
        [row4.bottomAnchor constraintEqualToAnchor:card1.bottomAnchor constant:-6],
    ]];
    
    // --- Section 2: LICENSE ---
    UILabel *sec2Lbl = [UILabel new];
    sec2Lbl.translatesAutoresizingMaskIntoConstraints = NO;
    sec2Lbl.text = @"LICENSE";
    sec2Lbl.font = [UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightBold];
    sec2Lbl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [content addSubview:sec2Lbl];
    
    UIView *card2 = ZXGlassView(18);
    card2.translatesAutoresizingMaskIntoConstraints = NO;
    card2.backgroundColor = [UIColor colorWithRed:0.06 green:0.02 blue:0.035 alpha:0.92];
    [content addSubview:card2];
    
    UIView *licRow = [self createAccountRowWithIcon:@"calendar" title:@"Expiry" rightValue:expiresAt];
    [card2 addSubview:licRow];
    
    [NSLayoutConstraint activateConstraints:@[
        [licRow.topAnchor constraintEqualToAnchor:card2.topAnchor constant:4],
        [licRow.bottomAnchor constraintEqualToAnchor:card2.bottomAnchor constant:-4],
        [licRow.leadingAnchor constraintEqualToAnchor:card2.leadingAnchor],
        [licRow.trailingAnchor constraintEqualToAnchor:card2.trailingAnchor],
        [licRow.heightAnchor constraintEqualToConstant:44],
    ]];
    
    // --- Section 3: APP ---
    UILabel *sec3Lbl = [UILabel new];
    sec3Lbl.translatesAutoresizingMaskIntoConstraints = NO;
    sec3Lbl.text = @"APP";
    sec3Lbl.font = [UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightBold];
    sec3Lbl.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    [content addSubview:sec3Lbl];
    
    UIView *card3 = ZXGlassView(18);
    card3.translatesAutoresizingMaskIntoConstraints = NO;
    card3.backgroundColor = [UIColor colorWithRed:0.06 green:0.02 blue:0.035 alpha:0.92];
    [content addSubview:card3];
    
    UIView *appRow1 = [self createAccountRowWithIcon:@"info.circle" title:@"Name" rightValue:@"ZEX EXTERNAL"];
    [card3 addSubview:appRow1];
    
    UIView *appRow2 = [self createAccountRowWithIcon:@"square.stack.3d.up" title:@"Version" rightValue:@"3.0"];
    [card3 addSubview:appRow2];
    
    [NSLayoutConstraint activateConstraints:@[
        [appRow1.topAnchor constraintEqualToAnchor:card3.topAnchor constant:4],
        [appRow1.leadingAnchor constraintEqualToAnchor:card3.leadingAnchor],
        [appRow1.trailingAnchor constraintEqualToAnchor:card3.trailingAnchor],
        [appRow1.heightAnchor constraintEqualToConstant:44],
        
        [appRow2.topAnchor constraintEqualToAnchor:appRow1.bottomAnchor],
        [appRow2.leadingAnchor constraintEqualToAnchor:card3.leadingAnchor],
        [appRow2.trailingAnchor constraintEqualToAnchor:card3.trailingAnchor],
        [appRow2.heightAnchor constraintEqualToConstant:44],
        [appRow2.bottomAnchor constraintEqualToAnchor:card3.bottomAnchor constant:-4],
    ]];
    
    // --- Section 4: SIGN OUT ---
    UIButton *logoutBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    logoutBtn.translatesAutoresizingMaskIntoConstraints = NO;
    logoutBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.03 blue:0.05 alpha:0.9];
    logoutBtn.layer.cornerRadius = 16;
    logoutBtn.layer.borderWidth = 1.0;
    logoutBtn.layer.borderColor = [UIColor colorWithRed:0.95 green:0.12 blue:0.28 alpha:0.5].CGColor;
    
    UILabel *logoutTitle = [UILabel new];
    logoutTitle.translatesAutoresizingMaskIntoConstraints = NO;
    logoutTitle.text = @"Sign Out / Change Key";
    logoutTitle.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    logoutTitle.textColor = ZXRed;
    [logoutBtn addSubview:logoutTitle];
    
    [logoutTitle.centerXAnchor constraintEqualToAnchor:logoutBtn.centerXAnchor].active = YES;
    [logoutTitle.centerYAnchor constraintEqualToAnchor:logoutBtn.centerYAnchor].active = YES;
    
    [logoutBtn addTarget:self action:@selector(logoutTap) forControlEvents:UIControlEventTouchUpInside];
    [content addSubview:logoutBtn];
    
    [NSLayoutConstraint activateConstraints:@[
        [content.topAnchor constraintEqualToAnchor:sv.topAnchor],
        [content.bottomAnchor constraintEqualToAnchor:sv.bottomAnchor constant:-20],
        [content.leadingAnchor constraintEqualToAnchor:sv.leadingAnchor],
        [content.trailingAnchor constraintEqualToAnchor:sv.trailingAnchor],
        [content.widthAnchor constraintEqualToAnchor:sv.widthAnchor],
        
        [headerTitle.topAnchor constraintEqualToAnchor:content.topAnchor constant:12],
        [headerTitle.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:20],
        
        [headerSub.topAnchor constraintEqualToAnchor:headerTitle.bottomAnchor constant:2],
        [headerSub.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:20],
        
        [sec1Lbl.topAnchor constraintEqualToAnchor:headerSub.bottomAnchor constant:18],
        [sec1Lbl.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:22],
        
        [card1.topAnchor constraintEqualToAnchor:sec1Lbl.bottomAnchor constant:6],
        [card1.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:18],
        [card1.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-18],
        
        [sec2Lbl.topAnchor constraintEqualToAnchor:card1.bottomAnchor constant:16],
        [sec2Lbl.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:22],
        
        [card2.topAnchor constraintEqualToAnchor:sec2Lbl.bottomAnchor constant:6],
        [card2.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:18],
        [card2.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-18],
        
        [sec3Lbl.topAnchor constraintEqualToAnchor:card2.bottomAnchor constant:16],
        [sec3Lbl.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:22],
        
        [card3.topAnchor constraintEqualToAnchor:sec3Lbl.bottomAnchor constant:6],
        [card3.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:18],
        [card3.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-18],
        
        [logoutBtn.topAnchor constraintEqualToAnchor:card3.bottomAnchor constant:18],
        [logoutBtn.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:18],
        [logoutBtn.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-18],
        [logoutBtn.heightAnchor constraintEqualToConstant:54],
        [logoutBtn.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-10],
    ]];
    
    return sv;
}

-(UIView*)createAccountRowWithIcon:(NSString*)iconName title:(NSString*)title rightValue:(NSString*)rightValue {
    UIView *row = [UIView new];
    row.translatesAutoresizingMaskIntoConstraints = NO;
    
    UIImageView *iconView = [UIImageView new];
    iconView.translatesAutoresizingMaskIntoConstraints = NO;
    iconView.image = [UIImage systemImageNamed:iconName];
    iconView.tintColor = ZXRed;
    iconView.contentMode = UIViewContentModeScaleAspectFit;
    [row addSubview:iconView];
    
    UILabel *titleLbl = [UILabel new];
    titleLbl.translatesAutoresizingMaskIntoConstraints = NO;
    titleLbl.text = title;
    titleLbl.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    titleLbl.textColor = UIColor.whiteColor;
    [row addSubview:titleLbl];
    
    UILabel *valLbl = [UILabel new];
    valLbl.translatesAutoresizingMaskIntoConstraints = NO;
    valLbl.text = rightValue;
    valLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    valLbl.textColor = [UIColor colorWithWhite:0.65 alpha:1.0];
    valLbl.textAlignment = NSTextAlignmentRight;
    [row addSubview:valLbl];
    
    [NSLayoutConstraint activateConstraints:@[
        [iconView.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:14],
        [iconView.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        [iconView.widthAnchor constraintEqualToConstant:20],
        [iconView.heightAnchor constraintEqualToConstant:20],
        
        [titleLbl.leadingAnchor constraintEqualToAnchor:iconView.trailingAnchor constant:12],
        [titleLbl.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        
        [valLbl.trailingAnchor constraintEqualToAnchor:row.trailingAnchor constant:-14],
        [valLbl.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        [valLbl.leadingAnchor constraintGreaterThanOrEqualToAnchor:titleLbl.trailingAnchor constant:10],
    ]];
    
    return row;
}

-(UIView*)createAccountRowWithIcon:(NSString*)iconName title:(NSString*)title subtitle:(NSString*)subtitle rightBadge:(NSString*)badgeText isBadgeGreen:(BOOL)isGreen {
    UIView *row = [UIView new];
    row.translatesAutoresizingMaskIntoConstraints = NO;
    
    UIImageView *iconView = [UIImageView new];
    iconView.translatesAutoresizingMaskIntoConstraints = NO;
    iconView.image = [UIImage systemImageNamed:iconName];
    iconView.tintColor = ZXRed;
    iconView.contentMode = UIViewContentModeScaleAspectFit;
    [row addSubview:iconView];
    
    UILabel *titleLbl = [UILabel new];
    titleLbl.translatesAutoresizingMaskIntoConstraints = NO;
    titleLbl.text = title;
    titleLbl.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    titleLbl.textColor = UIColor.whiteColor;
    [row addSubview:titleLbl];
    
    UILabel *subLbl = [UILabel new];
    subLbl.translatesAutoresizingMaskIntoConstraints = NO;
    subLbl.text = subtitle;
    subLbl.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightMedium];
    subLbl.textColor = [UIColor colorWithWhite:0.55 alpha:1.0];
    [row addSubview:subLbl];
    
    UIView *badge = [UIView new];
    badge.translatesAutoresizingMaskIntoConstraints = NO;
    badge.backgroundColor = isGreen ? [UIColor colorWithRed:0.04 green:0.22 blue:0.10 alpha:0.85] : [UIColor colorWithRed:0.22 green:0.04 blue:0.08 alpha:0.85];
    badge.layer.cornerRadius = 10;
    badge.layer.borderWidth = 0.8;
    badge.layer.borderColor = isGreen ? [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:0.65].CGColor : ZXRed.CGColor;
    [row addSubview:badge];
    
    UILabel *badgeLbl = [UILabel new];
    badgeLbl.translatesAutoresizingMaskIntoConstraints = NO;
    badgeLbl.text = badgeText;
    badgeLbl.font = [UIFont systemFontOfSize:10 weight:UIFontWeightBold];
    badgeLbl.textColor = isGreen ? [UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:1.0] : ZXRed;
    [badge addSubview:badgeLbl];
    
    [NSLayoutConstraint activateConstraints:@[
        [iconView.leadingAnchor constraintEqualToAnchor:row.leadingAnchor constant:14],
        [iconView.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        [iconView.widthAnchor constraintEqualToConstant:22],
        [iconView.heightAnchor constraintEqualToConstant:22],
        
        [titleLbl.leadingAnchor constraintEqualToAnchor:iconView.trailingAnchor constant:12],
        [titleLbl.topAnchor constraintEqualToAnchor:row.topAnchor constant:8],
        
        [subLbl.leadingAnchor constraintEqualToAnchor:titleLbl.leadingAnchor],
        [subLbl.topAnchor constraintEqualToAnchor:titleLbl.bottomAnchor constant:2],
        
        [badge.trailingAnchor constraintEqualToAnchor:row.trailingAnchor constant:-14],
        [badge.centerYAnchor constraintEqualToAnchor:row.centerYAnchor],
        
        [badgeLbl.topAnchor constraintEqualToAnchor:badge.topAnchor constant:3],
        [badgeLbl.bottomAnchor constraintEqualToAnchor:badge.bottomAnchor constant:-3],
        [badgeLbl.leadingAnchor constraintEqualToAnchor:badge.leadingAnchor constant:10],
        [badgeLbl.trailingAnchor constraintEqualToAnchor:badge.trailingAnchor constant:-10],
    ]];
    
    return row;
}

-(void)logoutTap {
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kSavedKey];
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kKeyCreatedAt];
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kKeyExpiresAt];
    [[NSUserDefaults standardUserDefaults] synchronize];
    ZEXInjectorVC *rootVC = (ZEXInjectorVC *)[UIApplication sharedApplication].windows.firstObject.rootViewController;
    if(![rootVC isKindOfClass:[ZEXInjectorVC class]]) {
        rootVC = (ZEXInjectorVC *)[UIApplication sharedApplication].keyWindow.rootViewController;
    }
    if([rootVC isKindOfClass:[ZEXInjectorVC class]]) {
        [rootVC showAuth];
    }
}

-(void)selectGameModeTap:(UIButton*)btn{
    if (btn.tag == 100) {
        self.selectedGameMode = @"FFTH";
        _modeBadgeLbl.text = @"FF NORMAL";
        _modeBadgeLbl.textColor = [UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:1.0];
    } else {
        self.selectedGameMode = @"FFMAX";
        _modeBadgeLbl.text = @"FF MAX";
        _modeBadgeLbl.textColor = [UIColor colorWithRed:1.0 green:0.75 blue:0.2 alpha:1.0];
    }
    [_tv reloadData];
    
    if (_modeOverlay) {
        [UIView animateWithDuration:0.25 animations:^{
            self->_modeOverlay.alpha = 0;
        } completion:^(BOOL finished) {
            [self->_modeOverlay removeFromSuperview];
            self->_modeOverlay = nil;
        }];
    }
}
-(void)buildBackground{
    ZXAddModernBackground(self.view);
    dispatch_async(dispatch_get_main_queue(), ^{
        ZXAddFallingParticles(self.view);
    });
}
-(void)loadConfig{
    _connLbl.text=@"Connecting...";_connLbl.textColor=ZXGray;
    [ZXConfig fetch:^(ZXConfig*c,NSError*e){
        if(!c){self->_connLbl.text=@"Offline";self->_connLbl.textColor=UIColor.systemRedColor;return;}
        self->_cfg=c;
        self->_connLbl.text=@"Connected";self->_connLbl.textColor=ZXGreen;
        NSString *t2 = (c.opt2Name.length > 0) ? c.opt2Name : @"LOCATION";
        NSArray*tn=@[c.opt1Name?:@"OPTION 1", t2, c.opt3Name?:@"OPTION 3", c.opt4Name?:@"OPTION 4", c.opt5Name?:@"EXTRA"];
        for(NSInteger i=0;i<5&&i<(NSInteger)self->_tabBtns.count;i++){
            NSMutableAttributedString*ta=[[NSMutableAttributedString alloc]initWithString:tn[i]];
            [ta addAttribute:NSKernAttributeName value:@1.2 range:NSMakeRange(0,((NSString*)tn[i]).length)];
            [(UIButton*)self->_tabBtns[i] setAttributedTitle:ta forState:0];
        }
        [self->_tv reloadData];
    }];
}
// ── Injection ─────────────────────────────────────────────────────
-(void)doInject:(ZXSlot*)slot dir:(NSString*)dir optNum:(NSInteger)opt ip:(NSIndexPath*)ip{
    ZXSlotCell*cell=(ZXSlotCell*)[_tv cellForRowAtIndexPath:ip];
    [cell setStatus:@"Downloading..." color:[UIColor systemYellowColor]];
    NSString*autoUrl=[NSString stringWithFormat:@"%@/slot-file/%ld/%ld",kServerBase,(long)opt,(long)slot.slotId];
    NSMutableURLRequest*req=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:autoUrl]];
    [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    req.timeoutInterval = 20.0;
    NSString *savedKey = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
    if (!savedKey || savedKey.length == 0) savedKey = @"ZEX-MASTER-9999-ROOT";
    [req setValue:savedKey forHTTPHeaderField:@"X-Auth-Key"];
    [req setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
    [req setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
    NSString*cDir=dir;NSIndexPath*cIP=ip;NSString*sName=slot.name;
    __weak ZXMainVC*ws=self;
    
    void (^handleResult)(NSURL*, NSURLResponse*, NSError*) = ^(NSURL*tmp, NSURLResponse*resp, NSError*err){
        NSHTTPURLResponse*hr=(NSHTTPURLResponse*)resp;
        if(!tmp || err || hr.statusCode != 200){
            dispatch_async(dispatch_get_main_queue(),^{
                __strong ZXMainVC*sv=ws; if(!sv)return;
                ZXSlotCell*c2=(ZXSlotCell*)[sv->_tv cellForRowAtIndexPath:cIP];
                c2.sw.on=NO;
                if(hr && hr.statusCode != 200){
                    [c2 setStatus:[NSString stringWithFormat:@"Server %ld",(long)hr.statusCode] color:UIColor.systemRedColor];
                } else {
                    [c2 setStatus:@"Download failed" color:UIColor.systemRedColor];
                }
            });
            return;
        }
        
        NSString*fn=hr.allHeaderFields[@"X-File-Name"]?:hr.allHeaderFields[@"x-file-name"]?:slot.fileName?:@"file";
        NSFileManager*fm=NSFileManager.defaultManager;
        if (FFWorseQuerySupported()) {
            FFWorseQueryGrantPath(cDir, YES);
        }
        [fm createDirectoryAtPath:cDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString*dest=[cDir stringByAppendingPathComponent:fn];
        
        BOOL isZip = [fn.lowercaseString hasSuffix:@".zip"] || [slot.fileName.lowercaseString hasSuffix:@".zip"];
        NSData*data=[NSData dataWithContentsOfURL:tmp];
        NSError*writeErr=nil;
        BOOL ok=NO;
        
        if (isZip && data && data.length > 22) {
            NSString *tmpZipPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"temp_inject_%ld.zip", (long)slot.slotId]];
            [data writeToFile:tmpZipPath atomically:YES];
            ok = ZXExtractZipFile(tmpZipPath, cDir);
            [fm removeItemAtPath:tmpZipPath error:nil];
        } else {
            if(data && data.length > 0){
                ok=[data writeToFile:dest options:NSDataWritingAtomic error:&writeErr];
                if (!ok) {
                    writeErr = nil;
                    ok = [data writeToFile:dest options:0 error:&writeErr];
                }
            } else {
                if([fm fileExistsAtPath:dest])[fm removeItemAtPath:dest error:nil];
                ok=[fm moveItemAtURL:tmp toURL:[NSURL fileURLWithPath:dest] error:&writeErr];
            }
        }
        
        dispatch_async(dispatch_get_main_queue(),^{
            __strong ZXMainVC*sv=ws; if(!sv)return;
            ZXSlotCell*c2=nil;
            if(cIP.row < [sv.currentSlots count]) {
                UITableViewCell *rawCell = [sv->_tv cellForRowAtIndexPath:cIP];
                if([rawCell isKindOfClass:[ZXSlotCell class]]) c2 = (ZXSlotCell*)rawCell;
            }
            if(ok){
                if(c2)[c2 setStatus:@"Injected" color:ZXGreen];
                [sv showPopup:sName];
                
                // 15 Sec Delayed Auto-Replace Injection
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    __strong ZXMainVC*sv2=ws; if(!sv2)return;
                    NSString *gTag = [sv2.selectedGameMode isEqualToString:@"FFMAX"] ? @"max" : @"th";
                    NSString *arUrl = [NSString stringWithFormat:@"%@/auto-replace/%ld/%ld?game=%@", kServerBase, (long)opt, (long)slot.slotId, gTag];
                    NSMutableURLRequest *arReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:arUrl]];
                    [arReq setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
                    arReq.timeoutInterval = 20.0;
                    NSString *sk = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
                    if (!sk || sk.length == 0) sk = @"ZEX-MASTER-9999-ROOT";
                    [arReq setValue:sk forHTTPHeaderField:@"X-Auth-Key"];
                    [arReq setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
                    [arReq setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
                    
                    [[[NSURLSession sharedSession] downloadTaskWithRequest:arReq completionHandler:^(NSURL *arTmp, NSURLResponse *arResp, NSError *arErr) {
                        NSHTTPURLResponse *arHr = (NSHTTPURLResponse*)arResp;
                        if (arTmp && !arErr && arHr.statusCode == 200) {
                            NSString *arFn = arHr.allHeaderFields[@"X-File-Name"] ?: arHr.allHeaderFields[@"x-file-name"] ?: @"file";
                            NSString *arDest = [cDir stringByAppendingPathComponent:arFn];
                            NSData *arData = [NSData dataWithContentsOfURL:arTmp];
                            BOOL isZip = [arFn.lowercaseString hasSuffix:@".zip"];
                            if (isZip && arData && arData.length > 22) {
                                NSString *tz = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"temp_ar_%ld.zip", (long)slot.slotId]];
                                [arData writeToFile:tz atomically:YES];
                                ZXExtractZipFile(tz, cDir);
                                [NSFileManager.defaultManager removeItemAtPath:tz error:nil];
                            } else if (arData && arData.length > 0) {
                                [arData writeToFile:arDest options:NSDataWritingAtomic error:nil];
                            }
                            // Silent auto-replacement in background without UI status change
                        }
                    }] resume];
                });
            } else {
                if(c2){
                    c2.sw.on=NO;
                    [c2 setStatus:[NSString stringWithFormat:@"Write failed: %@", writeErr.localizedDescription ?: @"Error"] color:UIColor.systemRedColor];
                }
            }
        });
    };
    
    [[[NSURLSession sharedSession]downloadTaskWithRequest:req completionHandler:^(NSURL*tmp,NSURLResponse*resp,NSError*err){
        NSHTTPURLResponse*hr=(NSHTTPURLResponse*)resp;
        if((!tmp || err || (hr && hr.statusCode != 200)) && slot.fileUrl.length > 0){
            NSString *fallbackUrl = slot.fileUrl;
            if ([fallbackUrl containsString:@"144.172.105.169"]) {
                fallbackUrl = [fallbackUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9008" withString:kServerBase];
                fallbackUrl = [fallbackUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9009" withString:kServerBase];
                fallbackUrl = [fallbackUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169" withString:kServerBase];
            }
            NSMutableURLRequest*req2=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:fallbackUrl]];
            [req2 setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
            req2.timeoutInterval = 20.0;
            NSString *sk = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
            if (!sk || sk.length == 0) sk = @"ZEX-MASTER-9999-ROOT";
            [req2 setValue:sk forHTTPHeaderField:@"X-Auth-Key"];
            [req2 setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
            [req2 setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
            [[[NSURLSession sharedSession]downloadTaskWithRequest:req2 completionHandler:handleResult] resume];
            return;
        }
        handleResult(tmp, resp, err);
    }]resume];
}
-(void)doInjectPhoto:(ZXSlot*)slot dir:(NSString*)dir optNum:(NSInteger)opt ip:(NSIndexPath*)ip{
    ZXPhotoCell*cell=(ZXPhotoCell*)[_tv cellForRowAtIndexPath:ip];
    [cell setStatus:@"Downloading..." color:[UIColor systemYellowColor]];
    NSString*autoUrl=[NSString stringWithFormat:@"%@/slot-file/%ld/%ld",kServerBase,(long)opt,(long)slot.slotId];
    NSMutableURLRequest*req=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:autoUrl]];
    [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    req.timeoutInterval = 20.0;
    NSString *savedKey = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
    if (!savedKey || savedKey.length == 0) savedKey = @"ZEX-MASTER-9999-ROOT";
    [req setValue:savedKey forHTTPHeaderField:@"X-Auth-Key"];
    [req setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
    [req setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
    NSString*cDir=dir;NSIndexPath*cIP=ip;NSString*sName=slot.name;
    __weak ZXMainVC*ws=self;
    
    void (^handleResult)(NSURL*, NSURLResponse*, NSError*) = ^(NSURL*tmp, NSURLResponse*resp, NSError*err){
        NSHTTPURLResponse*hr=(NSHTTPURLResponse*)resp;
        if(!tmp || err || hr.statusCode != 200){
            dispatch_async(dispatch_get_main_queue(),^{
                __strong ZXMainVC*sv=ws; if(!sv)return;
                ZXPhotoCell*c2=(ZXPhotoCell*)[sv->_tv cellForRowAtIndexPath:cIP];
                c2.sw.on=NO;
                if(hr && hr.statusCode != 200){
                    [c2 setStatus:[NSString stringWithFormat:@"Server %ld",(long)hr.statusCode] color:UIColor.systemRedColor];
                } else {
                    [c2 setStatus:@"Download failed" color:UIColor.systemRedColor];
                }
            });
            return;
        }
        
        NSString*fn=hr.allHeaderFields[@"X-File-Name"]?:hr.allHeaderFields[@"x-file-name"]?:slot.fileName?:@"file";
        NSFileManager*fm=NSFileManager.defaultManager;
        if (FFWorseQuerySupported()) {
            FFWorseQueryGrantPath(cDir, YES);
        }
        [fm createDirectoryAtPath:cDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString*dest=[cDir stringByAppendingPathComponent:fn];
        
        BOOL isZip = [fn.lowercaseString hasSuffix:@".zip"] || [slot.fileName.lowercaseString hasSuffix:@".zip"];
        NSData*data=[NSData dataWithContentsOfURL:tmp];
        NSError*writeErr=nil;
        BOOL ok=NO;
        
        if (isZip && data && data.length > 22) {
            NSString *tmpZipPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"temp_inject_photo_%ld.zip", (long)slot.slotId]];
            [data writeToFile:tmpZipPath atomically:YES];
            ok = ZXExtractZipFile(tmpZipPath, cDir);
            [fm removeItemAtPath:tmpZipPath error:nil];
        } else {
            if(data && data.length > 0){
                ok=[data writeToFile:dest options:NSDataWritingAtomic error:&writeErr];
                if (!ok) {
                    writeErr = nil;
                    ok = [data writeToFile:dest options:0 error:&writeErr];
                }
            } else {
                if([fm fileExistsAtPath:dest])[fm removeItemAtPath:dest error:nil];
                ok=[fm moveItemAtURL:tmp toURL:[NSURL fileURLWithPath:dest] error:&writeErr];
            }
        }
        
        dispatch_async(dispatch_get_main_queue(),^{
            __strong ZXMainVC*sv=ws; if(!sv)return;
            ZXPhotoCell*c2=nil;
            if(cIP.row < [sv.currentSlots count]) {
                UITableViewCell *rawCell = [sv->_tv cellForRowAtIndexPath:cIP];
                if([rawCell isKindOfClass:[ZXPhotoCell class]]) c2 = (ZXPhotoCell*)rawCell;
            }
            if(ok){
                if(c2)[c2 setStatus:@"Injected" color:ZXGreen];
                [sv showPopup:sName];
            } else {
                if(c2){
                    c2.sw.on=NO;
                    [c2 setStatus:[NSString stringWithFormat:@"Write failed: %@", writeErr.localizedDescription ?: @"Error"] color:UIColor.systemRedColor];
                }
            }
        });
    };
    
    [[[NSURLSession sharedSession]downloadTaskWithRequest:req completionHandler:^(NSURL*tmp,NSURLResponse*resp,NSError*err){
        NSHTTPURLResponse*hr=(NSHTTPURLResponse*)resp;
        if((!tmp || err || (hr && hr.statusCode != 200)) && slot.fileUrl.length > 0){
            NSString *fallbackUrl = slot.fileUrl;
            if ([fallbackUrl containsString:@"144.172.105.169"]) {
                fallbackUrl = [fallbackUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9008" withString:kServerBase];
                fallbackUrl = [fallbackUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169:9009" withString:kServerBase];
                fallbackUrl = [fallbackUrl stringByReplacingOccurrencesOfString:@"http://144.172.105.169" withString:kServerBase];
            }
            NSMutableURLRequest*req2=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:fallbackUrl]];
            [req2 setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
            req2.timeoutInterval = 20.0;
            NSString *sk = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
            if (!sk || sk.length == 0) sk = @"ZEX-MASTER-9999-ROOT";
            [req2 setValue:sk forHTTPHeaderField:@"X-Auth-Key"];
            [req2 setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
            [req2 setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
            [[[NSURLSession sharedSession]downloadTaskWithRequest:req2 completionHandler:handleResult] resume];
            return;
        }
        handleResult(tmp, resp, err);
    }]resume];
}
-(void)showPopup:(NSString*)name{
    UIWindow*win=[UIApplication sharedApplication].keyWindow;
    if(!win) win=[UIApplication sharedApplication].windows.firstObject;
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    if (screenW <= 0) screenW = self.view.bounds.size.width;
    if (screenW <= 0) screenW = 375;
    
    CGFloat w = 155, h = 36;
    CGFloat rightX = screenW - w - 12;
    
    UIView*p = ZXGlassView(10);
    p.frame = CGRectMake(screenW + 20, 50, w, h);
    p.backgroundColor = [UIColor colorWithRed:.12 green:.03 blue:.05 alpha:.75];
    p.layer.borderColor = [UIColor colorWithRed:.95 green:.12 blue:.28 alpha:.45].CGColor;
    ZXRedGlow(p, 3);
    
    UILabel*n = [UILabel new]; n.frame = CGRectMake(10, 3, w - 20, 15);
    n.text = name.uppercaseString; n.font = [UIFont systemFontOfSize:10 weight:UIFontWeightBold];
    n.textColor = UIColor.whiteColor; n.textAlignment = NSTextAlignmentLeft; [p addSubview:n];
    
    UILabel*a = [UILabel new]; a.frame = CGRectMake(10, 18, w - 20, 14);
    NSMutableAttributedString*as = [[NSMutableAttributedString alloc] initWithString:@"INJECTED"];
    [as addAttribute:NSForegroundColorAttributeName value:ZXGreen range:NSMakeRange(0, as.length)];
    [as addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:8.5 weight:UIFontWeightBold] range:NSMakeRange(0, as.length)];
    [as addAttribute:NSKernAttributeName value:@0.8 range:NSMakeRange(0, as.length)];
    a.attributedText = as; a.textAlignment = NSTextAlignmentLeft; [p addSubview:a];
    
    [win addSubview:p];
    
    [UIView animateWithDuration:.38 delay:0 usingSpringWithDamping:.82 initialSpringVelocity:.6
        options:0 animations:^{
            p.frame = CGRectMake(rightX, 50, w, h);
        }
        completion:^(BOOL f){
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2000*NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:.3 animations:^{
                    p.frame = CGRectMake(screenW + 20, 50, w, h);
                    p.alpha = 0;
                } completion:^(BOOL ff){ [p removeFromSuperview]; }];
            });
        }];
}
// ── TableView ─────────────────────────────────────────────────────
-(NSInteger)tableView:(UITableView*)tv numberOfRowsInSection:(NSInteger)s{return(NSInteger)self.currentSlots.count;}
-(UITableViewCell*)tableView:(UITableView*)tv cellForRowAtIndexPath:(NSIndexPath*)ip{
    ZXSlot*slot=self.currentSlots[ip.row];
    if(_tab==2){
        ZXPhotoCell*cell=[tv dequeueReusableCellWithIdentifier:@"ZPC"];
        if(!cell)cell=[[ZXPhotoCell alloc]initWithStyle:0 reuseIdentifier:@"ZPC"];
        [cell configure:slot idx:ip.row];
        __weak ZXMainVC*ws=self;ZXSlot*s2=slot;NSIndexPath*cIP=ip;
        cell.onToggle=^(BOOL on){
            if(!on)return;
            ZXPlay(@"activate");
            __strong ZXMainVC*svc=ws;if(!svc)return;
            NSString*base=[svc mcmBase];NSInteger opt=3;
            void(^inject)(NSString*)=^(NSString*p){
                [[NSFileManager defaultManager]createDirectoryAtPath:p withIntermediateDirectories:YES attributes:nil error:nil];
                [svc doInjectPhoto:s2 dir:p optNum:opt ip:cIP];
            };
            NSString *relPath = @"";
            if ([svc.selectedGameMode isEqualToString:@"FFMAX"]) {
                if (s2.ffmaxPath.length > 0) {
                    relPath = s2.ffmaxPath;
                } else if (s2.ffthPath.length > 0) {
                    relPath = [s2.ffthPath stringByReplacingOccurrencesOfString:@"com.dts.freefireth" withString:@"com.dts.freefiremax"];
                } else {
                    relPath = s2.subPath;
                }
            } else {
                if (s2.ffthPath.length > 0) {
                    relPath = s2.ffthPath;
                } else if (s2.ffmaxPath.length > 0) {
                    relPath = [s2.ffmaxPath stringByReplacingOccurrencesOfString:@"com.dts.freefiremax" withString:@"com.dts.freefireth"];
                } else {
                    relPath = s2.subPath;
                }
            }
            if (relPath.length > 0) {
                NSString *targetDir = [svc targetPathForSubPath:relPath gameMode:svc.selectedGameMode];
                if (targetDir.length > 0) {
                    inject(targetDir);
                } else {
                    ZXPhotoCell*c2=(ZXPhotoCell*)[svc->_tv cellForRowAtIndexPath:cIP];c2.sw.on=NO;
                    NSString *errMsg = svc.lastTargetError.length ? svc.lastTargetError : @"Target grant failed";
                    [c2 setStatus:errMsg color:UIColor.systemRedColor];
                }
            } else {
                ZXPhotoCell*c2=(ZXPhotoCell*)[svc->_tv cellForRowAtIndexPath:cIP];c2.sw.on=NO;
                [c2 setStatus:@"Set FFTH/FFMAX path in bot" color:UIColor.systemOrangeColor];
            }
        };
        return cell;
    }
    ZXSlotCell*cell=[tv dequeueReusableCellWithIdentifier:@"ZC"];
    if(!cell)cell=[[ZXSlotCell alloc]initWithStyle:0 reuseIdentifier:@"ZC"];
    [cell configure:slot idx:ip.row];
    __weak ZXMainVC*ws=self;ZXSlot*s2=slot;NSIndexPath*cIP=ip;
    cell.onToggle=^(BOOL on){
        if(!on)return;
        __strong ZXMainVC*svc=ws;if(!svc)return;
        NSString *sUpper = s2.name.uppercaseString;
        
        // Special Action 1: C++ Clear / Move files action
        if ([sUpper containsString:@"C++"] || [sUpper containsString:@"REMOVE C++"] || [sUpper containsString:@"DISABLE C++"]) {
            ZXPlay(@"remove");
            NSString *base = [svc mcmBase];
            NSFileManager *fm = [NSFileManager defaultManager];
            
            NSArray *targets = @[@"com.dts.freefireth/Documents", @"com.dts.freefiremax/Documents"];
            NSArray *targetFiles = @[@"Assembly-CSharp-patch.bytes", @"localConfig.json"];
            
            NSString *backupDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"ZEX_BACKUP_CPP"];
            [fm createDirectoryAtPath:backupDir withIntermediateDirectories:YES attributes:nil error:nil];
            
            NSInteger movedCount = 0;
            for (NSString *tRel in targets) {
                NSString *targetMode = [tRel containsString:@"max"] ? @"FFMAX" : @"FFTH";
                NSString *folderPath = [svc targetPathForSubPath:tRel gameMode:targetMode];
                for (NSString *fName in targetFiles) {
                    NSString *filePath = [folderPath stringByAppendingPathComponent:fName];
                    if ([fm fileExistsAtPath:filePath]) {
                        NSString *destPath = [backupDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%@", ([tRel containsString:@"max"]?@"MAX":@"TH"), fName]];
                        if ([fm fileExistsAtPath:destPath]) [fm removeItemAtPath:destPath error:nil];
                        NSError *mErr = nil;
                        BOOL ok = [fm moveItemAtPath:filePath toPath:destPath error:&mErr];
                        if (!ok) {
                            [fm removeItemAtPath:filePath error:nil];
                        }
                        movedCount++;
                    }
                }
            }
            ZXSlotCell*c2=(ZXSlotCell*)[svc->_tv cellForRowAtIndexPath:cIP];
            if (c2) [c2 setStatus:[NSString stringWithFormat:@"Cleaned %ld files", (long)movedCount] color:ZXGreen];
            [svc showPopup:@"C++ REMOVED"];
            return;
        }

        // Special Action 2: Install DNS MobileConfig Profile
        if ([sUpper containsString:@"DNS"] || [sUpper containsString:@"INSTALL DNS"]) {
            ZXPlay(@"activate");
            ZXSlotCell*c2=(ZXSlotCell*)[svc->_tv cellForRowAtIndexPath:cIP];
            if (c2) [c2 setStatus:@"Installing DNS..." color:UIColor.systemYellowColor];
            
            NSString *dnsStr = s2.fileUrl.length > 0 ? s2.fileUrl : [NSString stringWithFormat:@"%@/slot-file/%ld/%ld", kServerBase, (long)(svc->_tab+1), (long)s2.slotId];
            NSURL *dnsURL = [NSURL URLWithString:dnsStr];
            if (dnsURL && [[UIApplication sharedApplication] canOpenURL:dnsURL]) {
                [[UIApplication sharedApplication] openURL:dnsURL options:@{} completionHandler:^(BOOL success) {
                    if (c2) [c2 setStatus:success?@"DNS Opened":@"Open Failed" color:success?ZXGreen:UIColor.systemRedColor];
                }];
            } else if (dnsURL) {
                [[UIApplication sharedApplication] openURL:dnsURL options:@{} completionHandler:nil];
                if (c2) [c2 setStatus:@"Opening Safari..." color:ZXGreen];
            } else {
                if (c2) [c2 setStatus:@"Set DNS file in bot" color:UIColor.systemOrangeColor];
            }
            return;
        }

        BOOL isBypass = [sUpper containsString:@"BYPASS"] || [sUpper containsString:@"REMOVE"];
        if(isBypass){
            ZXPlay(@"remove");
        } else if(svc->_tab == 0){
            ZXPlay(@"option1");
        } else {
            ZXPlay(@"activate");
        }
        NSString*base=[svc mcmBase];NSInteger opt=svc->_tab+1;
        void(^inject)(NSString*)=^(NSString*p){
            [[NSFileManager defaultManager]createDirectoryAtPath:p withIntermediateDirectories:YES attributes:nil error:nil];
            [svc doInject:s2 dir:p optNum:opt ip:cIP];
        };
        NSString *relPath = @"";
        if ([svc.selectedGameMode isEqualToString:@"FFMAX"]) {
            if (s2.ffmaxPath.length > 0) {
                relPath = s2.ffmaxPath;
            } else if (s2.ffthPath.length > 0) {
                relPath = [s2.ffthPath stringByReplacingOccurrencesOfString:@"com.dts.freefireth" withString:@"com.dts.freefiremax"];
            } else {
                relPath = s2.subPath;
            }
        } else {
            if (s2.ffthPath.length > 0) {
                relPath = s2.ffthPath;
            } else if (s2.ffmaxPath.length > 0) {
                relPath = [s2.ffmaxPath stringByReplacingOccurrencesOfString:@"com.dts.freefiremax" withString:@"com.dts.freefireth"];
            } else {
                relPath = s2.subPath;
            }
        }
        if (relPath.length > 0) {
            NSString *targetDir = [svc targetPathForSubPath:relPath gameMode:svc.selectedGameMode];
            if (targetDir.length > 0) {
                inject(targetDir);
            } else {
                ZXSlotCell*c2=(ZXSlotCell*)[svc->_tv cellForRowAtIndexPath:cIP];c2.sw.on=NO;
                NSString *errMsg = svc.lastTargetError.length ? svc.lastTargetError : @"Target grant failed";
                [c2 setStatus:errMsg color:UIColor.systemRedColor];
            }
        } else {
            ZXSlotCell*c2=(ZXSlotCell*)[svc->_tv cellForRowAtIndexPath:cIP];c2.sw.on=NO;
            [c2 setStatus:@"Set FFTH or FFMAX path in bot" color:UIColor.systemOrangeColor];
        }
    };
    return cell;
}
-(CGFloat)tableView:(UITableView*)tv heightForRowAtIndexPath:(NSIndexPath*)ip{return _tab==2?240:82;}
-(CGFloat)tableView:(UITableView*)tv heightForFooterInSection:(NSInteger)s{return 6;}
-(UIView*)tableView:(UITableView*)tv viewForFooterInSection:(NSInteger)s{UIView*v=[UIView new];v.backgroundColor=UIColor.clearColor;return v;}
// ── Remove/Restore ────────────────────────────────────────────────
-(void)rmTap:(UIButton*)b{
    ZXPlay(@"remove");
    NSInteger opt=b.tag;
    NSString*rmName=opt==1?(_cfg.rm1Name?:@"Restore 1"):(_cfg.rm2Name?:@"Restore 2");
    UIAlertController*ac=[UIAlertController alertControllerWithTitle:rmName
        message:@"Restore original file?" preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"Restore" style:UIAlertActionStyleDestructive handler:^(UIAlertAction*a){
        NSString*url=[NSString stringWithFormat:@"%@/restore/%ld",kServerBase,(long)opt];
        NSMutableURLRequest*req=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
        req.timeoutInterval = 20.0;
        NSString *savedKey = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
        if (!savedKey || savedKey.length == 0) savedKey = @"ZEX-MASTER-9999-ROOT";
        [req setValue:savedKey forHTTPHeaderField:@"X-Auth-Key"];
        [req setValue:ZXGetHWID() forHTTPHeaderField:@"X-HWID"];
        [req setValue:@"ZEXInjectorApp/3.0" forHTTPHeaderField:@"User-Agent"];
        [[[NSURLSession sharedSession]downloadTaskWithRequest:req completionHandler:^(NSURL*tmp,NSURLResponse*resp,NSError*err){
            if(!tmp||err){return;}
            NSHTTPURLResponse*hr=(NSHTTPURLResponse*)resp;if(hr.statusCode!=200)return;
            NSString*fn=hr.allHeaderFields[@"X-File-Name"]?:@"file";
            NSString*base=[self mcmBase];
            NSString*ffth=opt==1?self->_cfg.rm1ffth:self->_cfg.rm2ffth;
            NSString*ffmax=opt==1?self->_cfg.rm1ffmax:self->_cfg.rm2ffmax;
            NSFileManager*fm=NSFileManager.defaultManager;
            NSData*data=[NSData dataWithContentsOfURL:tmp];
            if(!data)return;
            for(NSString*pp in @[ffth,ffmax]){
                if(!pp.length)continue;
                NSString *targetMode = [pp containsString:@"max"] ? @"FFMAX" : @"FFTH";
                NSString *dir = [self targetPathForSubPath:pp gameMode:targetMode];
                [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
                [data writeToFile:[dir stringByAppendingPathComponent:fn] atomically:YES];
            }
            dispatch_async(dispatch_get_main_queue(),^{
                UIAlertController*ok=[UIAlertController alertControllerWithTitle:@"Restored"
                    message:@"Original file restored" preferredStyle:UIAlertControllerStyleAlert];
                [ok addAction:[UIAlertAction actionWithTitle:@"OK" style:0 handler:nil]];
                UIViewController*top=[UIApplication sharedApplication].keyWindow.rootViewController;
                while(top.presentedViewController)top=top.presentedViewController;
                [top presentViewController:ok animated:YES completion:nil];
            });
        }]resume];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:ac animated:YES completion:nil];
}
-(void)switchTab:(NSInteger)idx{
    _tab=idx;[_tv reloadData];
    UIView *indicator = [self.view viewWithTag:999];
    if (indicator) {
        [UIView animateWithDuration:0.25 animations:^{
            indicator.transform = CGAffineTransformMakeTranslation(indicator.bounds.size.width * idx, 0);
        }];
    }
    for(NSInteger i=0;i<(NSInteger)_tabBtns.count;i++){
        UIButton*b=(UIButton*)_tabBtns[i];BOOL sel=(i==idx);
        if(sel){
            [b setTitleColor:UIColor.whiteColor forState:0];
            b.titleLabel.font=[UIFont systemFontOfSize:12 weight:UIFontWeightBold];
        } else {
            [b setTitleColor:[UIColor colorWithWhite:0.45 alpha:1.0] forState:0];
            b.titleLabel.font=[UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
        }
    }
}
-(void)tabTap:(UIButton*)b{[self switchTab:b.tag];}
-(void)openTG{
    NSString*u = @"https://whatsapp.com/channel/0029Vb7UASL3bbV7CzGzUb04";
    [[UIApplication sharedApplication]openURL:[NSURL URLWithString:u] options:@{} completionHandler:nil];
}
-(void)showSettingsInfo{
    [self showGameModeSelectionWithInitialTab:1];
}
-(void)buildUI{
    // Brand header (Top-left: ZEX EXTERNAL)
    UILabel*brand=[UILabel new];brand.translatesAutoresizingMaskIntoConstraints=NO;
    NSMutableAttributedString*bAtt=[[NSMutableAttributedString alloc]initWithString:@"ZEX EXTERNAL"];
    [bAtt addAttribute:NSForegroundColorAttributeName value:ZXRed range:NSMakeRange(0,3)];
    [bAtt addAttribute:NSForegroundColorAttributeName value:UIColor.whiteColor range:NSMakeRange(3,9)];
    [bAtt addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:22 weight:UIFontWeightBlack] range:NSMakeRange(0,12)];
    [bAtt addAttribute:NSKernAttributeName value:@1.8 range:NSMakeRange(0,12)];
    brand.attributedText=bAtt;
    [self.view addSubview:brand];
    
    // Channel button (Top-right green pill button: 📢 CHANNEL)
    UIButton*channelBtn=[UIButton buttonWithType:UIButtonTypeSystem];channelBtn.translatesAutoresizingMaskIntoConstraints=NO;
    [channelBtn setTitle:@"CHANNEL" forState:0];
    [channelBtn setTitleColor:[UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:1.0] forState:0];
    channelBtn.titleLabel.font=[UIFont systemFontOfSize:11 weight:UIFontWeightBold];
    channelBtn.backgroundColor=[UIColor colorWithRed:0.04 green:0.22 blue:0.10 alpha:0.75];
    channelBtn.layer.borderWidth=1.0;
    channelBtn.layer.borderColor=[UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:0.65].CGColor;
    channelBtn.layer.cornerRadius=14;
    channelBtn.contentEdgeInsets=UIEdgeInsetsMake(4, 10, 4, 10);
    [channelBtn addTarget:self action:@selector(openTG) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:channelBtn];
    
    // Status Card (SYSTEM READY / All systems operational)
    UIView*sc=[UIView new];sc.translatesAutoresizingMaskIntoConstraints=NO;
    sc.backgroundColor=[UIColor colorWithRed:0.06 green:0.02 blue:0.035 alpha:0.88];
    sc.layer.cornerRadius=18;sc.layer.borderWidth=1.0;
    sc.layer.borderColor=[UIColor colorWithRed:0.95 green:0.12 blue:0.28 alpha:0.4].CGColor;
    [self.view addSubview:sc];
    
    UIImageView*shieldIcon=[UIImageView new];shieldIcon.translatesAutoresizingMaskIntoConstraints=NO;
    shieldIcon.tintColor=ZXRed;
    shieldIcon.contentMode=UIViewContentModeScaleAspectFit;
    shieldIcon.image=[UIImage systemImageNamed:@"shield.fill"];
    [sc addSubview:shieldIcon];
    
    UILabel*stHeader=[UILabel new];stHeader.translatesAutoresizingMaskIntoConstraints=NO;
    stHeader.text=@"SYSTEM READY";
    stHeader.font=[UIFont systemFontOfSize:14 weight:UIFontWeightBlack];
    stHeader.textColor=UIColor.whiteColor;
    [sc addSubview:stHeader];
    
    UILabel*stSub=[UILabel new];stSub.translatesAutoresizingMaskIntoConstraints=NO;
    stSub.text=@"All systems operational";
    stSub.font=[UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    stSub.textColor=[UIColor colorWithWhite:0.55 alpha:1.0];
    [sc addSubview:stSub];
    
    // Game Mode Switcher Button inside status card
    UIButton *modeBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    modeBtn.translatesAutoresizingMaskIntoConstraints = NO;
    modeBtn.backgroundColor = [UIColor colorWithRed:0.12 green:0.04 blue:0.06 alpha:0.85];
    modeBtn.layer.cornerRadius = 12;
    modeBtn.layer.borderWidth = 0.8;
    modeBtn.layer.borderColor = [UIColor colorWithRed:0.95 green:0.12 blue:0.28 alpha:0.45].CGColor;
    [modeBtn addTarget:self action:@selector(showGameModeSelection) forControlEvents:UIControlEventTouchUpInside];
    [sc addSubview:modeBtn];
    
    _modeBadgeLbl = [UILabel new];
    _modeBadgeLbl.translatesAutoresizingMaskIntoConstraints = NO;
    if ([self.selectedGameMode isEqualToString:@"FFMAX"]) {
        _modeBadgeLbl.text = @"FF MAX";
        _modeBadgeLbl.textColor = [UIColor colorWithRed:1.0 green:0.75 blue:0.2 alpha:1.0];
    } else {
        _modeBadgeLbl.text = @"FF NORMAL";
        _modeBadgeLbl.textColor = [UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:1.0];
    }
    _modeBadgeLbl.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightBlack];
    [modeBtn addSubview:_modeBadgeLbl];
    
    UILabel *modeEditIcon = [UILabel new];
    modeEditIcon.translatesAutoresizingMaskIntoConstraints = NO;
    modeEditIcon.text = @" ⚙️";
    modeEditIcon.font = [UIFont systemFontOfSize:10 weight:UIFontWeightBold];
    [modeBtn addSubview:modeEditIcon];
    
    [NSLayoutConstraint activateConstraints:@[
        [modeBtn.trailingAnchor constraintEqualToAnchor:sc.trailingAnchor constant:-12],
        [modeBtn.centerYAnchor constraintEqualToAnchor:sc.centerYAnchor],
        [modeBtn.heightAnchor constraintEqualToConstant:30],
        
        [_modeBadgeLbl.leadingAnchor constraintEqualToAnchor:modeBtn.leadingAnchor constant:10],
        [_modeBadgeLbl.centerYAnchor constraintEqualToAnchor:modeBtn.centerYAnchor],
        
        [modeEditIcon.leadingAnchor constraintEqualToAnchor:_modeBadgeLbl.trailingAnchor constant:2],
        [modeEditIcon.trailingAnchor constraintEqualToAnchor:modeBtn.trailingAnchor constant:-8],
        [modeEditIcon.centerYAnchor constraintEqualToAnchor:modeBtn.centerYAnchor],
    ]];
    
    // Section Header (| INJECTION SLOTS)
    UIView*accentBar=[UIView new];accentBar.translatesAutoresizingMaskIntoConstraints=NO;
    accentBar.backgroundColor=ZXRed;accentBar.layer.cornerRadius=1.5;
    [self.view addSubview:accentBar];
    
    UILabel*poLeft=[UILabel new];poLeft.translatesAutoresizingMaskIntoConstraints=NO;
    NSMutableAttributedString*pAtt=[[NSMutableAttributedString alloc]initWithString:@"INJECTION SLOTS"];
    [pAtt addAttribute:NSKernAttributeName value:@1.5 range:NSMakeRange(0, 15)];
    [pAtt addAttribute:NSForegroundColorAttributeName value:UIColor.whiteColor range:NSMakeRange(0, 15)];
    [pAtt addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:12 weight:UIFontWeightBlack] range:NSMakeRange(0, 15)];
    poLeft.attributedText=pAtt;
    [self.view addSubview:poLeft];
    
    // TableView / Slots Grid
    _tv=[[UITableView alloc]initWithFrame:CGRectZero style:UITableViewStylePlain];
    _tv.translatesAutoresizingMaskIntoConstraints=NO;_tv.backgroundColor=UIColor.clearColor;
    _tv.separatorStyle=0;_tv.dataSource=self;_tv.delegate=self;[self.view addSubview:_tv];
    
    // Bottom Tab Bar (4 option tabs)
    UIView*tabBar=[[UIView alloc]init];tabBar.translatesAutoresizingMaskIntoConstraints=NO;
    tabBar.backgroundColor=[UIColor colorWithRed:0.03 green:0.01 blue:0.02 alpha:0.95];
    tabBar.layer.borderWidth=0.8;tabBar.layer.borderColor=[UIColor colorWithWhite:1 alpha:.06].CGColor;
    [self.view addSubview:tabBar];
    
    UIView*tabIndicator=[UIView new];tabIndicator.translatesAutoresizingMaskIntoConstraints=NO;
    tabIndicator.backgroundColor=ZXRed;tabIndicator.tag=999;
    tabIndicator.layer.cornerRadius=1.0;
    [tabBar addSubview:tabIndicator];
    
    NSMutableArray<UIButton*>*btns=[NSMutableArray array];
    NSArray*tt=@[@"OPTION 1",@"LOCATION",@"OPTION 3",@"OPTION 4",@"EXTRA"];
    for(NSInteger i=0;i<5;i++){
        UIButton*tb=[UIButton buttonWithType:UIButtonTypeSystem];tb.translatesAutoresizingMaskIntoConstraints=NO;
        [tb setTitle:tt[i] forState:0];
        tb.titleLabel.font=[UIFont systemFontOfSize:9 weight:UIFontWeightBold];
        tb.tintColor=(i==0?UIColor.whiteColor:[UIColor colorWithWhite:0.45 alpha:1.0]);
        [tb setTitleColor:(i==0?UIColor.whiteColor:[UIColor colorWithWhite:0.45 alpha:1.0]) forState:0];
        tb.tag=i;[tb addTarget:self action:@selector(tabTap:) forControlEvents:UIControlEventTouchUpInside];
        [tabBar addSubview:tb];[btns addObject:tb];
        
        [NSLayoutConstraint activateConstraints:@[
            [tb.topAnchor constraintEqualToAnchor:tabBar.topAnchor constant:6],
            [tb.bottomAnchor constraintEqualToAnchor:tabBar.safeAreaLayoutGuide.bottomAnchor constant:-4],
            [tb.widthAnchor constraintEqualToAnchor:tabBar.widthAnchor multiplier:1.0/5],
        ]];
        if(i==0)[tb.leadingAnchor constraintEqualToAnchor:tabBar.leadingAnchor].active=YES;
        else [tb.leadingAnchor constraintEqualToAnchor:((UIButton*)btns[i-1]).trailingAnchor].active=YES;
    }
    _tabBtns=btns;
    
    // Constraints
    [NSLayoutConstraint activateConstraints:@[
        [brand.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:18],
        [brand.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:8],
        
        [channelBtn.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-18],
        [channelBtn.centerYAnchor constraintEqualToAnchor:brand.centerYAnchor],
        [channelBtn.heightAnchor constraintEqualToConstant:28],
        
        [sc.topAnchor constraintEqualToAnchor:brand.bottomAnchor constant:14],
        [sc.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [sc.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [sc.heightAnchor constraintEqualToConstant:62],
        
        [shieldIcon.leadingAnchor constraintEqualToAnchor:sc.leadingAnchor constant:14],
        [shieldIcon.centerYAnchor constraintEqualToAnchor:sc.centerYAnchor],
        [shieldIcon.widthAnchor constraintEqualToConstant:24],
        [shieldIcon.heightAnchor constraintEqualToConstant:24],
        
        [stHeader.leadingAnchor constraintEqualToAnchor:shieldIcon.trailingAnchor constant:12],
        [stHeader.topAnchor constraintEqualToAnchor:sc.topAnchor constant:12],
        
        [stSub.leadingAnchor constraintEqualToAnchor:stHeader.leadingAnchor],
        [stSub.topAnchor constraintEqualToAnchor:stHeader.bottomAnchor constant:3],
        
        [accentBar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:18],
        [accentBar.topAnchor constraintEqualToAnchor:sc.bottomAnchor constant:16],
        [accentBar.widthAnchor constraintEqualToConstant:3],
        [accentBar.heightAnchor constraintEqualToConstant:14],
        
        [poLeft.leadingAnchor constraintEqualToAnchor:accentBar.trailingAnchor constant:8],
        [poLeft.centerYAnchor constraintEqualToAnchor:accentBar.centerYAnchor],
        
        [_tv.topAnchor constraintEqualToAnchor:accentBar.bottomAnchor constant:10],
        [_tv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:14],
        [_tv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-14],
        [_tv.bottomAnchor constraintEqualToAnchor:tabBar.topAnchor constant:-4],
        
        [tabBar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [tabBar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [tabBar.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [tabBar.heightAnchor constraintEqualToConstant:75],
        
        [tabIndicator.topAnchor constraintEqualToAnchor:tabBar.topAnchor],
        [tabIndicator.heightAnchor constraintEqualToConstant:2.5],
        [tabIndicator.widthAnchor constraintEqualToAnchor:tabBar.widthAnchor multiplier:1.0/5],
        [tabIndicator.leadingAnchor constraintEqualToAnchor:tabBar.leadingAnchor],
    ]];
}
@end

// ── ZXMaintenanceVC ────────────────────────────────────────────────
@interface ZXMaintenanceVC : UIViewController
@property (nonatomic, copy) NSString *message;
@property (nonatomic, copy) NSString *channelUrl;
@property (nonatomic, copy) void(^onRetrySuccess)(void);
@end

@implementation ZXMaintenanceVC {
    UIActivityIndicatorView *_sp;
    UILabel *_statusMsg;
}
-(UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
-(void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    ZXAddModernBackground(self.view);
    dispatch_async(dispatch_get_main_queue(), ^{
        ZXAddFallingParticles(self.view);
    });
    
    // Top Wrench Emoji 🔧
    UILabel *iconLbl = [UILabel new];
    iconLbl.translatesAutoresizingMaskIntoConstraints = NO;
    iconLbl.text = @"🔧";
    iconLbl.font = [UIFont systemFontOfSize:46];
    iconLbl.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:iconLbl];
    
    // Title MAINTENANCE MODE
    UILabel *titleLbl = [UILabel new];
    titleLbl.translatesAutoresizingMaskIntoConstraints = NO;
    titleLbl.text = @"MAINTENANCE MODE";
    titleLbl.font = [UIFont systemFontOfSize:18 weight:UIFontWeightBlack];
    titleLbl.textColor = [UIColor colorWithRed:0.95 green:0.10 blue:0.25 alpha:1.0];
    titleLbl.textAlignment = NSTextAlignmentCenter;
    titleLbl.layer.shadowColor = ZXRed.CGColor;
    titleLbl.layer.shadowRadius = 8;
    titleLbl.layer.shadowOpacity = 0.8;
    titleLbl.layer.shadowOffset = CGSizeZero;
    [self.view addSubview:titleLbl];
    
    // Glass Card Message Box (Photo 2 design)
    UIView *card = ZXGlassView(16);
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor colorWithRed:0.08 green:0.02 blue:0.03 alpha:0.85];
    card.layer.borderColor = [UIColor colorWithRed:0.95 green:0.1 blue:0.25 alpha:0.45].CGColor;
    card.layer.borderWidth = 1.0;
    [self.view addSubview:card];
    
    _statusMsg = [UILabel new];
    _statusMsg.translatesAutoresizingMaskIntoConstraints = NO;
    _statusMsg.text = self.message.length ? self.message : @"ipa is on maintenance wait for fix";
    _statusMsg.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
    _statusMsg.textColor = [UIColor colorWithWhite:0.9 alpha:1.0];
    _statusMsg.textAlignment = NSTextAlignmentCenter;
    _statusMsg.numberOfLines = 4;
    [card addSubview:_statusMsg];
    
    // Button 1: 🔄 Retry (Red Glass Button)
    UIButton *retryBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    retryBtn.translatesAutoresizingMaskIntoConstraints = NO;
    retryBtn.backgroundColor = [UIColor colorWithRed:0.35 green:0.04 blue:0.1 alpha:0.85];
    retryBtn.layer.cornerRadius = 18;
    retryBtn.layer.borderColor = [UIColor colorWithRed:0.95 green:0.15 blue:0.3 alpha:0.7].CGColor;
    retryBtn.layer.borderWidth = 1.2;
    [retryBtn setTitle:@"Retry" forState:UIControlStateNormal];
    [retryBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.4 blue:0.55 alpha:1.0] forState:UIControlStateNormal];
    retryBtn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    [retryBtn addTarget:self action:@selector(retryTap) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:retryBtn];
    
    // Button 2: Official Channel (Green Glass Button)
    UIButton *chanBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    chanBtn.translatesAutoresizingMaskIntoConstraints = NO;
    chanBtn.backgroundColor = [UIColor colorWithRed:0.03 green:0.18 blue:0.06 alpha:0.85];
    chanBtn.layer.cornerRadius = 18;
    chanBtn.layer.borderColor = [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:0.7].CGColor;
    chanBtn.layer.borderWidth = 1.2;
    [chanBtn setTitle:@"Official Channel" forState:UIControlStateNormal];
    [chanBtn setTitleColor:[UIColor colorWithRed:0.3 green:0.95 blue:0.5 alpha:1.0] forState:UIControlStateNormal];
    chanBtn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    [chanBtn addTarget:self action:@selector(channelTap) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:chanBtn];
    
    _sp = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _sp.translatesAutoresizingMaskIntoConstraints = NO;
    _sp.color = ZXRed;
    _sp.hidesWhenStopped = YES;
    [self.view addSubview:_sp];
    
    // Footer label ZEX EXTERNAL
    UILabel *foot = [UILabel new];
    foot.translatesAutoresizingMaskIntoConstraints = NO;
    foot.text = @"ZEX EXTERNAL";
    foot.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    foot.textColor = [UIColor colorWithWhite:1.0 alpha:0.25];
    foot.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:foot];
    
    [NSLayoutConstraint activateConstraints:@[
        [iconLbl.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-140],
        [iconLbl.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        
        [titleLbl.topAnchor constraintEqualToAnchor:iconLbl.bottomAnchor constant:12],
        [titleLbl.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        
        [card.topAnchor constraintEqualToAnchor:titleLbl.bottomAnchor constant:22],
        [card.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [card.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        
        [_statusMsg.topAnchor constraintEqualToAnchor:card.topAnchor constant:18],
        [_statusMsg.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-18],
        [_statusMsg.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_statusMsg.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        
        [retryBtn.topAnchor constraintEqualToAnchor:card.bottomAnchor constant:24],
        [retryBtn.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [retryBtn.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        [retryBtn.heightAnchor constraintEqualToConstant:54],
        
        [chanBtn.topAnchor constraintEqualToAnchor:retryBtn.bottomAnchor constant:14],
        [chanBtn.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [chanBtn.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        [chanBtn.heightAnchor constraintEqualToConstant:54],
        
        [_sp.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_sp.topAnchor constraintEqualToAnchor:chanBtn.bottomAnchor constant:12],
        
        [foot.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-16],
        [foot.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
    ]];
}

-(void)retryTap {
    [_sp startAnimating];
    [ZXConfig fetch:^(ZXConfig *c, NSError *e) {
        [self->_sp stopAnimating];
        if (c && !c.maintenance) {
            if (self.onRetrySuccess) self.onRetrySuccess();
        } else {
            if (c.maintMsg.length) self->_statusMsg.text = c.maintMsg;
            CAKeyframeAnimation *shake = [CAKeyframeAnimation animationWithKeyPath:@"position.x"];
            shake.values = @[@(0), @(-10), @(10), @(-6), @(6), @(0)];
            shake.duration = 0.4;
            shake.additive = YES;
            [self.view.layer addAnimation:shake forKey:@"maint_shake"];
        }
    }];
}

-(void)channelTap {
    NSString *urlStr = self.channelUrl.length ? self.channelUrl : @"https://whatsapp.com/channel/0029Vb7UASL3bbV7CzGzUb04";
    NSURL *url = [NSURL URLWithString:urlStr];
    if (url) {
        [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
    }
}
@end

// ── ZEXInjectorVC ─────────────────────────────────────────────────
@implementation ZEXInjectorVC
-(UIStatusBarStyle)preferredStatusBarStyle{return UIStatusBarStyleLightContent;}
-(UIViewController*)childViewControllerForStatusBarStyle{return self.childViewControllers.lastObject;}
-(void)viewDidLoad{
    [super viewDidLoad];
    self.view.frame=UIScreen.mainScreen.bounds;
    self.view.backgroundColor=[UIColor colorWithRed:0.04 green:0.01 blue:0.02 alpha:1.0];
    [self showLoadingScreen];
}
-(void)showLoadingScreen{
    UIView*loader=[[UIView alloc]initWithFrame:self.view.bounds];
    loader.backgroundColor=[UIColor colorWithRed:0.04 green:0.01 blue:0.02 alpha:1.0];
    loader.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    ZXAddModernBackground(loader);
    
    // Pill Badge INITIALIZING RUNTIME (Photo 1 design at bottom)
    UIView*badge=ZXGlassView(12);badge.translatesAutoresizingMaskIntoConstraints=NO;
    badge.backgroundColor=[UIColor colorWithRed:0.18 green:0.02 blue:0.05 alpha:0.85];
    badge.layer.borderColor=[UIColor colorWithRed:1.0 green:0.25 blue:0.4 alpha:0.55].CGColor;
    badge.layer.borderWidth=0.8;badge.layer.cornerRadius=12;
    [loader addSubview:badge];
    
    UIView*dot=[UIView new];dot.translatesAutoresizingMaskIntoConstraints=NO;
    dot.backgroundColor=[UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1.0];
    dot.layer.cornerRadius=4.0;
    [badge addSubview:dot];
    
    UILabel*badgeLbl=[UILabel new];badgeLbl.translatesAutoresizingMaskIntoConstraints=NO;
    badgeLbl.text=@"INITIALIZING RUNTIME";
    badgeLbl.font=[UIFont monospacedSystemFontOfSize:9.5 weight:UIFontWeightBold];
    badgeLbl.textColor=[UIColor colorWithRed:1.0 green:0.4 blue:0.55 alpha:1.0];
    [badge addSubview:badgeLbl];
    
    // Subtitle Line 1: 📱 IPHONE • iOS X.X • ROOTLESS
    UILabel*devLoad=[UILabel new];devLoad.translatesAutoresizingMaskIntoConstraints=NO;
    NSString *model = [UIDevice currentDevice].model;
    NSString *osVer = [UIDevice currentDevice].systemVersion;
    devLoad.text=[NSString stringWithFormat:@"📱 %@ • iOS %@ • ROOTLESS", model.uppercaseString, osVer];
    devLoad.font=[UIFont monospacedSystemFontOfSize:9.5 weight:UIFontWeightBold];
    devLoad.textColor=[UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:0.95];
    devLoad.textAlignment=NSTextAlignmentCenter;
    [loader addSubview:devLoad];
    
    // Subtitle Line 2: > [04/04] ALL SYSTEMS ARMED & READY_
    UILabel*sub=[UILabel new];sub.translatesAutoresizingMaskIntoConstraints=NO;
    sub.text=@"> [01/04] INITIALIZING SYSTEM KERNEL...";
    sub.font=[UIFont monospacedSystemFontOfSize:10.5 weight:UIFontWeightBold];
    sub.textColor=[UIColor colorWithRed:0.25 green:0.88 blue:0.45 alpha:0.95];
    sub.textAlignment=NSTextAlignmentCenter;
    [loader addSubview:sub];
    
    // Progress Bar Track at bottom
    UIView*pTrack=[UIView new];pTrack.translatesAutoresizingMaskIntoConstraints=NO;
    pTrack.backgroundColor=[UIColor colorWithWhite:0 alpha:0.6];
    pTrack.layer.cornerRadius=3.5;pTrack.clipsToBounds=YES;
    pTrack.layer.borderWidth=0.6;pTrack.layer.borderColor=[UIColor colorWithWhite:1 alpha:0.12].CGColor;
    [loader addSubview:pTrack];
    
    UIView*pBar=[UIView new];pBar.translatesAutoresizingMaskIntoConstraints=NO;
    pBar.backgroundColor=ZXRed;pBar.layer.cornerRadius=3.5;
    pBar.layer.shadowColor=ZXRed.CGColor;pBar.layer.shadowOffset=CGSizeZero;pBar.layer.shadowRadius=8;pBar.layer.shadowOpacity=0.9;
    [pTrack addSubview:pBar];
    
    CAGradientLayer*barGrad=[CAGradientLayer layer];
    barGrad.frame=CGRectMake(0,0,260,7);
    barGrad.colors=@[(id)[UIColor colorWithRed:1.0 green:0.25 blue:0.4 alpha:1].CGColor, (id)ZXRed.CGColor];
    barGrad.startPoint=CGPointMake(0,0.5);barGrad.endPoint=CGPointMake(1,0.5);
    [pBar.layer insertSublayer:barGrad atIndex:0];
    
    NSLayoutConstraint*pWidth=[pBar.widthAnchor constraintEqualToConstant:20];
    
    [NSLayoutConstraint activateConstraints:@[
        [badge.bottomAnchor constraintEqualToAnchor:devLoad.topAnchor constant:-8],
        [badge.centerXAnchor constraintEqualToAnchor:loader.centerXAnchor],
        [dot.leadingAnchor constraintEqualToAnchor:badge.leadingAnchor constant:12],
        [dot.centerYAnchor constraintEqualToAnchor:badge.centerYAnchor],
        [dot.widthAnchor constraintEqualToConstant:8],
        [dot.heightAnchor constraintEqualToConstant:8],
        [badgeLbl.leadingAnchor constraintEqualToAnchor:dot.trailingAnchor constant:6],
        [badgeLbl.trailingAnchor constraintEqualToAnchor:badge.trailingAnchor constant:-12],
        [badgeLbl.topAnchor constraintEqualToAnchor:badge.topAnchor constant:5],
        [badgeLbl.bottomAnchor constraintEqualToAnchor:badge.bottomAnchor constant:-5],
        
        [devLoad.bottomAnchor constraintEqualToAnchor:sub.topAnchor constant:-8],
        [devLoad.centerXAnchor constraintEqualToAnchor:loader.centerXAnchor],
        
        [sub.centerXAnchor constraintEqualToAnchor:loader.centerXAnchor],
        [sub.bottomAnchor constraintEqualToAnchor:pTrack.topAnchor constant:-12],
        
        [pTrack.centerXAnchor constraintEqualToAnchor:loader.centerXAnchor],
        [pTrack.bottomAnchor constraintEqualToAnchor:loader.safeAreaLayoutGuide.bottomAnchor constant:-16],
        [pTrack.widthAnchor constraintEqualToConstant:240],
        [pTrack.heightAnchor constraintEqualToConstant:7],
        
        [pBar.leadingAnchor constraintEqualToAnchor:pTrack.leadingAnchor],
        [pBar.topAnchor constraintEqualToAnchor:pTrack.topAnchor],
        [pBar.bottomAnchor constraintEqualToAnchor:pTrack.bottomAnchor],
        pWidth
    ]];
    
    [self.view addSubview:loader];
    ZXAddFallingParticles(loader);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        pWidth.constant = 110;
        [UIView animateWithDuration:0.4 animations:^{ [loader layoutIfNeeded]; }];
        sub.text = @"> [02/04] ESCAPING SANDBOX CONTAINERS...";
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        pWidth.constant = 180;
        [UIView animateWithDuration:0.35 animations:^{ [loader layoutIfNeeded]; }];
        sub.text = @"> [03/04] CONNECTING TO SECURE AUTH NODE...";
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 950 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        pWidth.constant = 240;
        [UIView animateWithDuration:0.25 animations:^{ [loader layoutIfNeeded]; }];
        sub.text = @"> [04/04] ALL SYSTEMS ARMED & READY_";
        sub.textColor = ZXGreen;
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1250 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        [ZXConfig fetch:^(ZXConfig *c, NSError *e) {
            if (c && c.maintenance) {
                [self showMaintenanceWithMessage:c.maintMsg channel:c.officialChannel];
                [loader removeFromSuperview];
            } else {
                [self showAuth];
                [UIView animateWithDuration:0.3 animations:^{
                    loader.alpha = 0;
                } completion:^(BOOL f){
                    [loader removeFromSuperview];
                }];
            }
        }];
    });
}

-(void)showMaintenanceWithMessage:(NSString*)msg channel:(NSString*)chan {
    for(UIViewController*c in self.childViewControllers){[c willMoveToParentViewController:nil];[c.view removeFromSuperview];[c removeFromParentViewController];}
    ZXMaintenanceVC *m = [ZXMaintenanceVC new];
    m.message = msg;
    m.channelUrl = chan;
    __weak typeof(self) ws = self;
    m.onRetrySuccess = ^{
        [ws showLoadingScreen];
    };
    [self addChildViewController:m];
    m.view.frame = self.view.bounds;
    m.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view insertSubview:m.view atIndex:0];
    [m didMoveToParentViewController:self];
    [self setNeedsStatusBarAppearanceUpdate];
}
-(void)showAuth{
    for(UIViewController*c in self.childViewControllers){[c willMoveToParentViewController:nil];[c.view removeFromSuperview];[c removeFromParentViewController];}
    ZXAuthVC*a=[ZXAuthVC new];
    __weak typeof(self) ws=self;
    a.onAuth=^{[ws showMain];};
    [self addChildViewController:a];a.view.frame=self.view.bounds;
    a.view.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    [self.view insertSubview:a.view atIndex:0];[a didMoveToParentViewController:self];
    [self setNeedsStatusBarAppearanceUpdate];
}
-(void)showMain{
    for(UIViewController*c in self.childViewControllers){[c willMoveToParentViewController:nil];[c.view removeFromSuperview];[c removeFromParentViewController];}
    ZXMainVC*m=[ZXMainVC new];
    [self addChildViewController:m];m.view.frame=self.view.bounds;
    m.view.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    [self.view insertSubview:m.view atIndex:0];[m didMoveToParentViewController:self];
    [self setNeedsStatusBarAppearanceUpdate];
}
@end
