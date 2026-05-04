#include <CoreFoundation/CFCGTypes.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#define NSLog(...)

@interface NSCGSWindowCornerRadiusMask : NSObject
- (double)cornerRadius;
@end

static double hook_cornerRadius(id self, SEL _cmd) {
    return CGFLOAT_EPSILON;
}

static void hook_updateLayer(id self, SEL _cmd) {
    // Force the layer to be empty and transparent
    id layer = [(id)self layer];
    [layer setContents:nil];
    [layer setBackgroundColor:nil];
    [layer setOpacity:0.0];
}


void ModCornerMaskPatchInit(void) {
    Class maskClass = NSClassFromString(@"NSCGSWindowCornerRadiusMask");
    if (!maskClass) {
        NSLog(@"[ModCornerMaskPatch] ERROR: NSCGSWindowCornerRadiusMask not found");
        return;
    }

    SEL cornerRadiusSel = @selector(cornerRadius);
    Method cornerRadiusMethod = class_getInstanceMethod(maskClass, cornerRadiusSel);

    if (cornerRadiusMethod) {
        method_setImplementation(cornerRadiusMethod, (IMP)hook_cornerRadius);
        NSLog(@"[ModCornerMaskPatch] Successfully hooked NSCGSWindowCornerRadiusMask cornerRadius to return 0");
    } else {
        NSLog(@"[ModCornerMaskPatch] ERROR: cornerRadius method not found on NSCGSWindowCornerRadiusMask");
    }


    Class decorClass = NSClassFromString(@"_NSTitlebarDecorationView");
    if (!decorClass) return;

    SEL updateLayerSel = @selector(updateLayer);
    Method updateLayerMethod = class_getInstanceMethod(decorClass, updateLayerSel);

    if (updateLayerMethod) {
        method_setImplementation(updateLayerMethod, (IMP)hook_updateLayer);
    }
}
