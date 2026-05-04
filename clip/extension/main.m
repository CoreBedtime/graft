#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <glib.h>
#include <AppKit/AppKit.h>
#include <CoreFoundation/CoreFoundation.h>
#import "window.h"

static void ShellPump(CFRunLoopTimerRef timer, void *info) {
    GMainContext *ctx = g_main_context_default();

    if (!g_main_context_acquire(ctx)) return;

    while (g_main_context_pending(ctx)) {
        g_main_context_iteration(ctx, FALSE);
    }

    g_main_context_release(ctx);
}

static bool gtkInitialized = false;

static void InitGTK(void) {
    if (gtkInitialized) return;
    gtkInitialized = true;

    NSLog(@"NSApp created → init GTK");

    setenv("GDK_BACKEND", "macos", 1);
    gtk_init();

    dispatch_async(dispatch_get_main_queue(), ^{
        CFRunLoopTimerContext ctx_timer = {0, NULL, NULL, NULL, NULL};
        CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
            kCFAllocatorDefault,
            CFAbsoluteTimeGetCurrent(),
            0.01,
            0,
            0,
            ShellPump,
            &ctx_timer
        );
        CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopCommonModes);
        CFRelease(timer);
    });
}

static id (*orig_sharedApplication)(id, SEL);
static void (*orig_makeKeyAndOrderFront)(id, SEL, id);
static void (*orig_orderFront)(id, SEL, id);
static void (*orig_orderFrontRegardless)(id, SEL);
static void (*orig_setFrameDisplay)(id, SEL, NSRect, BOOL);
static void (*orig_performWindowDragWithEvent)(id, SEL, id);

static void EnsureFrameForWindow(NSWindow *win) {
    if (!win) return;
    if (IsFrameHandle(win)) return;          // it's a frame's own NSWindow handle
    if (FindFrameForWindow(win)) return;     // already has a frame
    MakeFrameFor(win);
}

static id hooked_sharedApplication(id self, SEL _cmd) {
    id app = orig_sharedApplication(self, _cmd);
    InitGTK();
    return app;
}

static void hooked_makeKeyAndOrderFront(id self, SEL _cmd, id sender) {
    orig_makeKeyAndOrderFront(self, _cmd, sender);
    EnsureFrameForWindow((NSWindow *)self);
}

static void hooked_orderFront(id self, SEL _cmd, id sender) {
    orig_orderFront(self, _cmd, sender);
    EnsureFrameForWindow((NSWindow *)self);
}

static void hooked_orderFrontRegardless(id self, SEL _cmd) {
    orig_orderFrontRegardless(self, _cmd);
    EnsureFrameForWindow((NSWindow *)self);
}

static void hooked_setFrameDisplay(id self, SEL _cmd, NSRect frameRect, BOOL flag) {
    orig_setFrameDisplay(self, _cmd, frameRect, flag);
    NSWindow * child = FindActualWindowForFrame((NSWindow *)self, NULL);

    if (!child) return;

    NSRect frame_frame = NSInsetRect(frameRect, 32, 32);
    [child setFrame:frame_frame display:YES];
}

static void hooked_performWindowDragWithEvent(id self, SEL _cmd, NSEvent *event) {
    orig_performWindowDragWithEvent(self, _cmd, event);
    NSWindow * child = FindActualWindowForFrame((NSWindow *)self, NULL);
    if (!child) return;
    orig_performWindowDragWithEvent(child, _cmd, event);
}

extern
void ModCornerMaskPatchInit(void);

__attribute__((constructor))
static void extension_init(void) {

    Class cls = objc_getClass("NSApplication");
    if (!cls) {
        return;
    }

    SEL sel = @selector(sharedApplication);
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        return;
    }

    orig_sharedApplication = (id (*)(id, SEL))method_getImplementation(m);
    method_setImplementation(m, (IMP)hooked_sharedApplication);

    Class winCls = objc_getClass("NSWindow");
    if (winCls) {
        Method mKeyFront = class_getInstanceMethod(winCls, @selector(makeKeyAndOrderFront:));
        Method mOrderFront = class_getInstanceMethod(winCls, @selector(orderFront:));
        Method mOrderFrontRegardless = class_getInstanceMethod(winCls, @selector(orderFrontRegardless));
        Method mSetFrame = class_getInstanceMethod(winCls, @selector(setFrame:display:));

        if (mKeyFront) {
            orig_makeKeyAndOrderFront = (void (*)(id, SEL, id))method_getImplementation(mKeyFront);
            method_setImplementation(mKeyFront, (IMP)hooked_makeKeyAndOrderFront);
        }
        if (mOrderFront) {
            orig_orderFront = (void (*)(id, SEL, id))method_getImplementation(mOrderFront);
            method_setImplementation(mOrderFront, (IMP)hooked_orderFront);
        }
        if (mOrderFrontRegardless) {
            orig_orderFrontRegardless = (void (*)(id, SEL))method_getImplementation(mOrderFrontRegardless);
            method_setImplementation(mOrderFrontRegardless, (IMP)hooked_orderFrontRegardless);
        }

        if (mSetFrame) {
            orig_setFrameDisplay = (void (*)(id, SEL, NSRect, BOOL))method_getImplementation(mSetFrame);
            method_setImplementation(mSetFrame, (IMP)hooked_setFrameDisplay);
        }
    }

    ModCornerMaskPatchInit();
}
