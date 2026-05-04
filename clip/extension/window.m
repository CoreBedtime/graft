#import "window.h"
#include <AppKit/AppKit.h>
#include <Foundation/Foundation.h>
#include <objc/runtime.h>

static CFMutableArrayRef gFrameRegistry = NULL;

static void EnsureRegistry(void) {
    if (!gFrameRegistry)
        gFrameRegistry = CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
}

void SyncFrameToWindow(EXWindowFrame *frame) {
    if (!frame || !frame->handle || !frame->actualWindow) return;
    NSWindow *actual = (__bridge NSWindow *)frame->actualWindow;
    NSRect actualFrame = [actual frame];
    NSRect syncedFrame =NSInsetRect(actualFrame, -16, -16);
    gtk_window_set_default_size(
        GTK_WINDOW(frame->window),
        (int)syncedFrame.size.width,
        (int)syncedFrame.size.height
    );

    [frame->handle addChildWindow:actual ordered:NSWindowAbove];

    NSWindowStyleMask style = actual.styleMask;
    style &= ~NSWindowStyleMaskResizable;
    if (!actual.toolbar) {
        style &= NSWindowStyleMaskFullSizeContentView;
        [actual setTitleVisibility:NSWindowTitleHidden];
        [actual setTitlebarSeparatorStyle:NSTitlebarSeparatorStyleNone];
        [actual setTitlebarAppearsTransparent:YES];

        if ([actual respondsToSelector:NSSelectorFromString(@"setTitlebarHeight:")]) {
            [actual performSelector:NSSelectorFromString(@"setTitlebarHeight:") withObject:@1];
        }
    }
    [actual setStyleMask:style];

    [[actual standardWindowButton:NSWindowCloseButton] setHidden:YES];
    [[actual standardWindowButton:NSWindowMiniaturizeButton] setHidden:YES];
    [[actual standardWindowButton:NSWindowZoomButton] setHidden:YES];
}

static void OnDrag(GtkGestureDrag *gesture, double x, double y, gpointer user_data) {
    EXWindowFrame *frame = (EXWindowFrame *)user_data;
    GdkSurface *surface = frame->surface;
    if (GDK_IS_TOPLEVEL(surface)) {
        GdkEvent *event = gtk_event_controller_get_current_event(GTK_EVENT_CONTROLLER(gesture));
        GdkDevice *device = gdk_event_get_device(event);
        int button = (int)gtk_gesture_single_get_current_button(GTK_GESTURE_SINGLE(gesture));
        guint32 timestamp = gtk_event_controller_get_current_event_time(GTK_EVENT_CONTROLLER(gesture));
        if (device) {
            gdk_toplevel_begin_move(GDK_TOPLEVEL(surface), device, button, x, y, timestamp);
        }
    }
}

EXWindowFrame *MakeFrameFor(NSWindow *actualWindow) {
    EnsureRegistry();
    EXWindowFrame *frame = g_new0(EXWindowFrame, 1);
    frame->actualWindow = (__bridge_retained void *)actualWindow;
    frame->window = gtk_window_new();

    gtk_window_set_decorated(GTK_WINDOW(frame->window), false);

    gtk_widget_set_visible(frame->window, TRUE);
    frame->surface = gtk_native_get_surface(GTK_NATIVE(frame->window));
    frame->handle = gdk_macos_surface_get_native_window(frame->surface);

    // Initial sync
    SyncFrameToWindow(frame);

    // Enable dragging anywhere on the surface
    GtkGesture *drag = gtk_gesture_drag_new();
    gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(drag), 0); // all buttons
    g_signal_connect(drag, "drag-begin", G_CALLBACK(OnDrag), frame);
    gtk_widget_add_controller(frame->window, GTK_EVENT_CONTROLLER(drag));

    CFArrayAppendValue(gFrameRegistry, frame);
    return frame;
}

bool IsFrameHandle(NSWindow *window) {
    if (!gFrameRegistry) return false;
    CFIndex count = CFArrayGetCount(gFrameRegistry);
    for (CFIndex i = 0; i < count; i++) {
        EXWindowFrame *frame = (EXWindowFrame *)CFArrayGetValueAtIndex(gFrameRegistry, i);
        if (frame->handle == window) return true;
    }
    return false;
}

EXWindowFrame *FindFrameForWindow(NSWindow *actualWindow) {
    if (!gFrameRegistry) return NULL;
    CFIndex count = CFArrayGetCount(gFrameRegistry);
    for (CFIndex i = 0; i < count; i++) {
        EXWindowFrame *frame = (EXWindowFrame *)CFArrayGetValueAtIndex(gFrameRegistry, i);
        NSWindow *win = (__bridge NSWindow *)frame->actualWindow;
        if (win == actualWindow) return frame;
    }
    return NULL;
}

NSWindow *FindActualWindowForFrame(NSWindow *frameHandle, EXWindowFrame **frame_out) {
    if (frame_out) *frame_out = NULL;
    if (!gFrameRegistry) return NULL;
    CFIndex count = CFArrayGetCount(gFrameRegistry);
    for (CFIndex i = 0; i < count; i++) {
        EXWindowFrame *frame = (EXWindowFrame *)CFArrayGetValueAtIndex(gFrameRegistry, i);
        if (frame->handle == frameHandle) {
            if (frame_out) *frame_out = frame;
            return (__bridge NSWindow *)frame->actualWindow;
        }
    }
    return NULL;
}

void RemoveFrameFor(EXWindowFrame *frame) {
    if (!frame) return;

    if (gFrameRegistry) {
        CFIndex idx = CFArrayGetFirstIndexOfValue(
            gFrameRegistry,
            CFRangeMake(0, CFArrayGetCount(gFrameRegistry)),
            frame
        );
        if (idx != kCFNotFound)
            CFArrayRemoveValueAtIndex(gFrameRegistry, idx);
    }

    if (frame->actualWindow) {
        (void)(__bridge_transfer NSWindow *)frame->actualWindow;
        frame->actualWindow = NULL;
    }

    if (frame->window) {
        gtk_window_destroy(GTK_WINDOW(frame->window));
        frame->window = NULL;
        frame->surface = NULL;
        frame->handle = NULL;
    }

    g_free(frame);
}
