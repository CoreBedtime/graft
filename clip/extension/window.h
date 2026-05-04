#ifndef window_h
#define window_h

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <CoreFoundation/CoreFoundation.h>

extern NSWindow *gdk_macos_surface_get_native_window(GdkSurface *surface);

typedef struct EXWindowFrame EXWindowFrame;

struct EXWindowFrame {
    GtkWidget *window;
    GdkSurface *surface;
    NSWindow *handle;
    void *actualWindow;     // __bridge_retained NSWindow*
};

void SyncFrameToWindow(EXWindowFrame *frame);
EXWindowFrame *MakeFrameFor(NSWindow *actualWindow);
EXWindowFrame *FindFrameForWindow(NSWindow *actualWindow);
void RemoveFrameFor(EXWindowFrame *frame);
bool IsFrameHandle(NSWindow *window);
NSWindow *FindActualWindowForFrame(NSWindow *frameHandle, EXWindowFrame **frame_out);
#endif
