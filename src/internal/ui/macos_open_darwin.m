// macos_open_darwin.m — Objective-C side of the AppleEvents bridge.
//
// Why a separate .m file (not the cgo preamble in macos_open_darwin.go):
// cgo's documentation forbids *definitions* in the preamble of any file that
// uses //export, because the preamble is copied into multiple C compilation
// units and the @implementation block would generate duplicate ObjC symbols
// (_OBJC_CLASS_$_PCNGOpenDocsInjector, _OBJC_METACLASS_$_…) at link time.
// Splitting the @implementation out lets cgo compile this unit exactly once.
//
// The _darwin suffix gives this file an automatic GOOS=darwin build constraint
// (Go file naming convention applies to .m, .c, .s, etc.).
//
// We #include the cgo-generated _cgo_export.h to pick up the auto-declared
// signatures `void goAppendOpenedPath(char *cpath)` and `void
// goFlushOpenedPaths(void)` — no manual extern needed.

#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#include "_cgo_export.h"

// PCNGOpenDocsInjector — helper class. Its +(void)load runs at dyld image-load
// time (before Go runtime init, before main(), before GLFW's _glfwPlatformInit).
// We inject application:openURLs: into GLFWApplicationDelegate via class_addMethod
// because GLFW does not implement that selector (verified cocoa_init.m:399-465);
// AppKit dispatches kAEOpenDocuments through the delegate first and silently
// drops the event if the delegate does not respond — so direct AppleEvent-manager
// registration would never fire (Pitfall #1).
@interface PCNGOpenDocsInjector : NSObject
+ (void)load;
- (void)pcngApplication:(NSApplication *)sender openURLs:(NSArray<NSURL *> *)urls;
@end

@implementation PCNGOpenDocsInjector

+ (void)load {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class glfwDelegate = objc_getClass("GLFWApplicationDelegate");
        if (!glfwDelegate) {
            // Defensive: GLFW class name may shift between versions. Log + noop.
            // Do NOT call into Go from here — Go runtime is not yet alive (Pitfall #9).
            NSLog(@"[picocrypt-ng] GLFWApplicationDelegate not found; "
                  @"AppleEvents handler not injected. .pcv double-click will not work.");
            return;
        }
        Method m = class_getInstanceMethod([PCNGOpenDocsInjector class],
                                           @selector(pcngApplication:openURLs:));
        IMP impl = method_getImplementation(m);
        const char *types = method_getTypeEncoding(m);
        SEL sel = @selector(application:openURLs:);
        // class_addMethod returns NO if the class already responds — in that case
        // someone else patched first (or future GLFW added the method); skip.
        if (!class_addMethod(glfwDelegate, sel, impl, types)) {
            NSLog(@"[picocrypt-ng] application:openURLs: already present on GLFW delegate; "
                  @"skipping injection.");
        }
    });
}

- (void)pcngApplication:(NSApplication *)sender openURLs:(NSArray<NSURL *> *)urls {
    // AppKit delivers an entire multi-file open gesture (e.g. several files
    // dragged onto the app/dock icon) as one openURLs: call. Buffer every file
    // URL, then flush once, so the whole selection reaches the UI as a single
    // drop. Flushing per URL instead lost files (issue #127): each single-path
    // drop replaced the previous one or was dropped by onDrop's scanning guard.
    for (NSURL *url in urls) {
        if (![url isFileURL]) continue;
        const char *path = [[url path] UTF8String];
        if (path != NULL) {
            // Cast away const: cgo's auto-generated signature is
            // `void goAppendOpenedPath(char *cpath)`. Go does not modify the
            // string — it copies it via C.GoString — so the cast is safe.
            goAppendOpenedPath((char *)path);
        }
    }
    goFlushOpenedPaths();
}

@end
