// open_readiness_darwin.m - iCloud readiness checks for macOS-opened paths.

#import <Foundation/Foundation.h>
#include <stdlib.h>
#include <string.h>

enum {
    PCNGOpenedPathReady = 0,
    PCNGOpenedPathDownloading = 1,
    PCNGOpenedPathNotDownloaded = 2,
    PCNGOpenedPathStale = 3,
    PCNGOpenedPathMissing = 4,
    PCNGOpenedPathError = 5,
};

static void pcngSetError(char **errorOut, NSError *error) {
    if (errorOut == NULL || error == nil) return;
    const char *msg = [[error localizedDescription] UTF8String];
    if (msg == NULL) return;
    *errorOut = strdup(msg);
}

void pcngFreeCString(char *s) {
    if (s != NULL) free(s);
}

int pcngCheckOpenedPathReadiness(char *path, char **errorOut) {
    @autoreleasepool {
        if (errorOut != NULL) *errorOut = NULL;
        if (path == NULL || strlen(path) == 0) return PCNGOpenedPathMissing;

        NSString *nsPath = [NSString stringWithUTF8String:path];
        if (nsPath == nil) return PCNGOpenedPathError;

        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:nsPath]) {
            return PCNGOpenedPathMissing;
        }

        NSURL *url = [NSURL fileURLWithPath:nsPath];
        NSError *error = nil;
        NSNumber *isUbiquitous = nil;
        if (![url getResourceValue:&isUbiquitous forKey:NSURLIsUbiquitousItemKey error:&error]) {
            pcngSetError(errorOut, error);
            return PCNGOpenedPathError;
        }

        if (![isUbiquitous boolValue]) {
            return [fm isReadableFileAtPath:nsPath] ? PCNGOpenedPathReady : PCNGOpenedPathError;
        }

        NSString *status = nil;
        error = nil;
        if (![url getResourceValue:&status forKey:NSURLUbiquitousItemDownloadingStatusKey error:&error]) {
            pcngSetError(errorOut, error);
            return PCNGOpenedPathError;
        }

        if ([status isEqualToString:NSURLUbiquitousItemDownloadingStatusCurrent]) {
            return PCNGOpenedPathReady;
        }

        error = nil;
        if (![fm startDownloadingUbiquitousItemAtURL:url error:&error]) {
            pcngSetError(errorOut, error);
            return PCNGOpenedPathError;
        }

        if ([status isEqualToString:NSURLUbiquitousItemDownloadingStatusDownloaded]) {
            return PCNGOpenedPathStale;
        }
        if ([status isEqualToString:NSURLUbiquitousItemDownloadingStatusNotDownloaded]) {
            return PCNGOpenedPathNotDownloaded;
        }
        return PCNGOpenedPathDownloading;
    }
}
