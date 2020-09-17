#ifndef NSError_BbsSignatureError_h
#define NSError_BbsSignatureError_h

#import <Foundation/Foundation.h>
#include "bbs.h"

@interface BbsSignatureError: NSObject

//TODO review ideally this would be an extension of NSError but there were issues with this approach
+ (NSError*) errorFromBbsSignatureError:(bbs_signature_error_t *) error;

@end

#endif /* NSError_BbsSignatureError_h */
