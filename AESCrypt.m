//
//  AESCrypt.m
//  Gurpartap Singh
//
//  Created by Gurpartap Singh on 06/05/12.
//  Copyright (c) 2012 Gurpartap Singh
// 
// 	MIT License
// 
// 	Permission is hereby granted, free of charge, to any person obtaining
// 	a copy of this software and associated documentation files (the
// 	"Software"), to deal in the Software without restriction, including
// 	without limitation the rights to use, copy, modify, merge, publish,
// 	distribute, sublicense, and/or sell copies of the Software, and to
// 	permit persons to whom the Software is furnished to do so, subject to
// 	the following conditions:
// 
// 	The above copyright notice and this permission notice shall be
// 	included in all copies or substantial portions of the Software.
// 
// 	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// 	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// 	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// 	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// 	LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// 	OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// 	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import "AESCrypt.h"

#import "NSData+Base64.h"
#import "NSString+Base64.h"
#import "NSData+CommonCrypto.h"

@implementation AESCrypt

+ (NSString *)encrypt:(NSString *)message password:(NSString *)password {
  NSData *encryptedData = [[message dataUsingEncoding:NSUTF8StringEncoding] AES256EncryptedDataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
  NSString *base64EncodedString = [NSString base64StringFromData:encryptedData length:[encryptedData length]];
  return base64EncodedString;
}

+ (NSString *)decrypt:(NSString *)base64EncodedString password:(NSString *)password {
  NSData *encryptedData = [NSData base64DataFromString:base64EncodedString];
  NSData *decryptedData = [encryptedData decryptedAES256DataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
  return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

+ (NSString *)encrypt:(NSString *)message password:(NSString *)password iv:(id)iv
{
    NSParameterAssert([iv isKindOfClass: [NSData class]] || [iv isKindOfClass: [NSString class]]);
    
    NSMutableData *ivData;
    
	if ( [iv isKindOfClass: [NSString class]] )
		ivData = [[iv dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
	else
		ivData = (NSMutableData *)[iv mutableCopy];
    
    [ivData setLength:16]; // I think it should be 16 bytes, but I'm not 100 percent sure
    
    NSData *encryptedData = [[message dataUsingEncoding:NSUTF8StringEncoding] dataEncryptedUsingAlgorithm:kCCAlgorithmAES128 key:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] initializationVector:iv  options:kCCOptionPKCS7Padding error:nil]; // todo: error checking
    
    NSString *base64EncodedString = [NSString base64StringFromData:encryptedData length:[encryptedData length]];
    NSString *base64EncodedIV = [NSString base64StringFromData:ivData length:[ivData length]];
    
    NSString *concatenatedString = [NSString stringWithFormat:@"%@%@", base64EncodedIV, base64EncodedString]; // is this the best way to concatenate two strings?
    
    return concatenatedString;
    
}
+ (NSString *)decryptWithIV:(NSString *)base64EncodedString password:(NSString *)password
{
    if([base64EncodedString length] < 25)
        return nil;
    
    NSString *iv = [base64EncodedString substringToIndex:24];
    NSData *dataIV = [NSData base64DataFromString:iv];
    
    NSString *message = [base64EncodedString substringFromIndex:24];
    NSData *encryptedData = [NSData base64DataFromString:message];
    
    NSData *decryptedData = [encryptedData decryptedDataUsingAlgorithm:kCCAlgorithmAES128 key:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] initializationVector:dataIV options:kCCOptionPKCS7Padding error:nil]; // todo: error checking  
    
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding]; // autorelease?
}

@end
