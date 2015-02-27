//
//  Client.m
//  GamePark
//
//  Created by Alex Studnicka on 12/08/14.
//  Copyright (c) 2014 gamepark. All rights reserved.
//

#import "Client.h"
#import "GCDAsyncSocket.h"

#define CLIENT_VERSION				@"2.09"
#define RESPONSE_TAG				1001
#define PROCESS_TERMINATED			2001
#define TIMEOUT						-1

@implementation Client {
	
	dispatch_queue_t socketQueue;
	GCDAsyncSocket *listenSocket;
	GCDAsyncSocket *_receivingSocket;
	
	NSMutableDictionary *_runningProcesses;
	
}

- (instancetype)init {
	self = [super init];
	if (self) {
		
//		NSLog(@"Starting server");
		
		_runningProcesses = [NSMutableDictionary dictionary];
		
		socketQueue = dispatch_queue_create("socketQueue", NULL);
		
		listenSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:socketQueue];
		
		NSError *error = nil;
		if (![listenSocket acceptOnPort:8091 error:&error]) {
			NSLog(@"Error starting server: %@", error);
			return nil;
		}
		
//		NSLog(@"Server started on port %hu", listenSocket.localPort);

	}
	return self;
}

#pragma mark - Socket

- (void)socket:(GCDAsyncSocket *)sock didAcceptNewSocket:(GCDAsyncSocket *)newSocket {
	_receivingSocket = newSocket;
	
//	NSString *host = [newSocket connectedHost];
//	UInt16 port = [newSocket connectedPort];
//	NSLog(@"Accepted client %@:%hu", host, port);

	[newSocket readDataWithTimeout:TIMEOUT tag:0];
}

- (void)socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
	if (tag == RESPONSE_TAG) {
		[sock readDataWithTimeout:TIMEOUT tag:0];
		return;
	} else if (tag == PROCESS_TERMINATED) {
		return;
	}
}

- (NSMutableData *)dataFromHexString:(NSString *)command {
	command = [command stringByReplacingOccurrencesOfString:@" " withString:@""];
	NSMutableData *commandToSend= [[NSMutableData alloc] init];
	unsigned char whole_byte;
	char byte_chars[3] = {'\0','\0','\0'};
	for (int i = 0; i < ([command length] / 2); i++) {
		byte_chars[0] = [command characterAtIndex:i*2];
		byte_chars[1] = [command characterAtIndex:i*2+1];
		whole_byte = strtol(byte_chars, NULL, 16);
		[commandToSend appendBytes:&whole_byte length:1];
	}
	return commandToSend;
}

- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
	
//	dispatch_async(dispatch_get_main_queue(), ^{
//		@autoreleasepool {
//			...
//		}
//	}

	NSData *strData = [data subdataWithRange:NSMakeRange(0, data.length - 1)];
	NSString *msg = [[NSString alloc] initWithData:strData encoding:NSASCIIStringEncoding];
	if ([msg isEqualToString:@"<policy-file-request/>"]) {
		NSString *responseStr = @"<?xml version=\"1.0\"?><cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\"/></cross-domain-policy>";
		NSMutableData *responseData = [[responseStr dataUsingEncoding:NSASCIIStringEncoding] mutableCopy];
		[responseData appendData:[GCDAsyncSocket ZeroData]];
		[sock writeData:responseData withTimeout:-1 tag:0];
		return;
	}
	
	if (data.length < 120) {
		NSLog(@"UNKNOWN DATA: %@", data);
		return;
	}
	
	strData = [data subdataWithRange:NSMakeRange(32, 88)];
	msg = [[NSString alloc] initWithData:strData encoding:NSASCIIStringEncoding];
	if (msg) {
		
		NSData *lengthData = [data subdataWithRange:NSMakeRange(4, 4)];
		int length = CFSwapInt32LittleToHost(*(int*)(lengthData.bytes))-172;
		
		NSData *commandData = [data subdataWithRange:NSMakeRange(192, length)];
		NSString *commandStr;
		if (![msg hasPrefix:@"version"]) commandStr = [self customDeShake:commandData];
		
		if ([msg hasPrefix:@"version"]) {
			
			NSData *commandToSend = [self makeResponse:3 :20 :2 :CLIENT_VERSION :@"version" :nil :0 :NO];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"wmi"]) {
			
//			NSLog(@"wmi: %@", commandStr);
			
			NSString *wmiStr = @"76746b72 78727473 76767e02 534b1f08 04000400 04090504 0804057a 7b716374 7a7b7c7b 273b6866 700e0965 67096111 03464207 1617096d 215a1420 392b0570 23216772 76626f78 7a071a00 02041706 09051c75 0e090d75 0265077c 7d747e02 74697171";
			NSData *commandToSend = [self makeResponseData:3 :20 :2 :[self dataFromHexString:wmiStr] :@"wmi" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"getRegistry"]) {
			
			NSLog(@"getRegistry: %@", commandStr);
			
			NSData *commandToSend = [self makeResponse:3 :20 :2 :CLIENT_VERSION :@"getRegistry" :@"CANNOT GET REGISTRY VALUE: [-1,'0x0']" :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"lgdisks"]) {
			
//			NSLog(@"lgdisks: %@", commandStr);
			
			NSData *commandToSend = [self makeResponse:3 :20 :2 :@"" :@"lgdisks" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"getListDirectories"]) {
			
			NSData *commandToSend = [self makeResponse:3 :20 :7 :[self fileStrAtPath:commandStr] :@"getListDirectories" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"execProcess"]) {
			
//			NSLog(@"execProcess: %@", commandStr);
			
			NSScanner *commandScanner = [NSScanner scannerWithString:commandStr];
			
			NSString *processId;
			NSString *gamePath;
			NSString *parameters;
			[commandScanner scanUpToString:@" " intoString:&processId];
			[commandScanner scanUpToString:@"  " intoString:&gamePath];
			[commandScanner scanUpToString:@"  " intoString:&parameters];
			gamePath = [gamePath stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
			gamePath = [gamePath stringByReplacingOccurrencesOfString:@"CoD2MP_s.exe" withString:@"Call of Duty 2 Multiplayer.app"];
			gamePath = [gamePath stringByAppendingString:@"/Contents/MacOS/Call of Duty 2 Multiplayer"];
			parameters = [@"+" stringByAppendingString:parameters];
			
			if ([NSUserDefaults.standardUserDefaults boolForKey:@"DISABLE_DOWNLOADS"]) {
				parameters = [parameters stringByReplacingOccurrencesOfString:@"+set cl_allowDownload 1" withString:@"+set cl_allowDownload 0"];
			}
			
//			NSLog(@"Launching %@", processId);
			
			if ([[NSFileManager defaultManager] fileExistsAtPath:gamePath]) {
				NSTask *task = [NSTask new];
				task.launchPath = gamePath;
				task.arguments = @[parameters];
				task.terminationHandler = ^(NSTask *aTask){
//					NSLog(@"Process %@ Terminated", processId);
					[_runningProcesses removeObjectForKey:processId];
					NSData *commandToSend = [self makeResponse:4 :30 :3 :processId :nil :nil :50 :YES];
					[_receivingSocket writeData:commandToSend withTimeout:TIMEOUT tag:PROCESS_TERMINATED];
				};
				[task launch];
				
				_runningProcesses[processId] = task;
				
				NSData *commandToSend = [self makeResponse:3 :20 :3 :@"" :@"execProcess" :nil :0 :NO];
				[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			} else {
				dispatch_async(dispatch_get_main_queue(), ^{
					NSRunAlertPanel(@"Game not found", @"", @"OK", nil, nil);
				});
			}
			
		} else if ([msg hasPrefix:@"killProcess"]) {
			
//			NSLog(@"killProcess: %@", commandStr);
			
			NSTask *task = _runningProcesses[commandStr];
			[task terminate];
			[_runningProcesses removeObjectForKey:commandStr];
			
			NSData *commandToSend = [self makeResponse:3 :20 :12 :@"" :@"killProcess" :nil :0 :NO];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"isProcessRunning"]) {
			
			BOOL running = _runningProcesses[commandStr] ? YES : NO;
			
			NSLog(@"isProcessRunning: %@ (%@)", commandStr, running ? @"YES" : @"NO");
			
			NSData *commandToSend = [self makeResponse:3 :20 :12 :@"" :@"isProcessRunning" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"setRegistry"]) {
			
			NSLog(@"setRegistry: %@", commandStr);
			
			NSData *commandToSend = [self makeResponse:3 :20 :12 :@"" :@"setRegistry" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"replaceParamsInConfig"]) {
			
			NSLog(@"replaceParamsInConfig: %@", commandStr);
			
			NSData *commandToSend = [self makeResponse:3 :20 :12 :@"" :@"replaceParamsInConfig" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"tcpredirect"]) {
			
			NSLog(@"tcpredirect: %@", commandStr);
			
			NSData *commandToSend = [self makeResponse:3 :20 :12 :@"" :@"tcpredirect" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else if ([msg hasPrefix:@"getudpstatus"]) {
			
			NSLog(@"getudpstatus: %@", commandStr);
			
			NSData *commandToSend = [self makeResponse:3 :20 :12 :@"" :@"getudpstatus" :nil :0 :YES];
			[sock writeData:commandToSend withTimeout:TIMEOUT tag:RESPONSE_TAG];
			
		} else {
			NSLog(@"Unknwon REQUEST: %@ / %@", msg, data);
		}
		
		return;
	}
	
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
	if (sock != listenSocket) _receivingSocket = nil;
}

#pragma mark - Response

- (NSData *)makeResponse:(int)cat :(int)param1 :(int)param2 :(NSString *)param3 :(NSString *)param4 :(NSString *)param5 :(int)param6 :(BOOL)shake {
	return [self makeResponseData:cat :param1 :param2 :[param3 dataUsingEncoding:NSASCIIStringEncoding] :param4 :param5 :param6 :shake];
}

- (NSData *)makeResponseData:(int)cat :(int)param1 :(int)param2 :(NSData *)param3 :(NSString *)param4 :(NSString *)param5 :(int)param6 :(BOOL)shake {
	NSData *_loc8_ = nil;
	NSMutableData *data = [NSMutableData data];
	if (shake) {
		_loc8_ = [self customShakeData:param3];
	}
	NSString *userId = @"0000000";	//1096199
	int var;
	
	var = CFSwapInt32HostToLittle(cat);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(172 + (int)param3.length);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(0);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(NSDate.date.timeIntervalSince1970);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(arc4random_uniform(1000));
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(1);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(param1);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(param2);
	[data appendBytes:&var length:4];
	
	if (param4) {
		[data appendData:[[self padString:param4 padding:32] dataUsingEncoding:NSASCIIStringEncoding]];
	} else {
		[data appendData:[NSMutableData dataWithLength:32]];
	}
	
	NSString *tmpStr = [NSString stringWithFormat:@"%@%d%d%d%d", userId, arc4random_uniform(10), arc4random_uniform(10), arc4random_uniform(10), arc4random_uniform(10)];
	[data appendData:[[self padString:tmpStr padding:32] dataUsingEncoding:NSASCIIStringEncoding]];
	
	[data appendData:[[self padString:userId padding:24] dataUsingEncoding:NSASCIIStringEncoding]];
	
	var = CFSwapInt32HostToLittle((int)param3.length);
	[data appendBytes:&var length:4];
	
	var = CFSwapInt32HostToLittle(param6);
	[data appendBytes:&var length:4];
	
	if (param5) {
		[data appendData:[[self padString:param5 padding:64] dataUsingEncoding:NSASCIIStringEncoding]];
	} else {
		[data appendData:[NSMutableData dataWithLength:64]];
	}
	
	if (shake) {
		[data appendData:_loc8_];
	} else {
		[data appendData:param3];
	}
	
	return [NSData dataWithData:data];
}

- (NSString *)padString:(NSString *)string padding:(int)padding {
	if (string.length < padding) {
		NSMutableString *mutableString = [string mutableCopy];
		int i = (int)string.length;
		while (i < padding) {
			[mutableString appendString:@"0"];
			i++;
		}
		string = [NSString stringWithString:mutableString];
	}
	return string;
}

#pragma mark - Shake

- (NSData *)customShake:(NSString *)string {
	return [self customShakeData:[string dataUsingEncoding:NSASCIIStringEncoding]];
}

- (NSData *)customShakeData:(NSData *)data {
	unsigned char var1 = NAN;
	unsigned char var2 = NAN;
	
	NSMutableData *mutableData = [data mutableCopy];
	char *bytes = [mutableData mutableBytes];
	int length = (int)mutableData.length - 1;
	
	int _loc4_ = 0;
	if (length > 0) {
		_loc4_ = bytes[0] % 110;
	}
	
	for (int i = 0; i < length / 2; i++) {
		var1 = bytes[i];
		bytes[i] = bytes[length - i];
		if (i > 0) {
			var2 = bytes[i];
			var1 = var1 ^ _loc4_;
			bytes[i] = var2 ^ _loc4_;
		}
		bytes[length - i] = var1;
	}
	
	return [NSData dataWithData:mutableData];
}

- (NSString *)customDeShake:(NSData *)data {
	unsigned char var1 = NAN;
	unsigned char var2 = NAN;
	unsigned char var3 = NAN;
	
	NSMutableData *mutableData = [data mutableCopy];
	char *bytes = [mutableData mutableBytes];
	int length = (int)mutableData.length - 1;
	
	for (int i = 0; i < length / 2; i++) {
		var2 = bytes[i];
		bytes[i] = bytes[length - i];
		if (i > 0) {
			var3 = bytes[i];
			var2 = var2 ^ var1;
			bytes[i] = var3 ^ var1;
		}
		if (i == 0) {
			var1 = bytes[0] % 110;
		}
		bytes[length - i] = var2;
	}
	
//	NSLog(@"Deshake: %@", mutableData);
	return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}

#pragma mark - Files

- (NSString *)fileStrAtPath:(NSString *)path {
	path = [path stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
	
	NSFileManager *fm = NSFileManager.defaultManager;
	NSArray *content = [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:path] includingPropertiesForKeys:@[] options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
	NSMutableString *mutableStr = [NSMutableString string];
	for (NSURL *url in content) {
		BOOL isDirectory;
		[mutableStr appendString:([fm fileExistsAtPath:url.path isDirectory:&isDirectory] && isDirectory) ? @"[D]" : @"[F]"];
		[mutableStr appendFormat:@" %@;;", url.lastPathComponent];
	}
	[mutableStr replaceOccurrencesOfString:@"[D] Call of Duty 2 Multiplayer.app" withString:@"[F] CoD2MP_s.exe" options:0 range:NSMakeRange(0, mutableStr.length)];
	return [NSString stringWithString:mutableStr];
}


@end
