//
//  AppDelegate.m
//  GamePark
//
//  Created by Martin on 12.08.14.
//  Copyright (c) 2014 gamepark. All rights reserved.
//

#import "AppDelegate.h"
#import "Client.h"

@implementation AppDelegate {
	
	NSStatusItem *_myStatusItem;
	
	Client *_client;
	
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
	
	_client = [Client new];
	if (!_client) {
		exit(EXIT_FAILURE);
		return;
	}

	_myStatusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
	
	_myStatusItem.image = [NSImage imageNamed:@"menuIcon-normal"];
	_myStatusItem.alternateImage = [NSImage imageNamed:@"menuIcon-selected"];
	_myStatusItem.highlightMode = YES;
	
	[_myStatusItem setMenu:_menuItemMenu];
	
	[self updateToggle];
	
}

- (IBAction)toggleDownloading:(NSMenuItem *)sender {
	BOOL disabled = [NSUserDefaults.standardUserDefaults boolForKey:@"DISABLE_DOWNLOADS"];
	[NSUserDefaults.standardUserDefaults setBool:!disabled forKey:@"DISABLE_DOWNLOADS"];
	[NSUserDefaults.standardUserDefaults synchronize];
	[self updateToggle];
}

- (void)updateToggle {
	if ([NSUserDefaults.standardUserDefaults boolForKey:@"DISABLE_DOWNLOADS"]) {
		_downloadingToggle.title = @"Povolit stahování";
	} else {
		_downloadingToggle.title = @"Zakázat stahování";
	}
}

@end
