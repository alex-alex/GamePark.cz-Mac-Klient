//
//  AppDelegate.h
//  GamePark
//
//  Created by Martin on 12.08.14.
//  Copyright (c) 2014 gamepark. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate> {
	
	__weak IBOutlet NSMenu *_menuItemMenu;
	__weak IBOutlet NSMenuItem *_downloadingToggle;
	
}

@property (assign) IBOutlet NSWindow *window;

- (IBAction)toggleDownloading:(NSMenuItem *)sender;

@end
