#pragma once

// Status Bar
void UIShowStatusBar();
void UIHideStatusBar();
void UIStatusBarSetColor(const char* color);

// Auto Connect Startup Dialog
bool UIShowAutoConnectStartupDialog(); // true => Connect

// Update Operation Progress
void UIShowUpdateOperationDialog();
void UIProgressUpdateOperationDialog(int progress, const char* label);
void UIHideUpdateOperationDialog();

// Main Menu
enum class UIMainMenuResult
{
	Cancel = 0,

	ConnectDisconnect,
	RequestUpdates
};

UIMainMenuResult UIShowMainMenu();