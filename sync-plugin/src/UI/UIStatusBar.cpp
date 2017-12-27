#include "UI/UIFunctions.h"
#include "UI/UIStatusBar.h"

UIStatusBar* uiStatusBar = nullptr;

void UIShowStatusBar()
{
	if (uiStatusBar)
		return;

	uiStatusBar = new UIStatusBar();
	uiStatusBar->show();
}

void UIHideStatusBar()
{
	delete uiStatusBar;
	uiStatusBar = nullptr;
}

void UIStatusBarSetColor(const char* color)
{
	if (uiStatusBar == nullptr)
		return;

	std::string col = "QDockWidget { background-color: " + std::string(color) + "; }";
	uiStatusBar->setStyleSheet(col.c_str());
}