#include "UI/UIFunctions.h"
#include "UI/UIStatusBar.h"

#include <QtWidgets/qmainwindow.h>
#include <QtWidgets/qstatusbar.h>

UIStatusBar* uiStatusBar = nullptr;

void UIShowStatusBar()
{
	if (uiStatusBar)
		return;

	// Dock to Status Bar
	auto mainWindow = qobject_cast<QMainWindow*>(QApplication::activeWindow()->topLevelWidget());
	if (mainWindow)
	{
		auto statusBar = mainWindow->statusBar();
		if (statusBar)
		{
			uiStatusBar = new UIStatusBar();
			uiStatusBar->show();

			statusBar->addPermanentWidget(uiStatusBar);
			return;
		}
	}
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

	std::string col = "QWidget { background-color: " + std::string(color) + "; }";
	uiStatusBar->setStyleSheet(col.c_str());
}

void UIStatusBarSetText(const std::string& text)
{
	if (uiStatusBar == nullptr)
		return;

	uiStatusBar->setWindowTitle(("IDA Sync-Plugin - " + text).c_str());
}