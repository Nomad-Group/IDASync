#pragma once

//#include <Windows.h>
#include <QtGui/QDockWidget>
#include "ui_StatusBar.h"

class UIStatusBar : public QDockWidget, public Ui::DockWidget
{
	Q_OBJECT

public:
	UIStatusBar() : QDockWidget(QApplication::activeWindow())
	{
		setupUi(this);
	}

private:
};