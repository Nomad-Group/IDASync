#pragma once

#include <QtGui/QDockWidget>
#include "ui_StatusBar.h"

class UIStatusBar : public QDockWidget, public Ui::StatusBar
{
	Q_OBJECT

public:
	UIStatusBar() : QDockWidget(QApplication::activeWindow())
	{
		setupUi(this);
	}

private:
};