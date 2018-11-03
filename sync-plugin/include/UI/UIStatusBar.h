#pragma once

#include <QtWidgets/qdockwidget.h>
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