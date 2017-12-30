#pragma once

#include <QtGui/QDialog>
#include "ui_AutoConnectStartupDialog.h"

class UIAutoConnectStartupDialog : public QDialog, public Ui::AutoConnectStartupDialog
{
	Q_OBJECT

public:
	UIAutoConnectStartupDialog() : QDialog(QApplication::activeWindow())
	{
		setupUi(this);
		connect(button_yes, SIGNAL(clicked()), this, SLOT(onClickYes()));
		connect(button_no, SIGNAL(clicked()), this, SLOT(close()));
	}

	bool shouldConnect = false;

private slots:
	void onClickYes()
	{
		shouldConnect = true;
		close();
	}

private:
};