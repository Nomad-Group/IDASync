#pragma once

#include <Windows.h>
#include <QtGui/QDialog>
#include "ui_TestDialog.h"

class ExampleDialog : public QDialog, public Ui::Dialog
{
	// This Qt macro "Q_OBJECT" tells the Qt Add-in to invoke the moc compiler
	Q_OBJECT
public:
	// "QApplication::activeWindow()" gets the IDA parent QWidget
	ExampleDialog() : QDialog(QApplication::activeWindow())
	{
		// Initialize the dialog
		setupUi(this);

		// Hide the help caption button
		setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
	}

private:
};