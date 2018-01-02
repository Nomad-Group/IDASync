#pragma once

#include <QtGui/QDialog>
#include "ui_UpdateOperationDialog.h"

class UIUpdateOperationDialog : public QDialog, public Ui::UpdateOperationDialog
{
	Q_OBJECT

public:
	UIUpdateOperationDialog() : QDialog(QApplication::activeWindow())
	{
		setupUi(this);
	}

private:
};