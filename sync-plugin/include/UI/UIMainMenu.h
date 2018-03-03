#pragma once

#include "UIFunctions.h"
#include <QtGui/QDialog>
#include "ui_MenuMain.h"

class UIMainMenu : public QDialog, public Ui::MainMenu
{
	Q_OBJECT

public:
	UIMainMenu() : QDialog(QApplication::activeWindow())
	{
		setupUi(this);

		connect(buttonOkay, SIGNAL(clicked()), this, SLOT(onClickOkay()));
		connect(list, SIGNAL(itemDoubleClicked(QListWidgetItem*)), this, SLOT(onClickOkay()));
		connect(buttonCancel, SIGNAL(clicked()), this, SLOT(close()));
	}

	UIMainMenuResult result = UIMainMenuResult::Cancel;

private slots:
	void onClickOkay()
	{
		auto selectedItems = list->selectedItems();
		if (selectedItems.count() > 0)
		{
			auto selectedItem = selectedItems.front();
			if (selectedItem->text() == "Connect" || selectedItem->text() == "Disconnect")
				result = UIMainMenuResult::ConnectDisconnect;
			else if (selectedItem->text() == "Request Updates")
				result = UIMainMenuResult::RequestUpdates;
		}

		close();
	}

private:
};