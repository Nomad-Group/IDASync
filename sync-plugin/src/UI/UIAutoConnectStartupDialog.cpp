#include "UI/UIFunctions.h"
#include "UI/UIAutoConnectStartupDialog.h"

bool UIShowAutoConnectStartupDialog()
{
	UIAutoConnectStartupDialog dialog;
	dialog.exec();

	return dialog.shouldConnect;
}