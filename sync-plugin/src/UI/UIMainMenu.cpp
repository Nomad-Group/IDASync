#include "ui/UIMainMenu.h"

UIMainMenuResult UIShowMainMenu(bool isCurrentlyConnected)
{
	UIMainMenu mainMenu(isCurrentlyConnected);
	mainMenu.exec();

	return mainMenu.result;
}