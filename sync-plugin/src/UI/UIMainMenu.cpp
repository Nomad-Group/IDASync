#include "ui/UIMainMenu.h"

UIMainMenuResult UIShowMainMenu()
{
	UIMainMenu mainMenu;
	mainMenu.exec();

	return mainMenu.result;
}