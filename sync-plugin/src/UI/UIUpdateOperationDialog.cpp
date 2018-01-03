#include "ui/UIUpdateOperationDialog.h"

UIUpdateOperationDialog* uiUpdateOperationDialog = nullptr;

void UIShowUpdateOperationDialog()
{
	if (uiUpdateOperationDialog == nullptr)
		uiUpdateOperationDialog = new UIUpdateOperationDialog();

	if(!uiUpdateOperationDialog->isVisible())
		uiUpdateOperationDialog->show();
}

void UIProgressUpdateOperationDialog(int progress, const char* label)
{
	if (uiUpdateOperationDialog == nullptr)
		return;

	uiUpdateOperationDialog->progressBar->setValue(progress);
	uiUpdateOperationDialog->labelProgress->setText(label);
}

void UIHideUpdateOperationDialog()
{
	delete uiUpdateOperationDialog;
	uiUpdateOperationDialog = nullptr;
}