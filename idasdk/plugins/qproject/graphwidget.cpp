/****************************************************************************
**
** Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial Usage
** Licensees holding valid Qt Commercial licenses may use this file in
** accordance with the Qt Commercial License Agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and Nokia.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU Lesser General Public License version 2.1 requirements
** will be met: http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Nokia gives you certain additional
** rights.  These rights are described in the Nokia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
** If you have questions regarding the use of this file, please contact
** Nokia at qt-info@nokia.com.
** $QT_END_LICENSE$
**
****************************************************************************/

#include "graphwidget.h"
#include "edge.h"
#include "node.h"

#include <QDebug>
#include <QGraphicsScene>
#include <QWheelEvent>
#include <QTime>

#include <math.h>

GraphWidget::GraphWidget()
  : timerId(0)
{
  qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));

  QGraphicsScene *scene = new QGraphicsScene(this);
  scene->setItemIndexMethod(QGraphicsScene::NoIndex);
  scene->setSceneRect(-400, -400, 800, 800);
  setScene(scene);
  setCacheMode(CacheBackground);
  setViewportUpdateMode(BoundingRectViewportUpdate);
  setRenderHint(QPainter::Antialiasing);
  setTransformationAnchor(AnchorUnderMouse);
  setResizeAnchor(AnchorViewCenter);

  Node *node1 = new Node(this);
  Node *node2 = new Node(this);
  Node *node3 = new Node(this);
  Node *node4 = new Node(this);
  centerNode = new Node(this);
  Node *node6 = new Node(this);
  Node *node7 = new Node(this);
  Node *node8 = new Node(this);
  Node *node9 = new Node(this);
  scene->addItem(node1);
  scene->addItem(node2);
  scene->addItem(node3);
  scene->addItem(node4);
  scene->addItem(centerNode);
  scene->addItem(node6);
  scene->addItem(node7);
  scene->addItem(node8);
  scene->addItem(node9);
  scene->addItem(new Edge(centerNode, node1));
  scene->addItem(new Edge(centerNode, node2));
  scene->addItem(new Edge(centerNode, node3));
  scene->addItem(new Edge(centerNode, node4));
  scene->addItem(new Edge(centerNode, node6));
  scene->addItem(new Edge(centerNode, node7));
  scene->addItem(new Edge(centerNode, node8));
  scene->addItem(new Edge(centerNode, node9));

  node1->setPos(-100, -100);
  node2->setPos(0, -100);
  node3->setPos(100, -100);
  node4->setPos(-100, 0);
  centerNode->setPos(0, 0);
  node6->setPos(100, 0);
  node7->setPos(-100, 100);
  node8->setPos(0, 100);
  node9->setPos(100, 100);

  scale(qreal(0.8), qreal(0.8));
  setMinimumSize(400, 400);
  setWindowTitle(tr("Elastic IDA Nodes"));
}

void GraphWidget::itemMoved()
{
  if (!timerId)
    timerId = startTimer(10);
}

void GraphWidget::keyPressEvent(QKeyEvent *event)
{
  switch (event->key()) {
  case Qt::Key_Up:
    centerNode->moveBy(0, -20);
    break;
  case Qt::Key_Down:
    centerNode->moveBy(0, 20);
    break;
  case Qt::Key_Left:
    centerNode->moveBy(-20, 0);
    break;
  case Qt::Key_Right:
    centerNode->moveBy(20, 0);
    break;
  case Qt::Key_Plus:
    scaleView(qreal(1.2));
    break;
  case Qt::Key_Minus:
    scaleView(1 / qreal(1.2));
    break;
  case Qt::Key_Space:
  case Qt::Key_Enter:
    foreach (QGraphicsItem *item, scene()->items()) {
      if (qgraphicsitem_cast<Node *>(item))
        item->setPos(-150 + qrand() % 300, -150 + qrand() % 300);
    }
    break;
    default:
    QGraphicsView::keyPressEvent(event);
  }
}

void GraphWidget::timerEvent(QTimerEvent *event)
{
  Q_UNUSED(event);

  QList<Node *> nodes;
  foreach (QGraphicsItem *item, scene()->items()) {
    if (Node *node = qgraphicsitem_cast<Node *>(item))
      nodes << node;
  }

  foreach (Node *node, nodes)
    node->calculateForces();

  bool itemsMoved = false;
  foreach (Node *node, nodes) {
    if (node->advance())
      itemsMoved = true;
  }

  if (!itemsMoved) {
    killTimer(timerId);
    timerId = 0;
  }
}

void GraphWidget::wheelEvent(QWheelEvent *event)
{
  scaleView(pow((double)2, -event->delta() / 240.0));
}

void GraphWidget::drawBackground(QPainter *painter, const QRectF &rect)
{
  Q_UNUSED(rect);

  // Shadow
  QRectF sceneRect = this->sceneRect();
  QRectF rightShadow(sceneRect.right(), sceneRect.top() + 5, 5, sceneRect.height());
  QRectF bottomShadow(sceneRect.left() + 5, sceneRect.bottom(), sceneRect.width(), 5);
  if (rightShadow.intersects(rect) || rightShadow.contains(rect))
    painter->fillRect(rightShadow, Qt::darkGray);
  if (bottomShadow.intersects(rect) || bottomShadow.contains(rect))
    painter->fillRect(bottomShadow, Qt::darkGray);

  // Fill
  QLinearGradient gradient(sceneRect.topLeft(), sceneRect.bottomRight());
  gradient.setColorAt(0, Qt::white);
  gradient.setColorAt(1, Qt::lightGray);
  painter->fillRect(rect.intersect(sceneRect), gradient);
  painter->setBrush(Qt::NoBrush);
  painter->drawRect(sceneRect);

  // Text
  QRectF textRect(sceneRect.left() + 4, sceneRect.top() + 4,
                  sceneRect.width() - 4, sceneRect.height() - 4);
  QString message(tr("Click and drag the nodes around, and zoom with the mouse "
                     "wheel or the '+' and '-' keys"));

  QFont font = painter->font();
  font.setBold(true);
  font.setPointSize(14);
  painter->setFont(font);
  painter->setPen(Qt::lightGray);
  painter->drawText(textRect.translated(2, 2), message);
  painter->setPen(Qt::black);
  painter->drawText(textRect, message);
}

void GraphWidget::scaleView(qreal scaleFactor)
{
  qreal factor = matrix().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width();
  if (factor < 0.07 || factor > 100)
    return;

  scale(scaleFactor, scaleFactor);
}
