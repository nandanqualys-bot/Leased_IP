"""A single 24px vector family with rounded, consistent strokes."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QPixmap, QPainter, QPen, QColor

def navigation_icon(index):
    pixmap = QPixmap(24, 24); pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap); painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(QColor('#8A8A8E'), 1.7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if index == 0:
        for x,y in ((4,4),(14,4),(4,14),(14,14)): painter.drawRoundedRect(x,y,6,6,1,1)
    elif index == 1:
        painter.drawRoundedRect(4,4,16,16,4,4); painter.drawLine(8,12,16,12); painter.drawLine(12,8,12,16)
    elif index in (4,6):
        painter.drawEllipse(4,4,16,16); painter.drawLine(12,7,12,12); painter.drawLine(12,12,16,14)
        if index == 6: painter.drawPoint(7,12)
    elif index == 2:
        for y in (5,13):
            painter.drawRoundedRect(4,y,16,6,2,2); painter.drawPoint(17,y+3)
    elif index == 7:
        painter.drawRoundedRect(6,3,12,18,2,2)
        for y in (8,12,16): painter.drawLine(9,y,15,y)
    elif index == 8:
        painter.drawLine(12,3,12,15); painter.drawLine(8,11,12,15); painter.drawLine(12,15,16,11)
        painter.drawLine(4,16,4,20); painter.drawLine(4,20,20,20); painter.drawLine(20,20,20,16)
    elif index == 3:
        painter.drawEllipse(9,3,6,6); painter.drawRoundedRect(5,12,14,8,3,3)
    else:
        for y,x in ((6,9),(12,15),(18,8)):
            painter.drawLine(4,y,20,y); painter.drawEllipse(x-2,y-2,4,4)
    painter.end(); return QIcon(pixmap)
