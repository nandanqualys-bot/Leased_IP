"""Refined controls that preserve the existing layout and input contracts."""
from PySide6.QtCore import Qt, QVariantAnimation, QEasingCurve, QRectF, Signal
from PySide6.QtGui import QColor, QPainter, QPalette, QBrush
from PySide6.QtWidgets import (QComboBox, QSpinBox, QLineEdit, QStyledItemDelegate,
                              QStyle, QStyleOptionFrame)
import re


class FocusSpinBox(QSpinBox):
    def __init__(self, *args):
        super().__init__(*args)
        self.setFocusPolicy(Qt.StrongFocus)

    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class SoftSelection(QStyledItemDelegate):
    """Rounded selection paint, independent of the host platform's item style."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.alpha = 65
        self.motion = QVariantAnimation(self); self.motion.setDuration(150)
        self.motion.valueChanged.connect(self._update_alpha)
        if parent is not None and parent.selectionModel() is not None:
            parent.selectionModel().selectionChanged.connect(self._animate)

    def _animate(self, *_):
        self.motion.stop(); self.motion.setStartValue(30); self.motion.setEndValue(65); self.motion.start()

    def _update_alpha(self, value):
        self.alpha = value
        if self.parent() is not None: self.parent().viewport().update()

    def paint(self, painter, option, index):
        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        if selected or hovered:
            painter.save(); painter.setRenderHint(QPainter.Antialiasing)
            color = QColor('#7C94B8'); color.setAlpha(self.alpha if selected else 25)
            painter.setPen(Qt.NoPen); painter.setBrush(color)
            painter.drawRoundedRect(QRectF(option.rect).adjusted(2, 2, -2, -2), 6, 6)
            painter.restore()
            option.state &= ~(QStyle.State_Selected | QStyle.State_MouseOver)
            option.backgroundBrush=QBrush(Qt.NoBrush)
            text=option.palette.color(QPalette.Text)
            option.palette.setColor(QPalette.Highlight,text)
            option.palette.setColor(QPalette.HighlightedText,text)
        super().paint(painter, option, index)


class RefinedComboBox(QComboBox):
    def __init__(self, *args):
        super().__init__(*args)
        self.setFocusPolicy(Qt.StrongFocus)
        self.view().setItemDelegate(SoftSelection(self.view()))
        self._opening = QVariantAnimation(self)
        self._opening.setDuration(160); self._opening.setEasingCurve(QEasingCurve.OutCubic)
        self._opening.valueChanged.connect(lambda value: self.view().window().setWindowOpacity(value))

    def showPopup(self):
        super().showPopup()
        self._opening.stop(); self._opening.setStartValue(.85); self._opening.setEndValue(1.)
        self._opening.start()

    def hidePopup(self):
        self._opening.stop(); self.view().window().setWindowOpacity(1.)
        super().hidePopup()

    def wheelEvent(self, event):
        if self.hasFocus(): super().wheelEvent(event)
        else: event.ignore()


def paint_tokens(painter, rect, values, color):
    painter.save(); painter.setClipRect(rect); painter.setRenderHint(QPainter.Antialiasing)
    x = rect.left() + 5
    for position, value in enumerate(values):
        width = painter.fontMetrics().horizontalAdvance(value) + 16
        available = rect.right() - x - 5
        if width > available:
            value = f'+{len(values)-position}'
            width = painter.fontMetrics().horizontalAdvance(value) + 16
        if width > available: break
        box = QRectF(x, rect.center().y()-12, width, 24)
        painter.setPen(Qt.NoPen); painter.setBrush(QColor(128,140,160,35))
        painter.drawRoundedRect(box, 6, 6)
        painter.setPen(color); painter.drawText(box, Qt.AlignCenter, value)
        x += width + 5
        if value.startswith('+'): break
    painter.restore()


class TokenInput(QLineEdit):
    """Semicolon editing on focus; tokens and a full tooltip when browsing."""
    valuesChanged = Signal(list)
    def __init__(self, *args, comma_separator=True):
        super().__init__(*args)
        self.comma_separator = comma_separator
        self.setPlaceholderText('Enter a value and press Enter')
        self.returnPressed.connect(self.commit_values)
        self.textChanged.connect(lambda _text: self.update())

    def values(self):
        pattern=r'[,;\n\r]+' if self.comma_separator else r'[;\n\r]+'
        return list(dict.fromkeys(v.strip() for v in re.split(pattern,self.text()) if v.strip()))

    def commit_values(self):
        values = self.values(); self.blockSignals(True); self.setText('; '.join(values)); self.blockSignals(False)
        self.setToolTip('\n'.join(values)); self.valuesChanged.emit(values); self.update()

    def focusOutEvent(self,event):
        self.commit_values(); super().focusOutEvent(event)

    def mousePressEvent(self,event):
        if not self.hasFocus():
            values=self.values(); x=10
            for position,value in enumerate(values):
                width=self.fontMetrics().horizontalAdvance(value)+34
                if x <= event.position().x() <= x+width and event.position().x() >= x+width-17:
                    values.pop(position); self.setText('; '.join(values)); self.setToolTip('\n'.join(values))
                    event.accept(); return
                x += width+5
        super().mousePressEvent(event)

    def paintEvent(self, event):
        if self.hasFocus() or not self.text():
            return super().paintEvent(event)
        painter = QPainter(self)
        option = QStyleOptionFrame(); self.initStyleOption(option)
        self.style().drawPrimitive(QStyle.PE_PanelLineEdit, option, painter, self)
        paint_tokens(painter, self.rect().adjusted(5,0,-5,0), self.values(), self.palette().color(QPalette.Text))


class TokenDelegate(SoftSelection):
    def paint(self, painter, option, index):
        values = index.data(Qt.UserRole + 1)
        if not values:
            return super().paint(painter, option, index)
        self.initStyleOption(option, index); option.text = ''
        # Draw the selection without a concatenated string underneath the tokens.
        if option.state & QStyle.State_Selected:
            painter.save(); painter.setPen(Qt.NoPen); painter.setBrush(QColor(124,148,184,65))
            painter.drawRoundedRect(QRectF(option.rect).adjusted(2,2,-2,-2),6,6); painter.restore()
        paint_tokens(painter, option.rect, values, option.palette.color(QPalette.Text))
