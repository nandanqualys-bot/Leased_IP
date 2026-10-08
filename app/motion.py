"""Small, interruptible animations without moving the page layout."""
from PySide6.QtCore import QVariantAnimation, QEasingCurve, QObject, QEvent
from PySide6.QtWidgets import QLabel, QProgressBar, QScrollBar, QGraphicsOpacityEffect

class NumberLabel(QLabel):
    def __init__(self, text):
        super().__init__(text)
        self.motion = QVariantAnimation(self)
        self.motion.setDuration(180)
        self.motion.setEasingCurve(QEasingCurve.OutCubic)
        self.motion.valueChanged.connect(lambda value: QLabel.setText(self, str(round(value))))

    def setText(self, text):
        if text.isdigit() and self.text().isdigit() and self.isVisible():
            self.motion.stop(); self.motion.setStartValue(float(self.text()))
            self.motion.setEndValue(float(text)); self.motion.start()
        else:
            super().setText(text)

class ProgressBar(QProgressBar):
    def __init__(self):
        super().__init__()
        self.motion = QVariantAnimation(self); self.motion.setDuration(180)
        self.motion.valueChanged.connect(lambda value: QProgressBar.setValue(self, round(value)))

    def setValue(self, value):
        self.motion.stop(); self.motion.setStartValue(float(max(0,self.value())))
        self.motion.setEndValue(float(value)); self.motion.start()

class ScrollbarMotion(QObject):
    def eventFilter(self, obj, event):
        if isinstance(obj, QScrollBar):
            if event.type() == QEvent.Show and not hasattr(obj, '_fade'):
                effect = QGraphicsOpacityEffect(obj); effect.setOpacity(.65); obj.setGraphicsEffect(effect)
                obj._fade = QVariantAnimation(obj); obj._fade.setDuration(180)
                obj._fade.valueChanged.connect(effect.setOpacity)
            if hasattr(obj, '_fade') and event.type() in (QEvent.Enter, QEvent.Leave):
                obj._fade.stop(); obj._fade.setStartValue(obj.graphicsEffect().opacity())
                obj._fade.setEndValue(1.0 if event.type() == QEvent.Enter else .65); obj._fade.start()
        return False
