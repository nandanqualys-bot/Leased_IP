"""Atlas EASM desktop entry point: python main.py"""
import sys
from PySide6.QtWidgets import QApplication
from app.window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Atlas EASM')
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
