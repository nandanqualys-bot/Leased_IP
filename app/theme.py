"""Calm, high-contrast desktop design tokens for the Qt widget interface."""
LIGHT = '''
QWidget { font-family: "Inter", "Segoe UI Variable", "Segoe UI", Arial; font-size: 10pt; color: #202936; background: #F6F7F9; }
QLabel { background: transparent; }
QFrame#sidebar { background: rgba(232,236,242,224); border-right: 1px solid rgba(188,199,214,150); }
QFrame#hero { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #162B4A,stop:0.62 #254D75,stop:1 #3B79A8); border: 0; border-radius: 22px; }
QFrame#metricCard, QFrame#panel, QFrame#detailCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(255,255,255,250),stop:1 rgba(249,252,255,239)); border: 1px solid rgba(216,224,235,185); border-radius: 18px; }
QLabel#brand { color: #172A43; font-size: 17pt; font-weight: 750; letter-spacing: 1px; }
QLabel#eyebrow { color: #7C8999; font-size: 9pt; font-weight: 700; letter-spacing: 1.4px; }
QLabel#heading { color: #162339; font-size: 27pt; font-weight: 700; }
QLabel#sectionTitle { color: #1D2B3D; font-size: 16pt; font-weight: 650; }
QLabel#metricValue { color: #1B304C; font-size: 24pt; font-weight: 700; }
QLabel#muted { color: #728093; }
QLabel#heroTitle { color: white; font-size: 25pt; font-weight: 700; }
QLabel#heroText { color: #DFEAF4; font-size: 11pt; }
QLabel#statusChip { background: #E8F4ED; color: #1B7450; border-radius: 10px; padding: 4px 10px; font-weight: 700; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #FFFFFF,stop:1 #F6F8FB); border: 1px solid #DDE3EB; border-radius: 11px; padding: 9px 14px; font-weight: 600; color: #25354A; }
QPushButton:hover { background: #F1F6FC; border-color: #BACDE1; }
QPushButton:disabled { color: #A3ACB8; background: #F2F3F5; }
QPushButton#primary { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #3881CF,stop:1 #2869BC); color: white; border: 1px solid #2869BC; }
QPushButton#primary:hover { background: #1F58A4; }
QPushButton#danger { color: #AD4454; background: rgba(255,249,250,245); border: 1px solid #ECD8DC; }
QPushButton#danger:hover { background: #FBEDEF; }
QPushButton:focus { border: 1px solid #60A2E8; }
QPushButton#heroAction { background: white; color: #184A79; border: 0; padding: 12px 20px; }
QPushButton#navItem { background: transparent; border: 0; border-radius: 10px; text-align: left; padding: 12px 16px; color: #617084; }
QPushButton#navItem:hover { background: #E3E9F0; color: #19395E; }
QPushButton#navItem[active="true"] { background: #FFFFFF; color: #205B9A; font-weight: 700; border: 1px solid #E0E5EB; }
QLineEdit, QTextEdit, QPlainTextEdit, QTableWidget, QComboBox, QSpinBox { background: white; border: 1px solid #D9E0E8; border-radius: 10px; padding: 8px; selection-background-color: #BFD8F6; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #4D8ACD; }
QTableWidget { gridline-color: transparent; alternate-background-color: #F9FAFC; selection-background-color: #E8F1FC; selection-color: #18365A; }
QHeaderView::section { background: #F7F9FB; color: #6D7B8D; border: 0; border-bottom: 1px solid #E4E9EF; padding: 10px; font-size: 9pt; font-weight: 700; }
QTabWidget::pane { border: 1px solid #E3E7ED; border-radius: 12px; background: white; }
QTabBar::tab { background: transparent; padding: 11px 15px; color: #69788B; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #245FAD; border-bottom: 2px solid #2B72C6; font-weight: 700; }
QProgressBar { background: #E9EDF2; border: 0; border-radius: 6px; height: 9px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #347AC5; border-radius: 6px; }
QStatusBar { background: #F0F2F5; color: #718095; border-top: 1px solid #E0E5EB; }
'''
DARK = '''
QWidget { font-family: "Inter", "Segoe UI Variable", "Segoe UI", Arial; font-size: 10pt; color: #EBEBEB; background: #181818; }
QLabel { background: transparent; }
QFrame#sidebar { background: rgba(28,28,30,235); border-right: 1px solid rgba(110,110,112,120); }
QFrame#hero { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #383838,stop:1 #565656); border: 0; border-radius: 22px; }
QFrame#metricCard, QFrame#panel, QFrame#detailCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(49,49,51,249),stop:1 rgba(36,36,38,242)); border: 1px solid rgba(130,130,132,115); border-radius: 18px; }
QLabel#brand { color: #F3F3F3; font-size: 17pt; font-weight: 750; letter-spacing: 1px; }
QLabel#eyebrow { color: #A1A1A1; font-size: 9pt; font-weight: 700; letter-spacing: 1.4px; }
QLabel#heading { color: #F7F7F7; font-size: 27pt; font-weight: 700; }
QLabel#sectionTitle { color: #F2F2F2; font-size: 16pt; font-weight: 650; }
QLabel#metricValue { color: #F7F7F7; font-size: 24pt; font-weight: 700; }
QLabel#muted { color: #A6A6A6; }
QLabel#heroTitle { color: white; font-size: 25pt; font-weight: 700; }
QLabel#heroText { color: #E8E8E8; font-size: 11pt; }
QLabel#statusChip { background: #434343; color: #DCDCDC; border-radius: 10px; padding: 4px 10px; font-weight: 700; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #434343,stop:1 #363636); border: 1px solid #515151; border-radius: 11px; padding: 9px 14px; color: #F1F1F1; font-weight: 600; }
QPushButton:hover { background: #454545; }
QPushButton:disabled { color: #7A7A7A; background: #2E2E2E; }
QPushButton#primary { background: #838383; color: #181818; border: 1px solid #838383; }
QPushButton#primary:hover { background: #9C9C9C; }
QPushButton#danger { color: #B7B7B7; background: #303030; border: 1px solid #4D4D4D; }
QPushButton#danger:hover { background: #3A3A3A; }
QPushButton:focus { border: 1px solid #A1A1A1; }
QPushButton#heroAction { background: white; color: #494949; border: 0; padding: 12px 20px; }
QPushButton#navItem { background: transparent; border: 0; text-align: left; padding: 12px 16px; color: #B6B6B6; }
QPushButton#navItem:hover { background: #353535; }
QPushButton#navItem[active="true"] { background: #3F3F3F; color: #EBEBEB; border: 1px solid #545454; font-weight: 700; }
QLineEdit, QTextEdit, QPlainTextEdit, QTableWidget, QComboBox, QSpinBox { background: #2B2B2B; border: 1px solid #4F4F4F; border-radius: 10px; padding: 8px; selection-background-color: #565656; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #A1A1A1; }
QTableWidget { gridline-color: transparent; alternate-background-color: #313131; selection-background-color: #4F4F4F; selection-color: white; }
QHeaderView::section { background: #373737; color: #BBBBBB; border: 0; border-bottom: 1px solid #4B4B4B; padding: 10px; font-weight: 700; }
QTabWidget::pane { border: 1px solid #414141; border-radius: 12px; background: #282828; }
QTabBar::tab { background: transparent; padding: 11px 15px; color: #AAAAAA; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #BCBCBC; border-bottom: 2px solid #A1A1A1; font-weight: 700; }
QProgressBar { background: #383838; border: 0; border-radius: 6px; height: 9px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #9C9C9C; border-radius: 6px; }
QStatusBar { background: #212121; color: #A3A3A3; border-top: 1px solid #373737; }
'''

# Shared application-wide controls, including dialogs and nested scroll areas.
CONTROLS = """
QScrollBar:vertical { background: transparent; width: 9px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 9px; margin: 2px; }
QScrollBar::handle { background: rgba(140,140,145,100); border-radius: 3px; min-height: 24px; min-width: 24px; }
QScrollBar::handle:hover { background: rgba(140,140,145,190); }
QScrollBar::handle:pressed { background: rgba(140,140,145,230); }
QScrollBar::add-line, QScrollBar::sub-line { width: 0px; height: 0px; border: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QPushButton:pressed { padding-top: 10px; padding-bottom: 8px; }
QToolTip { padding: 7px; border: 1px solid #888888; border-radius: 6px; }
QScrollArea { border: none; background: transparent; }
"""
LIGHT += CONTROLS
DARK += CONTROLS

REFINED_CONTROLS = '''
QComboBox:hover, QSpinBox:hover, QLineEdit:hover { border-color: #9199A5; }
QComboBox::drop-down { border: none; width: 24px; border-top-right-radius: 9px; border-bottom-right-radius: 9px; }
QComboBox QAbstractItemView { outline: 0; border: 1px solid #969BA3; border-radius: 10px; padding: 5px; selection-background-color: transparent; }
QComboBox QAbstractItemView::item { padding: 7px 10px; border-radius: 6px; }
QMenu { border: 1px solid #969BA3; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 7px 16px; border-radius: 6px; }
QMenu::item:selected { background: rgba(124,148,184,65); }
QCheckBox::indicator, QRadioButton::indicator { width: 14px; height: 14px; border: 1px solid #9299A4; background: transparent; }
QCheckBox::indicator { border-radius: 4px; }
QRadioButton::indicator { border-radius: 7px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background: #8299BA; border: 2px solid #B5C6DD; }
QCheckBox::indicator:hover, QRadioButton::indicator:hover { border-color: #7FA9D9; }
'''
LIGHT += REFINED_CONTROLS
DARK += REFINED_CONTROLS

DARK += """
QPushButton#primary { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #EFEFF1,stop:1 #CDCDCF); color: #202022; border: 1px solid #DADADC; }
QPushButton#primary:hover { background: #FFFFFF; }
QPushButton#primary:disabled { background: #454547; color: #909092; border-color: #505052; }
QPushButton#danger { color: #E2A2A2; background: #303032; border-color: #49494B; }
"""
