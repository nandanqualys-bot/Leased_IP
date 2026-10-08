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
QWidget { font-family: "Inter", "Segoe UI Variable", "Segoe UI", Arial; font-size: 10pt; color: #E7ECF3; background: #111925; }
QLabel { background: transparent; }
QFrame#sidebar { background: rgba(27,39,54,235); border-right: 1px solid rgba(88,109,136,120); }
QFrame#hero { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #203B5D,stop:1 #315D83); border: 0; border-radius: 22px; }
QFrame#metricCard, QFrame#panel, QFrame#detailCard { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(37,53,72,249),stop:1 rgba(29,43,61,242)); border: 1px solid rgba(97,122,154,115); border-radius: 18px; }
QLabel#brand { color: #EDF4FD; font-size: 17pt; font-weight: 750; letter-spacing: 1px; }
QLabel#eyebrow { color: #8FA4BD; font-size: 9pt; font-weight: 700; letter-spacing: 1.4px; }
QLabel#heading { color: #F3F7FC; font-size: 27pt; font-weight: 700; }
QLabel#sectionTitle { color: #ECF3FB; font-size: 16pt; font-weight: 650; }
QLabel#metricValue { color: #F2F7FF; font-size: 24pt; font-weight: 700; }
QLabel#muted { color: #97A8BC; }
QLabel#heroTitle { color: white; font-size: 25pt; font-weight: 700; }
QLabel#heroText { color: #DCEAF7; font-size: 11pt; }
QLabel#statusChip { background: #214D42; color: #A5EDD0; border-radius: 10px; padding: 4px 10px; font-weight: 700; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #30465E,stop:1 #25394F); border: 1px solid #40546C; border-radius: 11px; padding: 9px 14px; color: #ECF2FB; font-weight: 600; }
QPushButton:hover { background: #304860; }
QPushButton:disabled { color: #697C92; background: #223044; }
QPushButton#primary { background: #4A8CD7; color: #091A2D; border: 1px solid #4A8CD7; }
QPushButton#primary:hover { background: #65A4E9; }
QPushButton#danger { color: #F0A6B1; background: #3B2C3A; border: 1px solid #674453; }
QPushButton#danger:hover { background: #503344; }
QPushButton:focus { border: 1px solid #70A9E6; }
QPushButton#heroAction { background: white; color: #1E517E; border: 0; padding: 12px 20px; }
QPushButton#navItem { background: transparent; border: 0; text-align: left; padding: 12px 16px; color: #A8B8CB; }
QPushButton#navItem:hover { background: #24384D; }
QPushButton#navItem[active="true"] { background: #2B425C; color: #DCEEFF; border: 1px solid #3D5873; font-weight: 700; }
QLineEdit, QTextEdit, QPlainTextEdit, QTableWidget, QComboBox, QSpinBox { background: #1D2D40; border: 1px solid #3D526B; border-radius: 10px; padding: 8px; selection-background-color: #355B88; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #70A9E6; }
QTableWidget { gridline-color: transparent; alternate-background-color: #223348; selection-background-color: #335475; selection-color: white; }
QHeaderView::section { background: #26394F; color: #ABBDD2; border: 0; border-bottom: 1px solid #3A4D63; padding: 10px; font-weight: 700; }
QTabWidget::pane { border: 1px solid #334358; border-radius: 12px; background: #1C2A3A; }
QTabBar::tab { background: transparent; padding: 11px 15px; color: #9AACBF; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #91C2FA; border-bottom: 2px solid #70A9E6; font-weight: 700; }
QProgressBar { background: #2A3A4D; border: 0; border-radius: 6px; height: 9px; text-align: center; color: transparent; }
QProgressBar::chunk { background: #65A4E9; border-radius: 6px; }
QStatusBar { background: #172331; color: #91A6BF; border-top: 1px solid #2B394B; }
'''
