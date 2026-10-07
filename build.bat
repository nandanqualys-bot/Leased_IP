@echo off
setlocal
python -m pip install pyinstaller || exit /b 1
python -m PyInstaller --noconfirm --clean --windowed --onefile --name AtlasEASM --collect-all PySide6 --add-data "01_generate_input.py;." --add-data "02_off_asn_discovery.py;." --add-data "04_ip_verification.py;." --add-data "config.json;." main.py
exit /b %ERRORLEVEL%
