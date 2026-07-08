import os
import sys


if "--smoke-test" in sys.argv:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if sys.platform == "win32":
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PhilSys.MANTool")
    except Exception:
        pass

from PySide6.QtWidgets import QApplication

from nas_transfer_app.gui import MainWindow, run_app

if __name__ == "__main__":
    if "--smoke-test" in sys.argv:
        app = QApplication([])
        window = MainWindow()
        window.show()
        app.processEvents()
        window.close()
        sys.exit(0)

    run_app()
