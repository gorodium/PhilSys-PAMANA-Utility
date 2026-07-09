import sys
import queue
from nas_transfer_app.gui import MainWindow
from PySide6.QtWidgets import QApplication
import threading

app = QApplication(sys.argv)
window = MainWindow()

# Manually trigger
print("Triggering sync_nas_analytics...")
try:
    window.sync_nas_analytics()
    print("Function returned.")
except Exception as e:
    print("Error:", e)
