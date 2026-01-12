import sys

# Хак для путей когда python venv не совпадает с системным
sys.path.append("/usr/lib/python3/dist-packages")

from src.app import FileSpyApp

if __name__ == "__main__":
    app = FileSpyApp()
    app.run()
