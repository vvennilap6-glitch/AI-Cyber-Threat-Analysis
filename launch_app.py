import os
import subprocess
import sys
import time
import webbrowser
import shutil


if getattr(sys, "frozen", False):
    # When running as the .exe, the project folder is one level above dist
    PROJECT_FOLDER = os.path.dirname(
        os.path.dirname(os.path.abspath(sys.executable))
    )

    python_command = shutil.which("python")

    if not python_command:
        python_command = shutil.which("py")

    if not python_command:
        raise RuntimeError("Python was not found on this computer.")

else:
    # When running normally with Python
    PROJECT_FOLDER = os.path.dirname(os.path.abspath(__file__))
    python_command = sys.executable


APP_FILE = os.path.join(PROJECT_FOLDER, "app.py")


subprocess.Popen(
    [
        python_command,
        "-m",
        "streamlit",
        "run",
        APP_FILE,
        "--server.headless=true",
    ],
    cwd=PROJECT_FOLDER,
)

time.sleep(5)

webbrowser.open("http://localhost:8501")