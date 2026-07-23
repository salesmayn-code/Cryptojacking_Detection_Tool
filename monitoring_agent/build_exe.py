# Build script for creating Windows .exe from agent_gui.py
# Uses PyInstaller

# Install PyInstaller first:
# pip install pyinstaller

import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def ensure_icon_file() -> Path | None:
    """Create a simple tray icon if one is not already present."""
    icon_path = Path("agent_icon.ico")
    if icon_path.exists():
        return icon_path

    try:
        from PIL import Image, ImageDraw

        image = Image.new("RGB", (64, 64), color=(24, 34, 54))
        draw = ImageDraw.Draw(image)
        draw.rectangle((8, 8, 56, 56), outline=(72, 126, 245), width=3)
        draw.text((19, 21), "CD", fill=(72, 126, 245))
        image.save(icon_path, format="ICO")
        print("Generated fallback tray icon")
        return icon_path
    except Exception as exc:
        print(f"Tray icon generation skipped: {exc}")
        return None

def build_exe():
    """Build Windows executable"""
    
    print("="*60)
    print("  BUILDING CRYPTODETECT AGENT .EXE")
    print("="*60)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print("PyInstaller found")
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    project_root = _project_root()

    # Build command
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",  # Single executable
        "--windowed",  # Hide console and run as tray app
        "--name=CryptoDetect-Agent-v9",  # Output name
        "--hidden-import=psutil",
        "--hidden-import=requests",
        "--hidden-import=hashlib",
        "--hidden-import=pystray",
        "--hidden-import=PIL",
        "--hidden-import=pythoncom",
        "--hidden-import=pywintypes",
        "--hidden-import=win32com",
        "--hidden-import=win32com.client",
        "--add-data=README.txt:.",  # Include readme
        "--hidden-import=auto_updater",
        f"--paths={project_root}",
        "--hidden-import=static_analysis",
        "--hidden-import=static_analysis.pe_analyzer",
        "--hidden-import=static_analysis.string_extractor",
        "--hidden-import=pefile",
        "agent_gui.py"
    ]
    
    # Add icon if exists
    icon_path = ensure_icon_file()
    if icon_path and icon_path.exists():
        command.append(f"--icon={icon_path}")
        print("Using custom icon")
    
    print(f"\nBuilding executable...")
    print(f"   Command: {' '.join(command)}\n")
    
    try:
        subprocess.check_call(command)
        print("\n" + "="*60)
        print("BUILD SUCCESSFUL")
        print("   Output: dist/CryptoDetect-Agent-v9.exe")
        print("="*60)
        return True
    except subprocess.CalledProcessError as e:
        print(f"\nBuild failed: {e}")
        return False

if __name__ == "__main__":
    build_exe()
