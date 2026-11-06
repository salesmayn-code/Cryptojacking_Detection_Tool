# Build script for creating Windows .exe from agent_gui.py
# Uses PyInstaller

import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def ensure_icon_file() -> Path | None:
    """Generate a high-DPI multi-resolution shield + waveform .ico file."""
    icon_path = Path(__file__).resolve().parent / "agent_icon.ico"
    try:
        from agent_gui import create_shield_icon

        base_img = create_shield_icon(size=256)
        if base_img is not None:
            base_img.save(
                icon_path,
                format="ICO",
                sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
            )
            print("Generated multi-resolution shield icon:", icon_path)
            return icon_path
    except Exception as exc:
        print(f"Tray icon generation skipped: {exc}")
    return icon_path if icon_path.exists() else None


def build_exe():
    """Build Windows executable"""

    print("=" * 60)
    print("  BUILDING CRYPTODETECT AGENT v9.0 .EXE")
    print("=" * 60)

    try:
        import PyInstaller  # noqa: F401
        print("PyInstaller found")
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    project_root = _project_root()
    agent_dir = Path(__file__).resolve().parent

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name=CryptoDetect-Agent-v9",
        "--hidden-import=psutil",
        "--hidden-import=requests",
        "--hidden-import=hashlib",
        "--hidden-import=pystray",
        "--hidden-import=PIL",
        "--hidden-import=PIL.ImageTk",
        "--hidden-import=pythoncom",
        "--hidden-import=pywintypes",
        "--hidden-import=win32com",
        "--hidden-import=win32com.client",
        "--hidden-import=auto_updater",
        f"--paths={project_root}",
        "--hidden-import=static_analysis",
        "--hidden-import=static_analysis.pe_analyzer",
        "--hidden-import=static_analysis.string_extractor",
        "--hidden-import=pefile",
        "--hidden-import=pynvml",
        "agent_gui.py",
    ]

    readme_path = agent_dir / "README.txt"
    if readme_path.exists():
        command.insert(-1, "--add-data=README.txt;.")

    icon_path = ensure_icon_file()
    if icon_path and icon_path.exists():
        command.append(f"--icon={icon_path}")
        print("Using custom icon")

    print("\nBuilding executable...")
    print(f"   Command: {' '.join(command)}\n")

    try:
        subprocess.check_call(command, cwd=str(agent_dir))
        print("\n" + "=" * 60)
        print("BUILD SUCCESSFUL")
        print("   Output: dist/CryptoDetect-Agent-v9.exe")
        print("=" * 60)
        return True
    except subprocess.CalledProcessError as e:
        print(f"\nBuild failed: {e}")
        return False


if __name__ == "__main__":
    build_exe()
