"""
Setup checker — installs only confirmed-working packages for Python 3.14.
Run: python check_and_install.py
"""
import subprocess, sys, importlib, os

PACKAGES = [
    ("fastapi",               "fastapi"),
    ("uvicorn",               "uvicorn[standard]"),
    ("multipart",             "python-multipart"),
    ("groq",                  "groq"),
    ("sentence_transformers", "sentence-transformers"),
    ("numpy",                 "numpy"),
    ("pydantic",              "pydantic"),
    ("dotenv",                "python-dotenv"),
    ("httpx",                 "httpx"),
    ("jinja2",                "jinja2"),
    ("aiofiles",              "aiofiles"),
]

out = []
all_ok = True

for imp, pkg in PACKAGES:
    try:
        importlib.import_module(imp)
        out.append(f"OK       {imp}")
    except ImportError:
        out.append(f"MISSING  {imp} — installing {pkg}…")
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            out.append(f"DONE     {pkg}")
        else:
            last = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "unknown"
            out.append(f"FAILED   {pkg}: {last[:150]}")
            all_ok = False

out.append("")
out.append("ALL OK — ready to run." if all_ok else "Some packages failed — check above.")

status_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install_status.txt")
with open(status_file, "w") as f:
    f.write("\n".join(out) + "\n")

print("\n".join(out))
