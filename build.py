"""Vercel runs this before every deploy (see "buildCommand" in vercel.json).

1. Runs the tests. If any fail, the build stops and the site keeps its previous version.
2. Compiles the Tailwind CSS the pages use into public/app.css, so visitors download one small
   stylesheet instead of generating the CSS in their browser on every visit.
   public/app.css is ALSO kept in the repository, because Vercel serves public/ files as uploaded;
   upload the new app.css whenever index.html or admin.html changes.

The colour and font tokens live in public/index.html (the <style type="text/tailwindcss"> block),
so there is only one place to change them.
"""
import os
import re
import shutil
import stat
import subprocess
import sys
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TAILWIND_VERSION = "4.1.11"
WORK = ROOT / ".tailwind"
OUT = ROOT / "public" / "app.css"


def extract_theme(html: str) -> str:
    m = re.search(r'<style type="text/tailwindcss">(.*?)</style>', html, re.S)
    if not m:
        raise SystemExit("build: couldn't find the <style type=\"text/tailwindcss\"> theme block in public/index.html")
    return m.group(1).strip()


def run_tests() -> None:
    """Load the test file directly, so a missing or misplaced file fails loudly instead of "0 tests, all fine"."""
    print("build: running tests…", flush=True)
    path = ROOT / "tests" / "test_vdigdns.py"
    if not path.exists():
        raise SystemExit("build: tests/test_vdigdns.py is missing from the repository, so this version was NOT deployed. "
                         "Upload it into a folder named tests at the top of the repo.")
    sys.path.insert(0, str(path.parent))
    suite = unittest.defaultTestLoader.loadTestsFromName("test_vdigdns")
    result = unittest.TextTestRunner(verbosity=1, stream=sys.stdout).run(suite)
    if result.testsRun == 0:
        raise SystemExit("build: no tests ran, so this version was NOT deployed.")
    if not result.wasSuccessful():
        raise SystemExit("build: tests failed, so this version was NOT deployed. The previous version is still live.")
    print(f"build: {result.testsRun} tests passed", flush=True)


def standalone_tailwind() -> list[str]:
    """Tailwind's single-file binary from its GitHub release (no Node needed)."""
    binary = WORK / "tailwindcss"
    if not binary.exists():
        url = f"https://github.com/tailwindlabs/tailwindcss/releases/download/v{TAILWIND_VERSION}/tailwindcss-linux-x64"
        print(f"build: downloading {url}", flush=True)
        urllib.request.urlretrieve(url, binary)  # noqa: S310 - fixed, pinned release URL
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    return [str(binary)]


def compile_with(command: list[str], source: Path) -> bool:
    try:
        subprocess.run([*command, "-i", str(source), "-o", str(OUT), "--minify"], check=True, cwd=ROOT,
                       env={**os.environ, "NODE_ENV": "production"}, timeout=180)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"build: {command[0]} failed ({type(exc).__name__})", flush=True)
        return False


def build_css() -> None:
    html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    WORK.mkdir(exist_ok=True)
    source = WORK / "input.css"
    # source(none): scan only public/, so the output is the same on every machine
    source.write_text('@import "tailwindcss" source(none);\n@source "../public";\n\n' + extract_theme(html) + "\n", encoding="utf-8")
    print("build: compiling Tailwind CSS…", flush=True)
    # Tailwind's standalone binary bundles everything it needs (npx couldn't resolve the import on Vercel).
    if not compile_with(standalone_tailwind(), source):
        raise SystemExit("build: couldn't compile the CSS; not deploying.")
    css = OUT.read_text(encoding="utf-8")
    # A few classes the page can't work without: if they're missing, something went wrong.
    for needle in (".bg-navy", ".text-sky", ".hidden", "@container", ".lg\\:col-span-7"):
        if needle not in css:
            raise SystemExit(f"build: compiled CSS is missing {needle!r}; not deploying.")
    print(f"build: wrote public/app.css ({len(css) // 1024} KB)", flush=True)


if __name__ == "__main__":
    run_tests()
    build_css()
