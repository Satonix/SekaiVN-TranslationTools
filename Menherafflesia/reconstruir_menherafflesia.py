from pathlib import Path

ORIGINAL_EXE = Path("menherafflesia.exe")
PATCHED_PACKAGE = Path("package_patched.nw")
OUTPUT_EXE = Path("menherafflesia_traduzido.exe")

ZIP_START_OFFSET = 46338048

stub = ORIGINAL_EXE.read_bytes()[:ZIP_START_OFFSET]
pkg = PATCHED_PACKAGE.read_bytes()

OUTPUT_EXE.write_bytes(stub + pkg)

print("OK:", OUTPUT_EXE)
print("Stub size:", len(stub))
print("Package size:", len(pkg))
print("Final size:", OUTPUT_EXE.stat().st_size)
