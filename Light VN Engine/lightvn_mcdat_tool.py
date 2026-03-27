#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional

KEY = b"d6c5fKI3GgBWpZF3Tz6ia3kF0"
REV_KEY = KEY[::-1]


def xor_zero_mcdat(data: bytes) -> bytes:
    """Algorithm used by 0.mcdat and small mcdat payloads (<100 bytes)."""
    buf = bytearray(len(data) + 1)
    buf[: len(data)] = data
    idx_i = 0
    idx_j = len(data)
    for i in range(len(data)):
        stream = KEY[i % len(KEY)]
        buf[idx_i] ^= stream
        buf[idx_j] ^= stream
        idx_i += 1
        idx_j -= 1
    return bytes(buf[: len(data)])


def xor_mcdat(data: bytes) -> bytes:
    """Decrypt/encrypt a Light.vn .mcdat payload.

    The operation is symmetric: applying it twice returns the original bytes.
    """
    buf = bytearray(data)
    if len(buf) < 100:
        return xor_zero_mcdat(bytes(buf))

    for i in range(100):
        buf[i] ^= KEY[i % len(KEY)]

    start = len(buf) - 99
    for i in range(99):
        buf[start + i] ^= REV_KEY[i % len(REV_KEY)]

    return bytes(buf)

def detect_extension(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"BM"):
        return ".bmp"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ".gif"
    if data.startswith(b"OggS"):
        return ".ogg"
    if data.startswith(b"ID3"):
        return ".mp3"
    if data.startswith(b"PK\x03\x04"):
        return ".zip"
    if data.startswith(b"{\n") or data.startswith(b"{"):
        return ".json"
    if data.startswith(b"["):
        return ".json"
    if data[:3] == b"\xef\xbb\xbf":
        return ".txt"
    if len(data) >= 4 and (data[:2] in {b"\xff\xfe", b"\xfe\xff"}):
        return ".txt"
    sample = data[:512]
    printable = sum(1 for b in sample if b in b"\r\n\t" or 32 <= b <= 126)
    if sample and printable / len(sample) > 0.92:
        return ".txt"
    return ".bin"


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def load_zero_json_from_mcdat(zero_mcdat_path: Path) -> dict:
    dec = xor_zero_mcdat(zero_mcdat_path.read_bytes())
    obj = json.loads(dec.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("0.mcdat did not decode to a JSON object")
    return obj


def load_name_map_from_zero_mcdat(zero_mcdat_path: Path) -> Dict[str, str]:
    obj = load_zero_json_from_mcdat(zero_mcdat_path)
    result: Dict[str, str] = {}
    for rel_path, enc_path in obj.items():
        enc_name = Path(str(enc_path)).name
        result[enc_name] = str(rel_path)
    return result


def load_reverse_map_from_json(json_path: Path) -> Dict[str, str]:
    obj = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("0.mcdat.json must be a JSON object")
    return {str(rel).replace("\\", "/").lower(): Path(str(enc_path)).name for rel, enc_path in obj.items()}


def normalize_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix().lower()


def iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def is_script_path(rel_path: str) -> bool:
    rel = rel_path.replace("\\", "/").lower()
    if rel.startswith("scripts/"):
        return True
    if rel.startswith("plugins/lvn_message/"):
        return True
    return False



def cmd_inspect(paths: list[Path]) -> int:
    for path in paths:
        data = path.read_bytes()
        dec = xor_mcdat(data)
        ext = detect_extension(dec)
        print(f"{path}: size={len(data)} decrypted_ext_guess={ext} decrypted_size={len(dec)}")
        print(f"  decrypted_head={dec[:16].hex()}")
    return 0


def cmd_export_zero(zero_path: Path, output: Optional[Path]) -> int:
    obj = load_zero_json_from_mcdat(zero_path)
    out = output or zero_path.with_suffix(".json")
    write_bytes(out, json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"))
    print(f"exported {zero_path} -> {out} ({len(obj)} entries)")
    return 0


def cmd_list_scripts(zero_or_json: Path, output: Optional[Path]) -> int:
    if zero_or_json.suffix.lower() == ".json":
        obj = json.loads(zero_or_json.read_text(encoding="utf-8"))
    else:
        obj = load_zero_json_from_mcdat(zero_or_json)

    lines = []
    for rel, enc in obj.items():
        if is_script_path(str(rel)):
            lines.append(f"{enc} -> {rel}")

    lines.sort()
    text = "\n".join(lines) + ("\n" if lines else "")
    if output:
        write_bytes(output, text.encode("utf-8"))
        print(f"wrote {output} ({len(lines)} lines)")
    else:
        sys.stdout.write(text)
    return 0


def cmd_decrypt(path: Path, output: Optional[Path], guess_ext: bool) -> int:
    if path.is_dir():
        out_dir = output or (path.parent / f"{path.name}_dec")
        out_dir.mkdir(parents=True, exist_ok=True)
        for file in iter_files(path):
            rel = file.relative_to(path)
            dec = xor_mcdat(file.read_bytes())
            out = out_dir / rel
            if guess_ext and file.suffix.lower() == ".mcdat":
                out = out.with_suffix(detect_extension(dec))
            write_bytes(out, dec)
            print(f"decrypted {file} -> {out}")
        return 0

    dec = xor_mcdat(path.read_bytes())
    out = output or path.with_suffix(path.suffix + ".dec")
    if guess_ext:
        out = out.with_suffix(detect_extension(dec))
    write_bytes(out, dec)
    print(f"decrypted {path} -> {out}")
    return 0


def cmd_encrypt(path: Path, output: Optional[Path]) -> int:
    if path.is_dir():
        out_dir = output or (path.parent / f"{path.name}_enc")
        out_dir.mkdir(parents=True, exist_ok=True)
        for file in iter_files(path):
            rel = file.relative_to(path)
            enc = xor_mcdat(file.read_bytes())
            out = out_dir / rel
            write_bytes(out, enc)
            print(f"encrypted {file} -> {out}")
        return 0

    enc = xor_mcdat(path.read_bytes())
    out = output or (path.with_suffix(path.suffix + ".mcdat"))
    write_bytes(out, enc)
    print(f"encrypted {path} -> {out}")
    return 0


def cmd_unpack(indir: Path, output: Optional[Path], guess_ext: bool, scripts_only: bool) -> int:
    if not indir.is_dir():
        raise SystemExit(f"Not a directory: {indir}")

    out_dir = output or (indir / ("scripts_output" if scripts_only else "output"))
    out_dir.mkdir(parents=True, exist_ok=True)

    name_map: Dict[str, str] = {}
    zero = indir / "0.mcdat"
    if zero.exists():
        dec = xor_zero_mcdat(zero.read_bytes())
        write_bytes(out_dir / "0.mcdat.json", dec)
        try:
            name_map = load_name_map_from_zero_mcdat(zero)
            print(f"loaded name map from {zero}")
        except Exception as exc:
            print(f"warning: failed to parse 0.mcdat JSON ({exc})")
    else:
        print("warning: 0.mcdat not found; original filenames cannot be recovered")

    files = sorted(indir.glob("*.mcdat"))
    total = len(files)
    done = 0
    for idx, mc in enumerate(files, start=1):
        if mc.name == "0.mcdat":
            continue

        rel_name = name_map.get(mc.name, mc.name)
        if scripts_only and not is_script_path(rel_name):
            continue

        dec = xor_mcdat(mc.read_bytes())
        if mc.name in name_map:
            out = out_dir / name_map[mc.name]
        else:
            out = out_dir / mc.name
            if guess_ext:
                out = out.with_suffix(detect_extension(dec))
        if guess_ext and out.suffix == "":
            out = out.with_suffix(detect_extension(dec))
        write_bytes(out, dec)
        done += 1
        print(f"[{idx}/{total}] unpack {mc.name} -> {out}")
    print(f"done: {done} file(s)")
    return 0


def cmd_repack(indir: Path, output: Optional[Path]) -> int:
    if not indir.is_dir():
        raise SystemExit(f"Not a directory: {indir}")

    out_dir = output or (indir.parent / "Newmcdat")
    out_dir.mkdir(parents=True, exist_ok=True)

    reverse_map: Dict[str, str] = {}
    json_path = indir / "0.mcdat.json"
    if json_path.exists():
        reverse_map = load_reverse_map_from_json(json_path)
        enc_zero = xor_zero_mcdat(json_path.read_bytes())
        write_bytes(out_dir / "0.mcdat", enc_zero)
        print(f"wrote {out_dir / '0.mcdat'}")
    else:
        print("warning: 0.mcdat.json not found; files will keep current basenames")

    files = [p for p in iter_files(indir) if p.name.lower() != "0.mcdat.json"]
    total = len(files)
    for idx, path in enumerate(files, start=1):
        rel = normalize_rel(path, indir)
        out_name = reverse_map.get(rel, path.name)
        enc = xor_mcdat(path.read_bytes())
        write_bytes(out_dir / out_name, enc)
        print(f"[{idx}/{total}] repack {rel} -> {out_name}")
    return 0


def cmd_patch(indir: Path, output: Optional[Path]) -> int:
    if not indir.is_dir():
        raise SystemExit(f"Not a directory: {indir}")

    out_dir = output or (indir.parent / "Patch")
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = indir / "0.mcdat.json"
    if not json_path.exists():
        raise SystemExit("0.mcdat.json not found; patch mode needs the unpacked name list")

    reverse_map = load_reverse_map_from_json(json_path)
    patch_map: Dict[str, str] = {}
    count = 0
    for path in iter_files(indir):
        if path.name.lower() == "0.mcdat.json":
            continue
        rel = normalize_rel(path, indir)
        out_name = reverse_map.get(rel, f"Patch{count}.mcdat")
        enc = xor_mcdat(path.read_bytes())
        write_bytes(out_dir / out_name, enc)
        patch_map[rel] = f"Patch/{out_name}"
        print(f"patch {rel} -> {out_name}")
        count += 1

    patch_json = json.dumps(patch_map, ensure_ascii=False, indent=2).encode("utf-8")
    write_bytes(out_dir / "0.mcdat", xor_zero_mcdat(patch_json))
    print(f"wrote patch 0.mcdat with {count} file(s)")
    return 0



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Unpack/repack Light.vn .mcdat files (scripts/images/audio/resources)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("inspect", help="inspect file(s) and guess decrypted format")
    p.add_argument("paths", nargs="+", type=Path)

    p = sub.add_parser("export-zero", help="decode 0.mcdat to JSON")
    p.add_argument("zero_path", type=Path)
    p.add_argument("-o", "--output", type=Path)

    p = sub.add_parser("list-scripts", help="list likely script files from 0.mcdat or 0.mcdat.json")
    p.add_argument("zero_or_json", type=Path)
    p.add_argument("-o", "--output", type=Path)

    p = sub.add_parser("decrypt", help="decrypt a file or directory")
    p.add_argument("path", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--guess-ext", action="store_true", help="rename output based on decrypted magic")

    p = sub.add_parser("encrypt", help="encrypt a file or directory")
    p.add_argument("path", type=Path)
    p.add_argument("-o", "--output", type=Path)

    p = sub.add_parser("unpack", help="unpack a folder containing .mcdat files")
    p.add_argument("indir", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--guess-ext", action="store_true", help="append an extension when it can be detected")
    p.add_argument("--scripts-only", action="store_true", help="only unpack scripts/* and plugins/lvn_message/*")

    p = sub.add_parser("repack", help="repack an unpacked folder back into .mcdat files")
    p.add_argument("indir", type=Path)
    p.add_argument("-o", "--output", type=Path)

    p = sub.add_parser("patch", help="build a Patch folder from an unpacked folder")
    p.add_argument("indir", type=Path)
    p.add_argument("-o", "--output", type=Path)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "inspect":
        return cmd_inspect(args.paths)
    if args.cmd == "export-zero":
        return cmd_export_zero(args.zero_path, args.output)
    if args.cmd == "list-scripts":
        return cmd_list_scripts(args.zero_or_json, args.output)
    if args.cmd == "decrypt":
        return cmd_decrypt(args.path, args.output, args.guess_ext)
    if args.cmd == "encrypt":
        return cmd_encrypt(args.path, args.output)
    if args.cmd == "unpack":
        return cmd_unpack(args.indir, args.output, args.guess_ext, args.scripts_only)
    if args.cmd == "repack":
        return cmd_repack(args.indir, args.output)
    if args.cmd == "patch":
        return cmd_patch(args.indir, args.output)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
