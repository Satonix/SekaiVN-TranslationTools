from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def int32(x: int) -> int:
    return ((x + 2**31) % 2**32) - 2**31


def norm_path(p: str) -> str:
    return p.replace("\\", "/").strip().lower()


def gk(k0: int) -> bytes:
    b = bytearray(256)
    num = (k0 * 7391 + 42828) & 0xFFFFFFFF
    num2 = ((num << 17) ^ num) & 0xFFFFFFFF
    for i in range(256):
        num = (num - k0) & 0xFFFFFFFF
        num = (num + num2) & 0xFFFFFFFF
        num2 = (num + 56) & 0xFFFFFFFF
        num = (num * (num2 & 0xEF)) & 0xFFFFFFFF
        b[i] = num & 0xFF
        num = (num >> 1) & 0xFFFFFFFF
    return bytes(b)


def dd(data: bytes, key: int) -> bytes:
    table = gk(key)
    out = bytearray(data)
    for i in range(len(out)):
        x = out[i]
        x ^= table[i % 253]
        x = (x + 3) & 0xFF
        x = (x + table[i % 89]) & 0xFF
        x ^= 0x99
        out[i] = x
    return bytes(out)


def ee(data: bytes, key: int) -> bytes:
    table = gk(key)
    out = bytearray(data)
    for i in range(len(out)):
        x = out[i]
        x ^= 0x99
        x = (x - table[i % 89]) & 0xFF
        x = (x - 3) & 0xFF
        x ^= table[i % 253]
        out[i] = x
    return bytes(out)


@dataclass
class Entry:
    path: str
    offset: int
    size: int
    key: int
    path_offset: int


class KinkoiDat:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.entries: Dict[str, Entry] = {}
        self._parse()

    def _parse(self) -> None:
        with self.path.open("rb") as f:
            hdr = f.read(1024)
            vals = struct.unpack("<256i", hdr)

            numfiles = 0
            for i in range(4, 255):
                numfiles = int32(numfiles + vals[i])

            toc_enc = f.read(16 * numfiles)
            toc = dd(toc_enc, struct.unpack_from("<I", hdr, 212)[0])

            paths_len = struct.unpack_from("<i", toc, 12)[0] - (1024 + 16 * numfiles)
            paths_enc = f.read(paths_len)
            paths = dd(paths_enc, struct.unpack_from("<I", hdr, 92)[0])

        cur = 0
        for i in range(numfiles):
            off = 16 * i
            size = struct.unpack_from("<I", toc, off)[0]
            path_off = struct.unpack_from("<i", toc, off + 4)[0]
            key = struct.unpack_from("<I", toc, off + 8)[0]
            data_off = struct.unpack_from("<I", toc, off + 12)[0]

            j = path_off
            while j < len(paths) and paths[j] != 0:
                j += 1

            raw_name = paths[cur:j]
            name = norm_path(raw_name.decode("ascii", errors="replace"))

            if not name or "�" in name:
                j2 = path_off
                while j2 < len(paths) and paths[j2] != 0:
                    j2 += 1
                raw_name2 = paths[path_off:j2]
                name2 = norm_path(raw_name2.decode("ascii", errors="replace"))
                if name2:
                    name = name2
                    j = j2

            self.entries[name] = Entry(
                path=name,
                offset=data_off,
                size=size,
                key=key,
                path_offset=path_off,
            )
            cur = j + 1

    def list_paths(self) -> List[str]:
        return sorted(self.entries.keys())

    def read(self, inner_path: str) -> Optional[bytes]:
        inner = norm_path(inner_path)
        ent = self.entries.get(inner)
        if ent is None:
            return None
        with self.path.open("rb") as f:
            f.seek(ent.offset)
            enc = f.read(ent.size)
        return dd(enc, ent.key)


class KinkoiGame:
    def __init__(self):
        self.archives: List[KinkoiDat] = []

    def open(self, path: str | Path) -> bool:
        p = Path(path)
        if not p.exists():
            return False
        try:
            dat = KinkoiDat(p)
        except Exception:
            return False
        self.archives.insert(0, dat)
        return True

    def list_all_unique_paths(self) -> List[str]:
        seen = {}
        for arc in self.archives:
            for path in arc.list_paths():
                seen.setdefault(path, arc.path.name)
        return sorted(seen.keys())

    def get(self, inner_path: str) -> Optional[bytes]:
        inner = norm_path(inner_path)
        for arc in self.archives:
            data = arc.read(inner)
            if data is not None:
                return data
        return None

    def source_of(self, inner_path: str) -> Optional[str]:
        inner = norm_path(inner_path)
        for arc in self.archives:
            if inner in arc.entries:
                return str(arc.path)
        return None


def open_game(root: str | Path) -> KinkoiGame:
    root = Path(root)
    game = KinkoiGame()

    system_dat = root / "system.dat"
    if not game.open(system_dat):
        raise FileNotFoundError(
            f"Não foi possível abrir {system_dat}\n"
            f"Dica: se você já está dentro da pasta Kinkoi_Data, use:\n"
            f"    python KinkoiTool.py list-game ."
        )

    arcs_bytes = game.get("def/arcs.txt")
    if arcs_bytes is None:
        return game

    for line in arcs_bytes.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        game.open(root / line)

    return game


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def default_data_key(index: int) -> int:
    return (0x11111111 + index * 0x010203) & 0xFFFFFFFF


def build_dat_from_folder(input_dir: Path, out_file: Path,
                          toc_key: int = 0x12345678,
                          paths_key: int = 0x9ABCDEF0) -> int:
    if not input_dir.exists() or not input_dir.is_dir():
        raise FileNotFoundError(f"Pasta não encontrada: {input_dir}")

    files: List[Tuple[str, bytes]] = []
    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = norm_path(str(p.relative_to(input_dir)))
        files.append((rel, p.read_bytes()))

    if not files:
        raise ValueError("A pasta de entrada não contém arquivos.")

    paths_blob = b"".join(inner.encode("ascii") + b"\x00" for inner, _ in files)

    current_offset = 1024 + 16 * len(files) + len(paths_blob)
    toc_plain = bytearray()
    enc_datas: List[bytes] = []

    path_cur = 0
    for i, (inner, data) in enumerate(files):
        key = default_data_key(i)
        enc = ee(data, key)

        toc_plain += struct.pack(
            "<IIII",
            len(data),
            path_cur,
            key,
            current_offset
        )

        enc_datas.append(enc)
        current_offset += len(enc)
        path_cur += len(inner.encode("ascii")) + 1

    toc_enc = ee(bytes(toc_plain), toc_key)
    paths_enc = ee(paths_blob, paths_key)

    hdr = bytearray(1024)
    struct.pack_into("<I", hdr, 92, paths_key)
    struct.pack_into("<I", hdr, 212, toc_key)

    signed_paths_key = int32(paths_key)
    signed_toc_key = int32(toc_key)
    signed_count_word = int32(len(files) - signed_paths_key - signed_toc_key)

    struct.pack_into("<i", hdr, 16, signed_count_word)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(hdr + toc_enc + paths_enc + b"".join(enc_datas))
    return len(files)


HELP_TEXT = r"""
KinkoiTool - GUIA
========================

Esta ferramenta tem 2 modos de trabalho:

1) Mexendo com um único .dat
   Use quando quiser mexer em um arquivo .dat específico.
   Comandos:
     list-dat
     extract-file
     extract-dat

2) Usando a lógica do próprio jogo
   Use quando você quer seguir a lógica real do jogo:
   system.dat + arcs.txt + patch.dat + patch2.dat + outros.
   Comandos:
     list-game
     extract-game-file
     extract-game

COMANDOS
--------

list-dat
    Lista os arquivos que existem dentro de um .dat

    Exemplo:
    python KinkoiTool.py list-dat system.dat

extract-file
    Extrai um arquivo interno de um .dat

    Exemplo:
    python KinkoiTool.py extract-file system.dat def/arcs.txt -o arcs.txt

extract-dat
    Extrai todo o conteúdo de um .dat para uma pasta.

    Exemplo:
    python KinkoiTool.py extract-dat system.dat -o system_dat_extraido


list-game
    Lista os arquivos usando a lógica do jogo.
    Ou seja: system.dat + outros .dat listados em def/arcs.txt.

    Exemplo:
    python KinkoiTool.py list-game .

extract-game-file
    Extrai um arquivo usando a lógica do jogo inteiro.
    Isso é útil para quando quiser mexer em patch.dat ou patch2.dat.

    Exemplo:
    python KinkoiTool.py extract-game-file . scripts/replay.bs5 -o replay.bs5

extract-game
    Extrai todos os arquivos usando a lógica do jogo.

    Exemplo:
    python KinkoiTool.py extract-game . -o extracted_game


INJEÇÃO / PATCH
---------------

build-patch
    Cria um patch2.dat a partir da pasta que contém os arquivos modificados.

    Exemplo:
    python KinkoiTool.py build-patch PASTA_MOD -o patch2.dat

    Se dentro dessa:
        PASTA_MOD\scripts\replay.bs5

    O patch criado conterá:
        scripts/replay.bs5

    Depois é só copiar o patch2.dat para a pasta Kinkoi_Data.

AVISO:
- Não reempacote o system.dat
- Crie o patch2.dat contendo apenas os arquivos que foram modificados.

OBS 
-----

- Se você já estiver dentro da pasta Kinkoi_Data, use "." nos comandos de jogo
- "-o" significa arquivo/pasta de saída
"""


def print_help_menu() -> None:
    print(HELP_TEXT.strip())


def cmd_list_dat(args):
    arc = KinkoiDat(args.archive)
    paths = arc.list_paths()
    if args.out:
        Path(args.out).write_text("\n".join(paths) + "\n", encoding="utf-8")
        print(f"Lista salva em: {args.out}")
    else:
        for p in paths:
            print(p)


def cmd_extract_file(args):
    arc = KinkoiDat(args.archive)
    data = arc.read(args.inner_path)
    if data is None:
        raise SystemExit(f"Arquivo interno não encontrado: {args.inner_path}")
    out = Path(args.out) if args.out else Path(Path(args.inner_path).name)
    write_bytes(out, data)
    print(f"Extraído: {args.inner_path} -> {out}")


def cmd_extract_dat(args):
    arc = KinkoiDat(args.archive)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    count = 0
    for inner in arc.list_paths():
        data = arc.read(inner)
        if data is None:
            continue
        write_bytes(outdir / inner, data)
        count += 1
    print(f"Extraídos {count} arquivos para: {outdir}")


def cmd_list_game(args):
    game = open_game(args.root)
    paths = game.list_all_unique_paths()
    if args.out:
        Path(args.out).write_text("\n".join(paths) + "\n", encoding="utf-8")
        print(f"Lista salva em: {args.out}")
    else:
        for p in paths:
            print(p)


def cmd_extract_game_file(args):
    game = open_game(args.root)
    data = game.get(args.inner_path)
    if data is None:
        raise SystemExit(f"Arquivo interno não encontrado no jogo: {args.inner_path}")
    out = Path(args.out) if args.out else Path(Path(args.inner_path).name)
    write_bytes(out, data)
    print(f"Extraído: {args.inner_path} -> {out}")
    src = game.source_of(args.inner_path)
    if src:
        print(f"Arquivo de origem: {src}")


def cmd_extract_game(args):
    game = open_game(args.root)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    count = 0
    for inner in game.list_all_unique_paths():
        data = game.get(inner)
        if data is None:
            continue
        write_bytes(outdir / inner, data)
        count += 1
    print(f"Extraídos {count} arquivos únicos para: {outdir}")


def cmd_build_patch(args):
    input_dir = Path(args.input_dir)
    out_file = Path(args.out)
    count = build_dat_from_folder(input_dir, out_file)
    print(f"Patch criado com sucesso: {out_file}")
    print(f"Arquivos incluídos: {count}")
    print()
    print("Agora copie esse arquivo para a pasta Kinkoi_Data do jogo.")
    print("O nome recomendado é: patch2.dat")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("list-dat", help="Lista os arquivos dentro de UM .dat")
    s.add_argument("archive", help="Ex: system.dat")
    s.add_argument("-o", "--out", help="Salvar a lista em um txt")
    s.set_defaults(func=cmd_list_dat)

    s = sub.add_parser("extract-file", help="Extrai UM arquivo de UM .dat")
    s.add_argument("archive", help="Ex: system.dat")
    s.add_argument("inner_path", help="Ex: def/arcs.txt")
    s.add_argument("-o", "--out", help="Arquivo de saída")
    s.set_defaults(func=cmd_extract_file)

    s = sub.add_parser("extract-dat", help="Extrai TUDO de UM .dat")
    s.add_argument("archive", help="Ex: system.dat")
    s.add_argument("-o", "--out", required=True, help="Pasta de saída")
    s.set_defaults(func=cmd_extract_dat)

    s = sub.add_parser("list-game", help="Lista os arquivos usando a lógica do jogo inteiro")
    s.add_argument("root", help='Pasta Kinkoi_Data. Se já estiver nela, use "."')
    s.add_argument("-o", "--out", help="Salvar a lista em um txt")
    s.set_defaults(func=cmd_list_game)

    s = sub.add_parser("extract-game-file", help="Extrai UM arquivo usando a lógica do jogo inteiro")
    s.add_argument("root", help='Pasta Kinkoi_Data. Se já estiver nela, use "."')
    s.add_argument("inner_path", help="Ex: scripts/replay.bs5")
    s.add_argument("-o", "--out", help="Arquivo de saída")
    s.set_defaults(func=cmd_extract_game_file)

    s = sub.add_parser("extract-game", help="Extrai TUDO usando a lógica do jogo inteiro")
    s.add_argument("root", help='Pasta Kinkoi_Data. Se já estiver nela, use "."')
    s.add_argument("-o", "--out", required=True, help="Pasta de saída")
    s.set_defaults(func=cmd_extract_game)

    s = sub.add_parser("build-patch", help="Cria um patch2.dat a partir de uma pasta")
    s.add_argument("input_dir", help="Pasta com arquivos modificados")
    s.add_argument("-o", "--out", required=True, help="Arquivo .dat de saída")
    s.set_defaults(func=cmd_build_patch)

    s = sub.add_parser("help", help="Mostra a ajuda")
    s.set_defaults(func=lambda args: print_help_menu())

    return p


def main() -> int:
    if len(sys.argv) == 1:
        print_help_menu()
        return 0

    if sys.argv[1] in ("-h", "--help", "ajuda"):
        print_help_menu()
        return 0

    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        print_help_menu()
        return 0

    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
