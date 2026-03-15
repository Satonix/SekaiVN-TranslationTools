import io
import os
import struct
import sys
import zipfile

EOCD_SIG = b"PK\x05\x06"

def find_embedded_zip_candidates(data: bytes):
    i = 0
    while True:
        i = data.find(EOCD_SIG, i)
        if i == -1:
            break

        if i + 22 > len(data):
            i += 1
            continue

        try:
            disk_no, cd_disk, disk_entries, total_entries, cd_size, cd_offset, comment_len = struct.unpack_from(
                "<HHHHIIH", data, i + 4
            )
        except struct.error:
            i += 1
            continue

        end = i + 22 + comment_len
        if end > len(data):
            i += 1
            continue

        zip_start = i - cd_offset - cd_size
        if zip_start < 0:
            i += 1
            continue

        blob = data[zip_start:end]

        try:
            with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
                names = zf.namelist()
                if "package.json" in names or "index.html" in names:
                    yield {
                        "zip_start": zip_start,
                        "zip_end": end,
                        "size": len(blob),
                        "names": names,
                        "blob": blob,
                    }
        except zipfile.BadZipFile:
            pass

        i += 1


def main():
    if len(sys.argv) < 2:
        print("Uso: python extract_package.py <exe> [saida.nw]")
        sys.exit(1)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) >= 3 else "package_from_exe.nw"

    with open(src, "rb") as f:
        data = f.read()

    candidates = list(find_embedded_zip_candidates(data))
    if not candidates:
        print("Nenhum pacote zip embutido com package.json/index.html foi encontrado.")
        sys.exit(2)

    best = max(candidates, key=lambda c: c["size"])

    with open(dst, "wb") as f:
        f.write(best["blob"])

    print(f"OK: extraído para {dst}")
    print(f"Offset inicial: {best['zip_start']}")
    print(f"Tamanho: {best['size']} bytes")

    with zipfile.ZipFile(dst, "r") as zf:
        print("Arquivos-chave encontrados:")
        for key in ("package.json", "index.html"):
            try:
                info = zf.getinfo(key)
                print(f"  - {key} ({info.file_size} bytes)")
            except KeyError:
                print(f"  - {key} (não encontrado)")


if __name__ == "__main__":
    main()
