import os
import sys
import struct
import zlib
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from ctypes import WinDLL, c_int, c_uint, byref, create_string_buffer


# CONFIG
# Caso precise do .uca, só ajustar o UCADLL.
# Exemplo:
# UCADll = WinDLL(r'E:\tools\uca\ucadec.dll')
UCADll = None


def usage():
    print("""Usage: %s <DIR> [Compress]
Compress: 0 - No compress
          3 - zlib (default)
          4 - Reserved for UCI/UCA/DIF handling
Other value will be treated as 0
""" % sys.argv[0])
    sys.exit()


def char2bin(ch: int):
    data = []
    c = ch
    for _ in range(8):
        data.append(c & 1)
        c >>= 1
    data.reverse()
    return data


def create_tree_data(code_list, code, data, tree):
    if isinstance(tree, int):
        data += [0] + char2bin(tree)
        code_list.append((tree, code))
    else:
        data.append(1)
        create_tree_data(code_list, code + [0], data, tree[0])
        create_tree_data(code_list, code + [1], data, tree[1])


def bin2bytes(src_bits):
    out = bytearray()

    full_bytes = len(src_bits) >> 3
    for n in range(full_bytes):
        c = 0
        for i in range(8):
            c <<= 1
            c |= src_bits[n * 8 + i]
        out.append(c)

    rem = len(src_bits) & 7
    if rem:
        remain = src_bits[-rem:]
        c = 0
        for n in range(len(remain)):
            c |= remain[n] << (7 - n)
        out.append(c)

    return bytes(out)


def huffman_compress(src: bytes) -> bytes:
    if not src:
        return b""

    tree_weight = [0] * 256
    src_list = list(src)

    for c in src_list:
        tree_weight[c] += 1

    tree = []
    for n in range(256):
        if tree_weight[n]:
            tree.append((tree_weight[n], n))

    tree.sort(key=lambda x: x[0], reverse=True)

    if len(tree) == 1:
        only_char = tree[0][1]
        data = [0] + char2bin(only_char)
        for _ in src_list:
            data += [0]
        return bin2bytes(data)

    while len(tree) > 1:
        lchild = tree.pop()
        rchild = tree.pop()
        tree.append((lchild[0] + rchild[0], (lchild[1], rchild[1])))
        tree.sort(key=lambda x: x[0], reverse=True)

    tree = tree[0][1]
    data = []
    char_list = []
    create_tree_data(char_list, [], data, tree)
    char_list.sort(key=lambda x: x[0])

    char_map = {ch: bits for ch, bits in char_list}

    for c in src_list:
        data += char_map[c]

    return bin2bytes(data)


def encode_name_for_pac(name: str) -> bytes:
    data = name.encode("gbk").decode("gbk").encode("shift_jis")
    data = data.replace(b"_zeas_", b"\x81E")

    if len(data) > 64:
        raise ValueError("Nome muito longo para PAC (>64 bytes): %s" % name)

    return data + (b"\x00" * (64 - len(data)))


def md5_key(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def get_uca_uncmpr_size(filedata: bytes, cmpr_len: int) -> int:
    if UCADll is None:
        raise RuntimeError("Arquivo .uca encontrado, mas UCADll não foi carregada.")

    out_size = c_int(-1)
    src_buf = create_string_buffer(filedata, len(filedata))

    UCADll.UCADecode2(src_buf, cmpr_len, 0, byref(out_size), 44100)
    return c_uint(out_size.value).value


def pack_file_data(full_path: str, filename: str, default_compress: int):
    ext = os.path.splitext(filename)[1].lower()

    with open(full_path, "rb") as f:
        filedata = f.read()

    uncmpr = len(filedata)
    cmpr = len(filedata)
    out_name = filename
    out_data = filedata

    if ext == ".ifo":
        return None

    if ext == ".uci":
        bpp = int(filedata[3])
        w, h = struct.unpack("<II", filedata[4:12])
        w = (w + 3) & 0xFFFFFFFC
        uncmpr = w * h * bpp + 54
        out_name = os.path.splitext(filename)[0] + ".BMP"
        cmpr = len(filedata)
        out_data = filedata

    elif ext == ".dif":
        if filedata[:4] != b"ZDIF":
            return ("DIFF_LATER", filename, filedata)

        out_name = os.path.splitext(filename)[0] + ".BMP"
        bpp = int(filedata[31])
        w, h = struct.unpack("<II", filedata[32:40])
        w = (w + 3) & 0xFFFFFFFC
        uncmpr = w * h * bpp + 54
        cmpr = len(filedata)
        out_data = filedata

    elif ext == ".uca":
        out_name = os.path.splitext(filename)[0]
        uncmpr = get_uca_uncmpr_size(filedata, len(filedata))
        cmpr = len(filedata)
        out_data = filedata

    else:
        if default_compress == 3:
            out_data = zlib.compress(filedata, 9)
            cmpr = len(out_data)
        else:
            out_data = filedata
            cmpr = len(out_data)

    return (out_name, out_data, uncmpr, cmpr)


def pack_pac(src_dir: str, pak_path: str, compress: int = 3):
    if not os.path.isdir(src_dir):
        raise ValueError("Pasta inválida: %s" % src_dir)

    if compress not in [0, 3, 4]:
        compress = 0

    file_list = []
    for n in os.listdir(src_dir):
        full = os.path.join(src_dir, n)
        if os.path.isfile(full):
            if os.path.splitext(n)[1].lower() == ".ifo":
                continue
            file_list.append(n)

    print("Packing...")

    entries = []
    file_info_map = {}
    diff_later = []

    for n in file_list:
        full = os.path.join(src_dir, n)
        packed = pack_file_data(full, n, compress)

        if packed is None:
            continue

        if packed[0] == "DIFF_LATER":
            diff_later.append(n)
            continue

        out_name, out_data, uncmpr, cmpr = packed
        base_key = os.path.splitext(out_name)[0].upper()
        entries.append({
            "name": out_name,
            "data": out_data,
            "uncmpr": uncmpr,
            "cmpr": cmpr,
            "hash": md5_key(out_data),
            "base_key": base_key,
        })

    for n in diff_later:
        ifo_path = os.path.join(src_dir, os.path.splitext(n)[0] + ".ifo")
        dif_path = os.path.join(src_dir, n)

        if not os.path.exists(ifo_path):
            raise RuntimeError(".ifo não encontrado para %s" % n)

        with open(ifo_path, "r", encoding="utf-8", errors="replace") as f:
            base, diff, x, y, w, h = f.read().strip().split(",")

        with open(dif_path, "rb") as f:
            dif_raw = f.read()

        out_name = os.path.splitext(n)[0] + ".BMP"

        entries.append({
            "name": out_name,
            "data": ("DIFF_BUILD", base.upper(), int(x), int(y), dif_raw),
            "uncmpr": None,
            "cmpr": None,
            "hash": None,
            "base_key": os.path.splitext(out_name)[0].upper(),
        })

    with open(pak_path, "wb") as pak:
        pak.write(b"PAC\x00")
        pak.write(struct.pack("<II", 0, compress))

        file_offset = 12
        hash_map = {}
        info_records = []
        real_file_count = 0

        for ent in entries:
            if isinstance(ent["data"], tuple) and ent["data"][0] == "DIFF_BUILD":
                continue

            out_name = ent["name"]
            out_data = ent["data"]
            uncmpr = ent["uncmpr"]
            cmpr = ent["cmpr"]
            hkey = ent["hash"]

            file_info_map[ent["base_key"]] = (file_offset, uncmpr, cmpr)

            enc_name = encode_name_for_pac(out_name)

            if hkey in hash_map:
                info_records.append(enc_name + hash_map[hkey])
            else:
                info = struct.pack("<III", file_offset, uncmpr, cmpr)
                hash_map[hkey] = info
                info_records.append(enc_name + info)
                pak.write(out_data)
                file_offset += cmpr

            real_file_count += 1

        for ent in entries:
            if not (isinstance(ent["data"], tuple) and ent["data"][0] == "DIFF_BUILD"):
                continue

            _, base_name, x, y, dif_raw = ent["data"]

            if base_name not in file_info_map:
                raise RuntimeError("Base do DIF não encontrada: %s" % base_name)

            base_info = file_info_map[base_name]
            diff_data = b"ZDIF" + struct.pack("<IIII", base_info[0], base_info[2], x, y) + dif_raw

            out_name = ent["name"]
            enc_name = encode_name_for_pac(out_name)
            hkey = md5_key(diff_data)
            cmpr = len(diff_data)
            uncmpr = base_info[1]

            if hkey in hash_map:
                info_records.append(enc_name + hash_map[hkey])
            else:
                info = struct.pack("<III", file_offset, uncmpr, cmpr)
                hash_map[hkey] = info
                info_records.append(enc_name + info)
                pak.write(diff_data)
                file_offset += cmpr

            real_file_count += 1

        info_records.sort()

        raw_info = b"".join(info_records)
        huff_info = huffman_compress(raw_info)
        enc_info = bytes((c ^ 0xFF) for c in huff_info)

        pak.write(enc_info)
        pak.write(struct.pack("<I", len(enc_info)))

        pak.seek(4)
        pak.write(struct.pack("<II", real_file_count, compress))

    print("%d files.\nFinished." % real_file_count)


def choose_folder(title):
    path = filedialog.askdirectory(title=title)
    if not path:
        raise SystemExit("Operação cancelada.")
    return path


def choose_save_file(initial_dir, initial_name):
    path = filedialog.asksaveasfilename(
        title="Salvar arquivo PAC",
        initialdir=initial_dir,
        initialfile=initial_name,
        defaultextension=".pac",
        filetypes=[("PAC files", "*.pac"), ("All files", "*.*")]
    )
    if not path:
        raise SystemExit("Operação cancelada.")
    return path


def choose_compression():
    value = simpledialog.askinteger(
        "Compressão",
        "Escolha a compressão:\n0 = sem compressão\n3 = zlib\n4 = reservado\n\nRecomendado: 3",
        initialvalue=3,
        minvalue=0,
        maxvalue=4
    )
    if value is None:
        raise SystemExit("Operação cancelada.")
    if value not in [0, 3, 4]:
        value = 0
    return value


def main_gui():
    root = tk.Tk()
    root.withdraw()

    messagebox.showinfo(
        "Pack PAC",
        "Escolha a pasta com os arquivos que serão empacotados."
    )
    src_dir = choose_folder("Escolha a pasta de origem")

    default_name = os.path.basename(os.path.normpath(src_dir)) + ".pac"
    pak_path = choose_save_file(src_dir, default_name)
    compress = choose_compression()

    try:
        pack_pac(src_dir, pak_path, compress)
        messagebox.showinfo(
            "Concluído",
            "PAC gerado com sucesso:\n%s" % pak_path
        )
    except Exception as e:
        messagebox.showerror("Erro", str(e))
        raise


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        src = sys.argv[1]
        try:
            comp = int(sys.argv[2])
        except Exception:
            comp = 3
        pack_pac(src, src + ".pac", comp)
    else:
        main_gui()