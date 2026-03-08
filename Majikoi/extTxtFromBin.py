import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox


def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def read_cstring(data, offset):
    end = data.find(b'\x00', offset)
    if end == -1:
        return b'', len(data)
    return data[offset:end], end + 1


def ex_txt(data):
    inst_count = read_u32(data, 0)
    pos = inst_count * 8 + 4
    count = read_u32(data, pos)
    pos += 4

    txts = []
    for _ in range(count):
        s, pos = read_cstring(data, pos)
        txts.append(s)

    return txts


def choose_folder(title):
    path = filedialog.askdirectory(title=title)
    if not path:
        raise SystemExit('Operação cancelada.')
    return path


def main():
    root = tk.Tk()
    root.withdraw()

    messagebox.showinfo(
        'Extração de texto',
        'Escolha a pasta que contém os arquivos .bin'
    )
    path_bin = choose_folder('Escolha a pasta dos .bin')

    messagebox.showinfo(
        'Extração de texto',
        'Escolha a pasta onde os .txt serão salvos.'
    )
    path_txt = choose_folder('Escolha a pasta de saída dos .txt')

    os.makedirs(path_txt, exist_ok=True)

    ok_count = 0
    err_count = 0

    for f in os.listdir(path_bin):
        if not f.lower().endswith('.bin'):
            continue

        in_path = os.path.join(path_bin, f)
        out_path = os.path.join(path_txt, os.path.splitext(f)[0] + '.txt')

        try:
            with open(in_path, 'rb') as fin:
                data = fin.read()

            lines = ex_txt(data)
            text = '\r\n'.join(x.decode('cp932', errors='replace') for x in lines)

            with open(out_path, 'w', encoding='utf-16') as fout:
                fout.write(text)

            print(f'OK: {f} -> {out_path} ({len(lines)} linhas)')
            ok_count += 1

        except Exception as e:
            print(f'ERRO: {f} -> {e}')
            err_count += 1

    messagebox.showinfo(
        'Concluído',
        f'Processo finalizado.\n\nOK: {ok_count}\nErros: {err_count}'
    )


if __name__ == '__main__':
    main()