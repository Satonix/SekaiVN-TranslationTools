import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox


def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def read_cstring(data, offset):
    end = data.find(b'\x00', offset)
    if end == -1:
        raise ValueError(f'String terminator not found at offset 0x{offset:X}')
    return data[offset:end], end + 1


def pack_txt_block(lines):
    return b''.join(line + b'\x00' for line in lines)


def pack_txt(data, lines):
    inst_count = read_u32(data, 0)
    pos = inst_count * 8 + 4

    count = read_u32(data, pos)
    pos1 = pos + 4

    cur = pos1
    for _ in range(count):
        _, cur = read_cstring(data, cur)
    pos2 = cur

    if len(lines) != count:
        raise ValueError(
            f'Quantidade de linhas diferente: txt={len(lines)} / bin={count}'
        )

    return data[:pos1] + pack_txt_block(lines) + data[pos2:]


def choose_folder(title):
    path = filedialog.askdirectory(title=title)
    if not path:
        raise SystemExit('Operação cancelada.')
    return path


def load_txt_lines(txt_path, expected_count=None):
    with open(txt_path, 'r', encoding='utf-16') as f:
        text = f.read()

    text = text.replace('\r\n', '\n').replace('\r', '\n')
    lines = text.split('\n')

    if lines and lines[-1] == '':
        lines.pop()

    if expected_count is not None and len(lines) == expected_count * 2 - 1:
        alternating_blank = True
        for i in range(1, len(lines), 2):
            if lines[i] != '':
                alternating_blank = False
                break
        if alternating_blank:
            lines = lines[::2]

    return [line.encode('gbk', errors='replace') for line in lines]


def main():
    root = tk.Tk()
    root.withdraw()

    messagebox.showinfo(
        'Reinserção de texto',
        'Escolha a pasta que contém os arquivos .bin originais.'
    )
    path_bin = choose_folder('Escolha a pasta dos .bin originais')

    messagebox.showinfo(
        'Reinserção de texto',
        'Escolha a pasta que contém a tradução em .txt'
    )
    path_txt = choose_folder('Escolha a pasta dos .txt')

    messagebox.showinfo(
        'Reinserção de texto',
        'Escolha a pasta de saída dos novos .bin'
    )
    path_out = choose_folder('Escolha a pasta de saída')

    os.makedirs(path_out, exist_ok=True)

    ok_count = 0
    skip_count = 0
    err_count = 0

    for f in os.listdir(path_bin):
        if not f.lower().endswith('.bin'):
            continue

        in_path = os.path.join(path_bin, f)
        txt_name = os.path.splitext(f)[0] + '.txt'
        txt_path = os.path.join(path_txt, txt_name)
        out_path = os.path.join(path_out, f)

        try:
            with open(in_path, 'rb') as fin:
                data = fin.read()

            if os.path.exists(txt_path):
                inst_count = read_u32(data, 0)
                pos = inst_count * 8 + 4
                expected_count = read_u32(data, pos)

                lines = load_txt_lines(txt_path, expected_count=expected_count)
                new_data = pack_txt(data, lines)

                with open(out_path, 'wb') as fout:
                    fout.write(new_data)

                print(f'[OK] {f} <- {txt_name}')
                ok_count += 1
            else:
                with open(out_path, 'wb') as fout:
                    fout.write(data)

                print(f'[SKIP] TXT não encontrado para: {f}')
                skip_count += 1

        except Exception as e:
            print(f'[ERRO] {f}: {e}')
            err_count += 1

    messagebox.showinfo(
        'Concluído',
        f'Processo finalizado.\n\n'
        f'OK: {ok_count}\n'
        f'SKIP: {skip_count}\n'
        f'ERROS: {err_count}'
    )


if __name__ == '__main__':
    main()