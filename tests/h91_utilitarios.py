#!/usr/bin/env python3
"""H91 - utilitários de texto no estilo Unix (do fork SaguiOS-Extended, do
Alejandro Anuncibay, reescritos sobre o main atual).

Critério: cada programa, com entradas conhecidas num pendrive, dá a saída
esperada, lendo arquivos e a entrada (pipes do sagsh, como
"ls bin | sort -r | head -3"); os apelidos em português funcionam; erros
saem em português e com código de saída diferente de zero.
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qemu import Maquina, verificar, criar_pendrive, pendrive_qemu, RAIZ  # noqa: E402

PROGRAMAS = sorted([f[:-2] for f in os.listdir(os.path.join(RAIZ, "userland", "programas")) if f.endswith(".c")]
                   + ["sagui3d", "navegador", "cipo", "video", "saguicode", "saguicode-janela", "cc", "tocador", "mp3info"])

FRUTAS = "banana 3\nmaçã 10\nabacaxi 2\nBanana 7\nuva 10\nuva 10\nkiwi 1.5\n"
NUMEROS = "".join(f"{i}\n" for i in range(1, 26))
CAMPOS = "a:b:c\nd:e:f\nsem\n1:2:3:4\n"

ARQUIVOS = {
    "frutas.txt": FRUTAS,
    "numeros.txt": NUMEROS,
    "campos.txt": CAMPOS,
}


def limpo(texto):
    """Tira as sequências de cor e de cursor (ESC [ ... letra)."""
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", texto)


def rodar(m, comando):
    """Roda um comando e devolve só o que ele escreveu (sem o eco da linha
    digitada e sem o prompt seguinte)."""
    out = limpo(m.comando(comando))
    # O log do kernel ("[SAGUI] processo 7 ...") sai na mesma serial, entre
    # o eco da linha digitada e a saída do programa.
    out = re.sub(r"\[[A-Z][A-Z0-9_]*\] [^\n]*\n", "", out)
    out = out.split("\n", 1)[1] if "\n" in out else ""
    return out[:out.rfind("sagui:")] if "sagui:" in out else out


def codigo(m, programa):
    """O código de saída da última execução do programa (pelo log)."""
    achados = re.findall(rf"\({re.escape(programa)}\) terminou com codigo (-?\d+)", m.serial())
    return int(achados[-1]) if achados else None


def confere(m, comando, esperado, programa=None, cod=0):
    out = rodar(m, comando)
    ok = out == esperado
    if programa is not None:
        c = codigo(m, programa)
        ok = ok and c == cod
    verificar(ok, f"{comando!r} -> {esperado!r}" + ("" if ok else f" (veio {out!r})"))


def main():
    pen = criar_pendrive("h91-pen", rotulo="TEXTOS", arquivos=ARQUIVOS)
    extras = ["-device", "usb-ehci,id=ehci"] + pendrive_qemu(pen)
    with Maquina("h91", "ide", extras=extras) as m:
        m.esperar_serial("sagui:/$", 120)
        time.sleep(1)
        out = m.comando("ajuda")
        for nome in ("head/inicio", "tail/fim", "sort/ordenar", "uniq/unicos", "cut/cortar"):
            verificar(nome in out, f"o ajuda lista {nome}")
        m.comando("montar")
        m.comando("cd /usb")

        # ---- head
        confere(m, "head -3 numeros.txt", "1\n2\n3\n", "head")
        confere(m, "head -n 2 campos.txt frutas.txt",
                "==> campos.txt <==\na:b:c\nd:e:f\n\n==> frutas.txt <==\nbanana 3\nmaçã 10\n")
        confere(m, "head -c 5 numeros.txt", "1\n2\n3")
        confere(m, "cat numeros.txt | inicio -n 2", "1\n2\n")
        out = rodar(m, "ls /bin | sort -r | head -3")
        nomes = [l.split()[0] for l in out.splitlines() if l.strip()]
        verificar(nomes == sorted(PROGRAMAS, reverse=True)[:3], f"ls /bin | sort -r | head -3 = {nomes}")
        out = rodar(m, "head nada.txt")
        verificar("head: nada.txt: " in out and codigo(m, "head") == 1, "head de arquivo que não existe: erro e código 1")

        # ---- tail
        confere(m, "tail -3 numeros.txt", "23\n24\n25\n", "tail")
        confere(m, "tail -n +24 numeros.txt", "24\n25\n")
        confere(m, "tail -c 6 numeros.txt", "24\n25\n")
        confere(m, "cat frutas.txt | fim -n 1", "kiwi 1.5\n")

        # ---- sort
        confere(m, "sort frutas.txt", "Banana 7\nabacaxi 2\nbanana 3\nkiwi 1.5\nmaçã 10\nuva 10\nuva 10\n", "sort")
        confere(m, "sort -r numeros.txt | head -3", "9\n8\n7\n")
        confere(m, "sort -nr numeros.txt | head -3", "25\n24\n23\n")
        confere(m, "sort -k2n frutas.txt", "kiwi 1.5\nabacaxi 2\nbanana 3\nBanana 7\nmaçã 10\nuva 10\nuva 10\n")
        confere(m, "ordenar -t : -k 2 campos.txt", "sem\n1:2:3:4\na:b:c\nd:e:f\n")
        confere(m, "sort -fu frutas.txt", "abacaxi 2\nbanana 3\nBanana 7\nkiwi 1.5\nmaçã 10\nuva 10\n")
        rodar(m, "sort -c numeros.txt")
        verificar(codigo(m, "sort") == 1, "sort -c: fora de ordem devolve 1")

        # ---- uniq
        confere(m, "sort frutas.txt | uniq -c | tail -2", "      1 maçã 10\n      2 uva 10\n", "uniq")
        confere(m, "uniq -d frutas.txt", "uva 10\n")
        confere(m, "sort -f frutas.txt | unicos -i -u | head -2", "abacaxi 2\nbanana 3\n")

        # ---- cut
        confere(m, "cut -d : -f 2 campos.txt", "b\ne\nsem\n2\n", "cut")
        confere(m, "cut -d: -s -f1,3- campos.txt", "a:c\nd:f\n1:3:4\n")
        confere(m, "cortar -c 2-4 frutas.txt | head -2", "ana\naçã\n")
        rodar(m, "cut numeros.txt")
        verificar(codigo(m, "cut") == 1, "cut sem lista: uso e código 1")
        m.captura("H91-1-head-tail-sort-uniq-cut")
    return 0


if __name__ == "__main__":
    sys.exit(main())
