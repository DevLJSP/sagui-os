#!/usr/bin/env python3
"""Testes da H91: ferramenta tools/sadrivers.py e formato .sadrivers 0.1.

Roda só no computador, com Python 3, sem QEMU e sem compilar o kernel:

    python3 tests/h91_sadrivers.py

Os objetos ELF usados na maior parte dos testes são montados byte a byte pelo
próprio teste, então eles rodam sem compilador.  Quando há GCC i386 e `ld`, um
teste adicional compila um módulo C real e confere o layout das estruturas da
H89.  Os cinco vetores de Ed25519 são os da seção 7.1 do RFC 8032.
"""
import contextlib
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "tools"))

import sadrivers as sadrv  # noqa: E402


# ------------------------------------------------------------------ ELF de teste

def _alinhar(n, a):
    return (n + a - 1) // a * a


def montar_elf(secoes, simbolos, relocacoes=(), rel_info=None,
               rel_entrada_tamanho=8, rel_link=None, sym_entrada_tamanho=16,
               rel_tabelas=None):
    """Monta um ELF32 i386 relocável mínimo, suficiente para a ferramenta.

    secoes: lista de dicionários com nome, tipo, bandeiras, dados, alinhamento
            e, para NOBITS, tamanho.
    simbolos: lista com nome, valor, tamanho, info, secao (None = indefinido).
    relocacoes: lista com alvo, deslocamento, simbolo e tipo.
    rel_info: opcional, mapa nome_da_secao_alvo -> sh_info, para testar
              tabelas de relocação malformadas.
    rel_entrada_tamanho, rel_link e sym_entrada_tamanho: opcionais, para testar
              esses campos das tabelas de relocação/símbolos sem mexer no resto
              do objeto.  rel_tabelas, quando informado, é uma lista de
              {nome, alvo, entradas} e permite mais de uma tabela de relocação
              para a mesma seção alvo.
    """
    # A seção 0 é nula.  As seções de conteúdo vêm primeiro; depois entram as
    # de relocação (uma por seção alvo), a tabela de símbolos e as de texto.
    nomes_alvo = {s["nome"]: i + 1 for i, s in enumerate(secoes)}
    if rel_tabelas is None:
        alvos_com_reloc = []
        for r in relocacoes:
            if r["alvo"] not in nomes_alvo:
                raise AssertionError("relocação para seção desconhecida")
            if r["alvo"] not in alvos_com_reloc:
                alvos_com_reloc.append(r["alvo"])
        tabelas = [
            {"nome": ".rel" + alvo, "alvo": alvo,
             "entradas": [r for r in relocacoes if r["alvo"] == alvo]}
            for alvo in alvos_com_reloc
        ]
    else:
        tabelas = list(rel_tabelas)
        for tabela in tabelas:
            if tabela["alvo"] not in nomes_alvo:
                raise AssertionError("relocação para seção desconhecida")

    nomes_secoes = [""] + [s["nome"] for s in secoes] + \
                   [t["nome"] for t in tabelas] + \
                   [".symtab", ".strtab", ".shstrtab"]
    symtab_idx = 1 + len(secoes) + len(tabelas)
    strtab_idx = symtab_idx + 1
    shstrtab_idx = symtab_idx + 2

    strtab = bytearray(b"\x00")
    nome_off = {}
    for simbolo in simbolos:
        nome_off[simbolo["nome"]] = len(strtab)
        strtab.extend(simbolo["nome"].encode("ascii") + b"\x00")
    indice_simbolo = {s["nome"]: i + 1 for i, s in enumerate(simbolos)}

    # Tabela de símbolos: entrada 0 nula.
    symtab = bytearray(16)
    for simbolo in simbolos:
        shndx = 0 if simbolo.get("secao") is None else nomes_alvo[simbolo["secao"]]
        symtab.extend(struct.pack("<IIIBBH", nome_off[simbolo["nome"]],
                                  simbolo.get("valor", 0),
                                  simbolo.get("tamanho", 0),
                                  simbolo.get("info", 0x12),
                                  simbolo.get("outro", 0),
                                  shndx))

    # Dados das relocações.
    dados_rel = []
    for tabela in tabelas:
        corpo = bytearray()
        for r in tabela["entradas"]:
            corpo.extend(struct.pack("<II", r["deslocamento"],
                                     (indice_simbolo[r["simbolo"]] << 8) | r["tipo"]))
        dados_rel.append(bytes(corpo))

    # Cabeçalho de seções: índices já atribuídos.
    header = bytearray(52)
    header[:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into("<16sHHIIIIIHHHHHH", header, 0, bytes(header[:16]),
                     1, 3, 1, 0, 0, 0, 0, 52, 0, 0, 40,
                     len(nomes_secoes), shstrtab_idx)

    # Primeiro o shstrtab, para saber os nomes.
    shstrtab = bytearray(b"\x00")
    offs_nomes = {}
    for nome in nomes_secoes[1:]:
        offs_nomes[nome] = len(shstrtab)
        shstrtab.extend(nome.encode("ascii") + b"\x00")

    # Conteúdo de cada seção, na ordem final.
    conteudos = {}
    for i, secao in enumerate(secoes, 1):
        conteudos[i] = secao.get("dados", b"")
    for i, dados in enumerate(dados_rel, 1 + len(secoes)):
        conteudos[i] = dados
    conteudos[symtab_idx] = bytes(symtab)
    conteudos[strtab_idx] = bytes(strtab)
    conteudos[shstrtab_idx] = bytes(shstrtab)

    # Layout dos dados no arquivo.
    pos = 52
    offsets = {}
    for i, secao in enumerate(secoes, 1):
        alinhamento = max(1, secao.get("alinhamento", 1))
        pos = _alinhar(pos, alinhamento)
        offsets[i] = pos
        if secao["tipo"] != sadrv.SHT_NOBITS:
            pos += len(conteudos[i])
    for i in range(1 + len(secoes), 1 + len(secoes) + len(tabelas)):
        pos = _alinhar(pos, 4)
        offsets[i] = pos
        pos += len(conteudos[i])
    for i in (symtab_idx, strtab_idx, shstrtab_idx):
        alinhamento = 4 if i == symtab_idx else 1
        pos = _alinhar(pos, alinhamento)
        offsets[i] = pos
        pos += len(conteudos[i])
    shoff = _alinhar(pos, 4)

    arquivo = bytearray(shoff + len(nomes_secoes) * 40)
    arquivo[:52] = header
    struct.pack_into("<I", arquivo, 32, shoff)
    for i in range(1, len(nomes_secoes)):
        if i in conteudos and conteudos[i]:
            arquivo[offsets[i]:offsets[i] + len(conteudos[i])] = conteudos[i]

    def cabecalho_secao(i):
        if i == 0:
            return b"\x00" * 40
        nome = nomes_secoes[i]
        if i <= len(secoes):
            secao = secoes[i - 1]
            tipo = secao["tipo"]
            bandeiras = secao["bandeiras"]
            tamanho = secao.get("tamanho", len(secao.get("dados", b""))) \
                if tipo == sadrv.SHT_NOBITS else len(secao.get("dados", b""))
            alinhamento = secao.get("alinhamento", 1)
            entrada_tamanho = 0
        elif i < 1 + len(secoes) + len(tabelas):
            tipo, bandeiras, tamanho, alinhamento, entrada_tamanho = \
                sadrv.SHT_REL, 0, len(conteudos[i]), 4, rel_entrada_tamanho
        elif i == symtab_idx:
            tipo, bandeiras, tamanho, alinhamento, entrada_tamanho = \
                sadrv.SHT_SYMTAB, 0, len(symtab), 4, sym_entrada_tamanho
        else:
            tipo, bandeiras, tamanho, alinhamento, entrada_tamanho = \
                sadrv.SHT_STRTAB, 0, len(conteudos[i]), 1, 0
        link = symtab_idx if tipo == sadrv.SHT_REL else \
            (strtab_idx if tipo == sadrv.SHT_SYMTAB else 0)
        if tipo == sadrv.SHT_REL and rel_link is not None:
            link = rel_link
        info = 0
        if tipo == sadrv.SHT_REL:
            alvo_nome = tabelas[i - 1 - len(secoes)]["alvo"]
            info = nomes_alvo[alvo_nome]
            if rel_info is not None and alvo_nome in rel_info:
                info = rel_info[alvo_nome]
        if tipo == sadrv.SHT_SYMTAB:
            info = 2  # primeiro símbolo global, na tabela usada aqui
        return struct.pack("<IIIIIIIIII", offs_nomes[nome], tipo, bandeiras,
                           0, offsets[i], tamanho, link, info, alinhamento,
                           entrada_tamanho)

    for i in range(len(nomes_secoes)):
        arquivo[shoff + i * 40:shoff + (i + 1) * 40] = cabecalho_secao(i)
    return bytes(arquivo)


def objeto_exemplo():
    """Objeto com código, dados, BSS, realocações internas e externas."""
    texto = bytearray(29)
    struct.pack_into("<i", texto, 0, 0)
    struct.pack_into("<i", texto, 4, -4)
    struct.pack_into("<i", texto, 8, 0)
    struct.pack_into("<i", texto, 12, -4)
    struct.pack_into("<i", texto, 16, 0)
    struct.pack_into("<i", texto, 20, -4)
    texto[24:27] = b"\x31\xc0\xc3"       # xor eax,eax; ret (entrada)
    texto[28] = 0xC3                     # ret (função interna)
    secoes = [
        {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
         "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": bytes(texto),
         "alinhamento": 16},
        {"nome": ".rodata", "tipo": sadrv.SHT_PROGBITS,
         "bandeiras": sadrv.SHF_ALLOC, "dados": b"ola\x00", "alinhamento": 16},
        {"nome": ".data", "tipo": sadrv.SHT_PROGBITS,
         "bandeiras": sadrv.SHF_ALLOC | 0x1,
         "dados": struct.pack("<I", 0x11223344), "alinhamento": 16},
        {"nome": ".bss", "tipo": sadrv.SHT_NOBITS,
         "bandeiras": sadrv.SHF_ALLOC | 0x1, "dados": b"",
         "tamanho": 16, "alinhamento": 16},
    ]
    simbolos = [
        {"nome": "funcao_interna", "valor": 28, "tamanho": 1,
         "info": 0x02, "secao": ".text"},
        {"nome": "sadrv_entrada", "valor": 24, "tamanho": 3,
         "info": 0x12, "secao": ".text"},
        {"nome": "dado", "valor": 0, "tamanho": 4, "info": 0x11, "secao": ".data"},
        {"nome": "bss_var", "valor": 0, "tamanho": 4, "info": 0x11, "secao": ".bss"},
        {"nome": "memcpy", "valor": 0, "tamanho": 0, "info": 0x12, "secao": None},
    ]
    relocacoes = [
        {"alvo": ".text", "deslocamento": 0, "simbolo": "dado", "tipo": 1},
        {"alvo": ".text", "deslocamento": 4, "simbolo": "funcao_interna", "tipo": 2},
        {"alvo": ".text", "deslocamento": 8, "simbolo": "memcpy", "tipo": 1},
        {"alvo": ".text", "deslocamento": 12, "simbolo": "memcpy", "tipo": 2},
        {"alvo": ".text", "deslocamento": 16, "simbolo": "bss_var", "tipo": 1},
        {"alvo": ".text", "deslocamento": 20, "simbolo": "bss_var", "tipo": 2},
    ]
    return montar_elf(secoes, simbolos, relocacoes)


TOML_EXEMPLO = """# manifesto de teste da H91
id = "saguios.diagnostico"
nome = "Diagnóstico de exemplo"
descricao = "Lê os primeiros registradores do dispositivo e anota no diário."
autor = "Eli Rigobeli"
versao = "0.1.0"
licenca = "GPL-3.0-or-later"
entrada = "sadrv_entrada"

[[dispositivo]]
tipo = "pci"
classe = 0x02
subclasse = 0x00

[[dispositivo]]
tipo = "pci"
fabricante = 0x8086
modelo = 0x100E
"""

SEMENTE_TESTE = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


def escrever_arquivos(base: Path):
    (base / "modulo.o").write_bytes(objeto_exemplo())
    (base / "modulo.toml").write_text(TOML_EXEMPLO, encoding="utf-8")
    (base / "chave.txt").write_text(
        "# semente so de teste\n" + SEMENTE_TESTE.hex() + "\n", encoding="ascii")
    publica = sadrv.ed25519_chave_publica(SEMENTE_TESTE)
    (base / "chave.pub").write_text(publica.hex() + "\n", encoding="ascii")
    return base / "modulo.o", base / "modulo.toml", base / "chave.txt", publica


def rodar_cli(argumentos):
    saida = io.StringIO()
    erro = io.StringIO()
    with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
        codigo = sadrv.main(argumentos)
    return codigo, saida.getvalue(), erro.getvalue()


def reassinar_pacote(pacote):
    """Recalcula resumo e assinatura depois de adulterar um pacote de teste."""
    ruim = bytearray(pacote)
    resumo = hashlib.sha256(ruim[:48] + ruim[80:-64]).digest()
    ruim[48:80] = resumo
    ruim[-64:] = sadrv.ed25519_assinar(SEMENTE_TESTE, resumo)
    return bytes(ruim)


def deslocamento_da_imagem(pacote):
    return sadrv._ler_campo_header(pacote)[3]


# ------------------------------------------------------------------ testes

class TesteIdECaminhos(unittest.TestCase):
    def test_ids_validos(self):
        for valor in ("saguios.e1000", "a.b", "x-1.y_2", "0.0", "a.b-c_d"):
            self.assertEqual(sadrv.validar_id(valor), valor)

    def test_ids_invalidos(self):
        invalidos = [
            "", ".", "..", "A.b", "a", "a b", "a/b", "a\\b", "/a.b",
            "../a.b", "a..b", ".a.b", "a.b.", "a.b-", "a.b_", "a.b\x00",
            "C:\\a.b", "a.b/" + "c" * 40, "é.b", "a.b\n",
        ]
        for valor in invalidos:
            with self.assertRaises(sadrv.ErroSadrivers, msg=repr(valor)):
                sadrv.validar_id(valor)

    def test_caminho_do_pacote_nao_sai_da_pasta(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            caminho = sadrv.caminho_pacote(base, "saguios.teste")
            self.assertEqual(caminho, (base / "saguios.teste.sadrivers").resolve())
            for valor in ("../fora", "a/b", "..", ".", "C:\\fora"):
                with self.assertRaises(sadrv.ErroSadrivers):
                    sadrv.caminho_pacote(base, valor)

    def test_caminho_do_pacote_nao_resolve_o_link_final(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            alvo = base / "outro.sadrivers"
            alvo.write_bytes(b"nao e este o pacote autorizado")
            link = base / "saguios.teste.sadrivers"
            try:
                os.symlink(alvo, link)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            caminho = sadrv.caminho_pacote(base, "saguios.teste")
            self.assertEqual(caminho, link)
            self.assertNotEqual(caminho, alvo)
            self.assertTrue(caminho.is_symlink())


class TesteListaAutorizada(unittest.TestCase):
    def test_lista_com_comentarios_duplicatas_e_invalidos(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ativo.txt").write_text(
                "# comentario\n"
                "saguios.diagnostico\n"
                "saguios.diagnostico # repetido\n"
                "../fora\n"
                "MAIUSCULO\n"
                "saguios.rede\n", encoding="ascii")
            ids = sadrv.ler_lista_autorizada(base / "ativo.txt")
            self.assertEqual(ids, ["saguios.diagnostico", "saguios.rede"])

    def test_listar_nao_abre_nao_listado(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ativo.txt").write_text("saguios.listado\n", encoding="ascii")
            (base / "saguios.listado.sadrivers").write_bytes(b"lixo")
            # Este arquivo é inválido de propósito.  Se a ferramenta o abrisse,
            # a listagem falharia ou tentaria validar o conteúdo.
            (base / "saguios.solto.sadrivers").write_bytes(b"nao abra")
            (base / "nome-invalido.txt").write_bytes(b"x")
            lista = sadrv.listar_pacotes(base)
            por_id = {p.id: p for p in lista}
            self.assertEqual(por_id["saguios.listado"].estado, "presente")
            self.assertEqual(por_id["saguios.solto"].estado, "nao_listado")
            self.assertIsNone(por_id["saguios.solto"].caminho)
            self.assertNotIn("nome-invalido", por_id)

    def test_listado_ausente(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ativo.txt").write_text("saguios.falta\n", encoding="ascii")
            lista = sadrv.listar_pacotes(base)
            self.assertEqual(len(lista), 1)
            self.assertEqual(lista[0].estado, "ausente")
            self.assertIsNone(lista[0].caminho)

    def test_erro_de_acesso_do_pacote_nao_vira_ausente(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            caminho = sadrv.caminho_pacote(base, "saguios.teste")
            caminho.write_bytes(b"x")
            (base / "ativo.txt").write_text("saguios.teste\n", encoding="ascii")
            lstat_original = sadrv.os.lstat

            def lstat_com_acesso_negado(alvo):
                if Path(alvo) == caminho:
                    raise PermissionError(13, "Acesso negado", str(alvo))
                return lstat_original(alvo)

            sadrv.os.lstat = lstat_com_acesso_negado
            try:
                with self.assertRaises(sadrv.ErroUso) as ctx:
                    sadrv.listar_pacotes(base)
            finally:
                sadrv.os.lstat = lstat_original
            self.assertIn("Acesso negado", str(ctx.exception))
            self.assertIn(str(caminho), str(ctx.exception))


class TesteToml(unittest.TestCase):
    def test_exemplo(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO)
        self.assertEqual(m.id, "saguios.diagnostico")
        self.assertEqual(m.versao, "0.1.0")
        self.assertEqual(len(m.dispositivos), 2)
        self.assertEqual(m.dispositivos[0].bandeiras, 0x01)
        self.assertEqual(m.dispositivos[1].bandeiras, 0x02)
        self.assertEqual(m.simbolo_entrada, "sadrv_entrada")

    def test_texto_latin1(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO)
        self.assertIn("Diagnóstico", m.nome)

    def test_campo_desconhecido(self):
        texto = TOML_EXEMPLO.replace("autor =", "cor = 1\nautor =")
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_duplicado(self):
        texto = TOML_EXEMPLO.replace("autor =", "autor = \"outro\"\nautor =")
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_inteiro_negativo_e_float(self):
        for trecho in ("classe = -1", "classe = 1.0"):
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_manifesto_toml(TOML_EXEMPLO.replace("classe = 0x02", trecho))

    def test_interface_sem_classe(self):
        texto = TOML_EXEMPLO.replace("classe = 0x02\nsubclasse = 0x00",
                                     "interface = 0x00")
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_modelo_sem_fabricante(self):
        texto = TOML_EXEMPLO.replace("fabricante = 0x8086\nmodelo = 0x100E",
                                     "modelo = 0x100E")
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_fabricante_curinga(self):
        texto = TOML_EXEMPLO.replace("fabricante = 0x8086", "fabricante = 0xFFFF")
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_tipo_usb_recusado(self):
        texto = TOML_EXEMPLO.replace('tipo = "pci"', 'tipo = "usb"', 1)
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_comentario_dentro_de_string(self):
        texto = TOML_EXEMPLO.replace('nome = "Diagnóstico de exemplo"',
                                     'nome = "Diagnóstico # de exemplo"')
        m = sadrv.ler_manifesto_toml(texto)
        self.assertIn("#", m.nome)


class TesteEd25519(unittest.TestCase):
    # Os cinco vetores positivos da seção 7.1 do RFC 8032: TEST 1, TEST 2,
    # TEST 3, TEST 1024 (mensagem de 1023 bytes) e TEST SHA(abc) (64 bytes).
    VETORES = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ("f5e5767cf153319517630f226876b86c"
         "8160cc583bc013744c6bf255f5cc0ee5",
         "278117fc144c72340f67d0f2316e8386"
         "ceffbf2b2428c9c51fef7c597f1d426e",
         "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
         "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
         "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
         "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
         "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
         "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
         "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
         "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
         "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
         "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
         "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
         "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
         "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
         "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
         "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
         "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
         "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
         "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
         "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
         "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
         "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
         "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
         "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
         "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
         "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
         "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
         "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
         "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
         "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
         "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
         "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
         "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
         "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
         "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"),
        ("833fe62409237b9d62ec77587520911e"
         "9a759cec1d19755b7da901b96dca3d42",
         "ec172b93ad5e563bf4932c70e1245034"
         "c35467ef2efd4d64ebf819683467e2bf",
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
         "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
         "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
    ]

    def test_vetores_do_rfc8032(self):
        self.assertEqual(len(self.VETORES), 5)
        for semente_hex, publica_hex, mensagem_hex, assinatura_hex in self.VETORES:
            semente = bytes.fromhex(semente_hex)
            mensagem = bytes.fromhex(mensagem_hex)
            assinatura = bytes.fromhex(assinatura_hex)
            publica = sadrv.ed25519_chave_publica(semente)
            self.assertEqual(publica.hex(), publica_hex)
            self.assertEqual(sadrv.ed25519_assinar(semente, mensagem).hex(),
                             assinatura_hex)
            self.assertTrue(sadrv.ed25519_verificar(publica, mensagem, assinatura))

    def test_assinatura_adulterada(self):
        semente = SEMENTE_TESTE
        publica = sadrv.ed25519_chave_publica(semente)
        mensagem = b"mensagem"
        assinatura = bytearray(sadrv.ed25519_assinar(semente, mensagem))
        assinatura[0] ^= 1
        self.assertFalse(sadrv.ed25519_verificar(publica, mensagem, bytes(assinatura)))

    def test_s_nao_canonico_recusado(self):
        publica = sadrv.ed25519_chave_publica(SEMENTE_TESTE)
        assinatura = bytearray(sadrv.ed25519_assinar(SEMENTE_TESTE, b"m"))
        assinatura[32:] = sadrv.ORDEM.to_bytes(32, "little")
        self.assertFalse(sadrv.ed25519_verificar(publica, b"m", bytes(assinatura)))

    def test_mensagem_adulterada(self):
        semente = SEMENTE_TESTE
        publica = sadrv.ed25519_chave_publica(semente)
        assinatura = sadrv.ed25519_assinar(semente, b"mensagem")
        self.assertFalse(sadrv.ed25519_verificar(publica, b"mensagem!", assinatura))

    def test_chave_publica_adulterada(self):
        semente = SEMENTE_TESTE
        publica = bytearray(sadrv.ed25519_chave_publica(semente))
        publica[0] ^= 1
        assinatura = sadrv.ed25519_assinar(semente, b"mensagem")
        self.assertFalse(sadrv.ed25519_verificar(bytes(publica), b"mensagem", assinatura))

    def test_id_da_chave(self):
        publica = sadrv.ed25519_chave_publica(SEMENTE_TESTE)
        esperado = hashlib.sha256(publica).digest()[:8]
        self.assertEqual(sadrv._id_da_chave(publica), esperado)

    def test_chave_identidade_nao_aceita_assinatura_falsa(self):
        identidade = sadrv._codificar(sadrv.PONTO_NEUTRO)
        # Para a chave identidade, [S]B = R + [k]A vale com R = O e S = 0
        # para qualquer mensagem.  A validação da chave precisa recusar antes
        # de olhar a equação.
        assinatura = identidade + b"\x00" * 32
        self.assertFalse(sadrv.ed25519_verificar(
            identidade, b"mensagem arbitraria", assinatura))
        with self.assertRaises(ValueError):
            sadrv._validar_ponto(sadrv._decodificar(identidade))

    def test_pontos_de_ordem_pequena_recusados(self):
        identidade = sadrv._codificar(sadrv.PONTO_NEUTRO)
        torcao = {}
        # Ordem 2: y = -1.
        torcao["ordem2"] = sadrv._codificar(sadrv._decodificar(
            (sadrv.PRIMO - 1).to_bytes(32, "little")))
        # Ordem 4: y = 0.
        torcao["ordem4"] = sadrv._codificar(sadrv._decodificar(b"\x00" * 32))
        # Ordem 8: [L]P de um ponto comum, calculado aqui e não copiado de
        # uma tabela externa.  y = 3 é o primeiro ponto que serve.
        p = sadrv._decodificar((3).to_bytes(32, "little"))
        t = sadrv._escalar(sadrv.ORDEM, p)
        self.assertEqual(sadrv._codificar(sadrv._escalar(8, t)), identidade)
        self.assertNotEqual(sadrv._codificar(sadrv._escalar(4, t)), identidade)
        torcao["ordem8"] = sadrv._codificar(t)
        publica_valida = sadrv._codificar(sadrv.PONTO_BASE)
        for nome, chave in torcao.items():
            with self.subTest(nome=nome):
                with self.assertRaises(ValueError):
                    sadrv._validar_ponto(sadrv._decodificar(chave))
                self.assertFalse(sadrv.ed25519_verificar(
                    chave, b"m", identidade + b"\x00" * 32))
                # O mesmo ponto pequeno no lugar de R, com uma chave A válida,
                # também precisa ser recusado antes da equação.
                assinatura = chave + (1).to_bytes(32, "little")
                self.assertFalse(sadrv.ed25519_verificar(
                    publica_valida, b"m", assinatura))

    def test_ponto_fora_do_subgrupo_principal_recusado(self):
        identidade = sadrv._codificar(sadrv.PONTO_NEUTRO)
        t = sadrv._escalar(
            sadrv.ORDEM,
            sadrv._decodificar((3).to_bytes(32, "little")))
        misto = sadrv._codificar(sadrv._somar(sadrv.PONTO_BASE, t))
        with self.assertRaises(ValueError):
            sadrv._validar_ponto(sadrv._decodificar(misto))
        self.assertFalse(sadrv.ed25519_verificar(
            misto, b"m", identidade + b"\x00" * 32))


class TesteManifesto(unittest.TestCase):
    def test_tlv_ida_e_volta(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        bruto = sadrv.montar_manifesto(m)
        lido = sadrv.ler_manifesto(bruto)
        self.assertEqual(lido.id, m.id)
        self.assertEqual(lido.entrada, 0)
        self.assertEqual(lido.id_chave, b"12345678")
        self.assertEqual(len(lido.dispositivos), 2)

    def test_tags_em_ordem(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        bruto = sadrv.montar_manifesto(m)
        tags = []
        i = 0
        while i < len(bruto):
            tag, n = struct.unpack_from("<HH", bruto, i)
            tags.append(tag)
            i += 4 + n
        self.assertEqual(tags, [1, 2, 3, 4, 5, 6, 7, 8, 9, 9])

    def test_tag_repetida_recusada(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        bruto = bytearray(sadrv.montar_manifesto(m))
        # Copia a entrada ID (tag 1) para o fim: fora de ordem/repetida.
        tag, n = struct.unpack_from("<HH", bruto, 0)
        bruto.extend(bruto[:4 + n])
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.ler_manifesto(bytes(bruto))
        self.assertEqual(ctx.exception.codigo, "MANIFESTO")

    def test_tag_obrigatoria_ausente(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        bruto = sadrv.montar_manifesto(m)
        # Remove a tag NOME (2) e as seguintes ficam fora de ordem.
        i = 0
        while i < len(bruto):
            tag, n = struct.unpack_from("<HH", bruto, i)
            if tag == 2:
                bruto = bruto[:i] + bruto[i + 4 + n:]
                break
            i += 4 + n
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.ler_manifesto(bruto)
        self.assertEqual(ctx.exception.codigo, "MANIFESTO")

    def test_tag_desconhecida(self):
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.ler_manifesto(struct.pack("<HH", 11, 0))

    def test_tlv_truncado(self):
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.ler_manifesto(b"\x01\x00\x05\x00abc")

    def test_versao_limites(self):
        for valor in ("0.0.0", "9999.9999.9999", "1.2.3"):
            self.assertEqual(sadrv._validar_versao(valor), valor)
        for valor in ("1.2", "1.2.3.4", "01.2.3", "10000.1.1", "a.b.c", "1.2.3 "):
            with self.assertRaises(sadrv.ErroSadrivers):
                sadrv._validar_versao(valor)

    def test_limite_de_texto(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.descricao = "x" * 257
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_manifesto(m)

    def test_limite_de_dispositivos(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.dispositivos = m.dispositivos * 9
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_manifesto(m)

    def test_dependencia_de_si_mesmo(self):
        texto = TOML_EXEMPLO + '\n[[dependencia]]\nid = "saguios.diagnostico"\n'
        with self.assertRaises(sadrv.ErroUso):
            sadrv.ler_manifesto_toml(texto)

    def test_dependencia_com_id_invalido(self):
        texto = TOML_EXEMPLO + '\n[[dependencia]]\nid = "../fora"\n'
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.ler_manifesto_toml(texto)


class TesteElf(unittest.TestCase):
    def test_layout_e_relocacoes(self):
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(objeto_exemplo())
            obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            self.assertEqual(len(obj.imagem), 52)
            self.assertEqual(obj.tamanho_bss, 16)
            self.assertEqual(obj.entrada, 24)
            # .text em 0, .rodata em 32, .data em 48.
            self.assertEqual(obj.imagem[32:36], b"ola\x00")
            self.assertEqual(struct.unpack_from("<I", obj.imagem, 48)[0], 0x11223344)
            # Absoluta interna para .data: 48.
            self.assertEqual(struct.unpack_from("<I", obj.imagem, 0)[0], 48)
            # PC32 interna para funcao_interna (28): 28 - 4 - 4 = 20.
            self.assertEqual(struct.unpack_from("<i", obj.imagem, 4)[0], 20)
            # Absoluta interna para BSS: base 64.
            self.assertEqual(struct.unpack_from("<I", obj.imagem, 16)[0], 64)
            # PC32 interna para BSS: 64 - 4 - 20 = 40.
            self.assertEqual(struct.unpack_from("<i", obj.imagem, 20)[0], 40)
            # Externas ficam com o adendo e viram realocações 1 e 2.
            self.assertEqual(struct.unpack_from("<i", obj.imagem, 8)[0], 0)
            self.assertEqual(struct.unpack_from("<i", obj.imagem, 12)[0], -4)
            tipos = [(r.deslocamento, r.tipo, r.alvo) for r in obj.realocacoes]
            self.assertEqual(tipos, [(0, 0, 48), (8, 1, 1), (12, 2, 1), (16, 0, 64)])

    def test_realocacao_desalinhada_aceita(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4,
                   "dados": b"\x00" * 8, "alinhamento": 16}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [{"alvo": ".text", "deslocamento": 2,
                       "simbolo": "sadrv_entrada", "tipo": 1}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos, relocacoes))
            obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            self.assertEqual([r.deslocamento for r in obj.realocacoes], [2])
            # O pacote também aceita o deslocamento não múltiplo de 4.
            m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
            m.entrada = 0
            pacote = sadrv.montar_pacote(
                sadrv.montar_manifesto(m), obj.imagem, obj.tamanho_bss,
                obj.realocacoes, SEMENTE_TESTE)
            lido = sadrv.analisar_pacote(pacote)
            self.assertEqual([r.deslocamento for r in lido.realocacoes], [2])

    def test_bss_alinhado_em_relacao_a_base(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
                   "alinhamento": 16}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        esperados = []
        for nome, alinhamento in (("a", 32), ("b", 64), ("c", 256),
                                  ("d", 4096)):
            nome_secao = ".bss." + nome
            secoes.append({
                "nome": nome_secao, "tipo": sadrv.SHT_NOBITS,
                "bandeiras": sadrv.SHF_ALLOC | 0x1, "dados": b"",
                "tamanho": 1, "alinhamento": alinhamento,
            })
            simbolos.append({"nome": "bss_" + nome, "valor": 0,
                             "tamanho": 1, "info": 0x11,
                             "secao": nome_secao})
            esperados.append((nome_secao, alinhamento, "bss_" + nome))
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            # base_bss = 16.  Os deslocamentos relativos precisam deixar
            # base_bss + deslocamento alinhado; o vão entra em tamanho_bss.
            self.assertEqual(obj.tamanho_bss, 4081)
            enderecos = {}
            for simbolo in obj.simbolos:
                if simbolo.nome.startswith("bss_"):
                    enderecos[simbolo.nome] = simbolo.endereco
            for nome_secao, alinhamento, nome_simbolo in esperados:
                self.assertEqual(enderecos[nome_simbolo] % alinhamento, 0,
                                 (nome_secao, alinhamento))
            self.assertEqual(
                [enderecos[n] for _s, _a, n in esperados],
                [16 + 16, 16 + 48, 16 + 240, 16 + 4080])

    def test_entrada_no_fim_da_secao_recusada(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\x90\xc3",
             "alinhamento": 16},
            {"nome": ".rodata", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC, "dados": b"dado",
             "alinhamento": 16},
        ]
        # valor == tamanho da .text: o início está no primeiro byte da
        # .rodata, não dentro da função.
        simbolos = [{"nome": "sadrv_entrada", "valor": 2, "tamanho": 0,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_rel_com_sh_info_invalido_recusada(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4,
                   "dados": b"\x00" * 8, "alinhamento": 16}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [{"alvo": ".text", "deslocamento": 0,
                       "simbolo": "sadrv_entrada", "tipo": 1}]
        for info in (0, 1 + len(secoes) + 5):
            with self.subTest(info=info), tempfile.TemporaryDirectory() as tmp:
                caminho = Path(tmp) / "x.o"
                caminho.write_bytes(montar_elf(
                    secoes, simbolos, relocacoes, {".text": info}))
                with self.assertRaises(sadrv.ErroUso):
                    sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_rel_malformada_de_secao_fora_da_imagem_recusada(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".debug_info", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": 0, "dados": b"\x00" * 4, "alinhamento": 4},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [{"alvo": ".debug_info", "deslocamento": 0,
                       "simbolo": "sadrv_entrada", "tipo": 1}]
        casos = {
            "entrada": {"rel_entrada_tamanho": 4},
            "link": {"rel_link": 0},
        }
        for nome, extra in casos.items():
            with self.subTest(caso=nome), tempfile.TemporaryDirectory() as tmp:
                caminho = Path(tmp) / "x.o"
                caminho.write_bytes(montar_elf(
                    secoes, simbolos, relocacoes, **extra))
                with self.assertRaises(sadrv.ErroUso):
                    sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_nota_alocada_do_gcc_e_ignorada(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".note.gnu.property", "tipo": sadrv.SHT_NOTE,
             "bandeiras": sadrv.SHF_ALLOC, "dados": b"\x04\x00\x00\x00nota",
             "alinhamento": 4},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            self.assertNotIn(b"nota", obj.imagem)

    def test_nota_executavel_recusada(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".note.perigo", "tipo": sadrv.SHT_NOTE,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\x00\x00\x00\x00",
             "alinhamento": 4},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_rel_de_secao_fora_da_imagem_valida_e_ignorada(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".debug_info", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": 0, "dados": b"\x00\x00\x00\x00",
             "alinhamento": 4},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [{"alvo": ".debug_info", "deslocamento": 0,
                       "simbolo": "sadrv_entrada", "tipo": 1}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos, relocacoes))
            obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            self.assertEqual(obj.realocacoes, [])

    def test_simbolo_indefinido_desconhecido(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\x90",
                   "alinhamento": 16}]
        simbolos = [{"nome": "printf", "valor": 0, "tamanho": 0,
                     "info": 0x12, "secao": None},
                    {"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_secao_alocada_desconhecida(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".init_array", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x1, "dados": b"\x00\x00\x00\x00",
             "alinhamento": 4},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_tipo_de_relocacao_desconhecido(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4,
                   "dados": b"\x00\x00\x00\x00", "alinhamento": 16}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 4,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [{"alvo": ".text", "deslocamento": 0,
                       "simbolo": "sadrv_entrada", "tipo": 3}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos, relocacoes))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_entrada_precisa_estar_em_texto_executavel(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".rodata", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC, "dados": b"\xc3",
             "alinhamento": 16},
        ]
        simbolos = [{"nome": "entrada_ruim", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".rodata"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "entrada_ruim")

    def test_alinhamento_absurdo_recusado(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
                   "alinhamento": 3}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_duas_secoes_com_relocacao_no_mesmo_deslocamento(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\x00\x00\x00\x00",
             "alinhamento": 16},
            {"nome": ".data", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x1, "dados": b"\x00\x00\x00\x00",
             "alinhamento": 16},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [
            {"alvo": ".text", "deslocamento": 0,
             "simbolo": "sadrv_entrada", "tipo": 1},
            {"alvo": ".data", "deslocamento": 0,
             "simbolo": "sadrv_entrada", "tipo": 1},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos, relocacoes))
            obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            # Os dois deslocamentos são 0, mas em seções diferentes: os
            # deslocamentos na imagem são 0 e 16.
            self.assertEqual([r.deslocamento for r in obj.realocacoes], [0, 16])

    def test_ponteiro_interno_efetivo_do_elf(self):
        # A palavra gravada na imagem é S + A.  O alvo da tabela (S = 0 aqui)
        # não basta: o valor efetivo precisa cair na área carregada, que mede
        # 16 bytes porque a imagem de quatro bytes é alinhada.
        for valor, aceito in ((0, True), (15, True), (16, False),
                              (0xFFFFFFFF, False)):
            with self.subTest(valor=valor), tempfile.TemporaryDirectory() as tmp:
                secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                           "bandeiras": sadrv.SHF_ALLOC | 0x4,
                           "dados": struct.pack("<I", valor),
                           "alinhamento": 16}]
                simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 4,
                             "info": 0x12, "secao": ".text"}]
                relocacoes = [{"alvo": ".text", "deslocamento": 0,
                               "simbolo": "sadrv_entrada", "tipo": 1}]
                caminho = Path(tmp) / "x.o"
                caminho.write_bytes(montar_elf(secoes, simbolos, relocacoes))
                if aceito:
                    obj = sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
                    self.assertEqual(struct.unpack_from("<I", obj.imagem, 0)[0],
                                     valor)
                else:
                    with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                        sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
                    self.assertEqual(ctx.exception.codigo, "REALOCACAO")

    def test_realocacoes_sobrepostas_no_elf(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4,
                   "dados": b"\x00" * 8, "alinhamento": 16}]
        simbolos = [
            {"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
             "info": 0x12, "secao": ".text"},
            {"nome": "memcpy", "valor": 0, "tamanho": 0,
             "info": 0x12, "secao": None},
        ]
        relocacoes = [
            {"alvo": ".text", "deslocamento": 0,
             "simbolo": "memcpy", "tipo": 1},
            {"alvo": ".text", "deslocamento": 2,
             "simbolo": "memcpy", "tipo": 1},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos, relocacoes))
            with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            self.assertEqual(ctx.exception.codigo, "REALOCACAO")

    def test_relocacoes_sobrepostas_em_tabelas_rel_diferentes(self):
        # Duas tabelas de relocação diferentes apontam para a mesma seção
        # alvo; depois da concatenação, os campos em 0 e 2 ocupam bytes que se
        # cruzam.  A checagem é global, não por tabela.
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4,
                   "dados": b"\x00" * 8, "alinhamento": 16}]
        simbolos = [
            {"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
             "info": 0x12, "secao": ".text"},
            {"nome": "memcpy", "valor": 0, "tamanho": 0,
             "info": 0x12, "secao": None},
        ]
        tabelas = [
            {"nome": ".rel.text.a", "alvo": ".text",
             "entradas": [{"alvo": ".text", "deslocamento": 0,
                           "simbolo": "memcpy", "tipo": 1}]},
            {"nome": ".rel.text.b", "alvo": ".text",
             "entradas": [{"alvo": ".text", "deslocamento": 2,
                           "simbolo": "memcpy", "tipo": 1}]},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(
                secoes, simbolos, rel_tabelas=tabelas))
            with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")
            self.assertEqual(ctx.exception.codigo, "REALOCACAO")

    def test_symtab_com_entrada_zero_recusada(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
                   "alinhamento": 16}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(
                secoes, simbolos, sym_entrada_tamanho=0))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_rel_com_entrada_zero_recusada(self):
        secoes = [{"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
                   "bandeiras": sadrv.SHF_ALLOC | 0x4,
                   "dados": b"\x00\x00\x00\x00", "alinhamento": 16}]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        relocacoes = [{"alvo": ".text", "deslocamento": 0,
                       "simbolo": "sadrv_entrada", "tipo": 1}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(
                secoes, simbolos, relocacoes, rel_entrada_tamanho=0))
            with self.assertRaises(sadrv.ErroUso):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")

    def test_bss_maior_que_o_limite(self):
        secoes = [
            {"nome": ".text", "tipo": sadrv.SHT_PROGBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x4, "dados": b"\xc3",
             "alinhamento": 16},
            {"nome": ".bss", "tipo": sadrv.SHT_NOBITS,
             "bandeiras": sadrv.SHF_ALLOC | 0x1, "dados": b"",
             "tamanho": sadrv.MAX_BSS + 1, "alinhamento": 16},
        ]
        simbolos = [{"nome": "sadrv_entrada", "valor": 0, "tamanho": 1,
                     "info": 0x12, "secao": ".text"}]
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "x.o"
            caminho.write_bytes(montar_elf(secoes, simbolos))
            with self.assertRaises(sadrv.ErroSadrivers):
                sadrv.ler_objeto_elf(caminho, "sadrv_entrada")


class TestePacote(unittest.TestCase):
    def _pacote(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            obj_path, toml_path, chave_path, publica = escrever_arquivos(base)
            m = sadrv.ler_manifesto_toml(toml_path.read_text(encoding="utf-8"))
            obj = sadrv.ler_objeto_elf(obj_path, m.simbolo_entrada)
            m = sadrv.Manifesto(id=m.id, nome=m.nome, descricao=m.descricao,
                                autor=m.autor, versao=m.versao, licenca=m.licenca,
                                id_chave=b"", entrada=obj.entrada,
                                dispositivos=m.dispositivos,
                                dependencias=m.dependencias,
                                simbolo_entrada=m.simbolo_entrada)
            pacote, m = sadrv.empacotar(m, obj.imagem, obj.tamanho_bss,
                                        obj.realocacoes, SEMENTE_TESTE)
            return pacote, m, publica

    def test_pacote_valido_e_campos(self):
        pacote, m, publica = self._pacote()
        p = sadrv.analisar_pacote(pacote, publica)
        self.assertEqual(p.manifesto.id, "saguios.diagnostico")
        self.assertEqual(p.manifesto.entrada, 24)
        self.assertEqual(p.tamanho_bss, 16)
        self.assertEqual(len(p.imagem), 52)
        self.assertEqual(len(p.realocacoes), 4)
        self.assertEqual(p.tamanho_total % 16, 0)
        self.assertGreaterEqual(p.tamanho_total, 176)
        self.assertEqual(p.resumo, hashlib.sha256(
            pacote[:48] + pacote[80:p.tamanho_total - 64]).digest())
        self.assertEqual(p.manifesto.id_chave,
                         hashlib.sha256(publica).digest()[:8])

    def test_pacote_sem_chave_aceita_estrutura(self):
        pacote, _m, _publica = self._pacote()
        p = sadrv.analisar_pacote(pacote)
        self.assertEqual(p.manifesto.id, "saguios.diagnostico")

    def test_magic_errado(self):
        pacote, _m, publica = self._pacote()
        ruim = bytearray(pacote)
        ruim[0] ^= 1
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(bytes(ruim), publica)
        self.assertEqual(ctx.exception.codigo, "ASSINATURA")

    def test_tamanho_menor(self):
        pacote, _m, publica = self._pacote()
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(pacote[:-16], publica)
        self.assertEqual(ctx.exception.codigo, "TAMANHO")

    def test_layout_com_preenchimento_sujo(self):
        pacote, _m, publica = self._pacote()
        p = sadrv.analisar_pacote(pacote)
        # O primeiro byte depois do manifesto é preenchimento; o manifesto
        # deste exemplo não é múltiplo de 16.
        ruim = bytearray(pacote)
        fim_manifesto = 80 + (p.deslocamento_imagem - 80)
        # Encontra o primeiro byte de preenchimento real usando o tamanho do TLV.
        fim_manifesto = 80 + len(p.manifesto_tlv)
        self.assertLess(fim_manifesto, p.deslocamento_imagem)
        ruim[fim_manifesto] = 1
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(bytes(ruim), publica)
        self.assertEqual(ctx.exception.codigo, "LAYOUT")

    def test_resumo_adulterado(self):
        pacote, _m, publica = self._pacote()
        ruim = bytearray(pacote)
        ruim[48] ^= 1
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(bytes(ruim), publica)
        self.assertEqual(ctx.exception.codigo, "RESUMO")

    def test_assinatura_adulterada(self):
        pacote, _m, publica = self._pacote()
        ruim = bytearray(pacote)
        ruim[-1] ^= 1
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(bytes(ruim), publica)
        self.assertEqual(ctx.exception.codigo, "ASSINATURA_CRIPTO")
        # Sem chave, a ferramenta confere só estrutura e resumo: a assinatura
        # não é uma garantia que se possa supor sem a chave.
        sadrv.analisar_pacote(bytes(ruim))

    def test_chave_errada(self):
        pacote, _m, _publica = self._pacote()
        outra = sadrv.ed25519_chave_publica(bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(pacote, outra)
        self.assertEqual(ctx.exception.codigo, "ASSINATURA_CRIPTO")

    def test_entrada_fora_da_imagem(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 52
        tlv = sadrv.montar_manifesto(m)
        pacote = sadrv.montar_pacote(tlv, b"\xc3\xc3\xc3\xc3", 0, [],
                                     SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(pacote)
        self.assertEqual(ctx.exception.codigo, "CAMPO")

    def test_realocacao_invalida(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        tlv = sadrv.montar_manifesto(m)
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(tlv, b"\xc3\xc3\xc3\xc3", 0,
                                [sadrv.Realocacao(1, 0, 0)], SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(tlv, b"\xc3\xc3\xc3\xc3", 0,
                                [sadrv.Realocacao(0, 1, 4)], SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(tlv, b"\xc3\xc3\xc3\xc3", 0,
                                [sadrv.Realocacao(0, 0, 999)], SEMENTE_TESTE)

    def test_ponteiro_interno_efetivo_do_pacote(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        tlv = sadrv.montar_manifesto(m)
        relocacao = [sadrv.Realocacao(0, 0, 0)]
        base = sadrv.montar_pacote(tlv, b"\x00" * 4, 0, relocacao,
                                   SEMENTE_TESTE)
        deslocamento_imagem = deslocamento_da_imagem(base)
        # A imagem de quatro bytes é alinhada para 16 bytes, então
        # carregado = 16; 15 é o último deslocamento válido.
        for valor, aceito in ((0, True), (15, True), (16, False),
                              (0xFFFFFFFF, False)):
            with self.subTest(valor=valor):
                imagem = struct.pack("<I", valor)
                if aceito:
                    pacote = sadrv.montar_pacote(tlv, imagem, 0, relocacao,
                                                 SEMENTE_TESTE)
                    lido = sadrv.analisar_pacote(pacote)
                    self.assertEqual(lido.realocacoes[0].alvo, 0)
                else:
                    with self.assertRaises(sadrv.ErroSadrivers):
                        sadrv.montar_pacote(tlv, imagem, 0, relocacao,
                                            SEMENTE_TESTE)
                    ruim = bytearray(base)
                    struct.pack_into("<I", ruim, deslocamento_imagem, valor)
                    with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                        sadrv.analisar_pacote(reassinar_pacote(ruim))
                    self.assertEqual(ctx.exception.codigo, "REALOCACAO")

    def test_realocacoes_sobrepostas_no_pacote(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        tlv = sadrv.montar_manifesto(m)
        imagem = b"\x90" * 8
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(
                tlv, imagem, 0,
                [sadrv.Realocacao(0, 1, 1),
                 sadrv.Realocacao(2, 1, 1)],
                SEMENTE_TESTE)
        base = sadrv.montar_pacote(
            tlv, imagem, 0,
            [sadrv.Realocacao(0, 1, 1),
             sadrv.Realocacao(4, 1, 1)],
            SEMENTE_TESTE)
        campos = sadrv._ler_campo_header(base)
        deslocamento_realocacoes = campos[6]
        ruim = bytearray(base)
        struct.pack_into("<I", ruim, deslocamento_realocacoes + 8, 2)
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(reassinar_pacote(ruim))
        self.assertEqual(ctx.exception.codigo, "REALOCACAO")

    def test_realocacoes_sobrepostas_em_secoes_diferentes(self):
        # A ferramenta já concatenou as seções: o que importa são os
        # deslocamentos globais.  Dois campos em 0 e 2 podem ter vindo de
        # seções diferentes e continuam proibidos.
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        tlv = sadrv.montar_manifesto(m)
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(
                tlv, b"\x90" * 8, 0,
                [sadrv.Realocacao(0, 1, 1),
                 sadrv.Realocacao(2, 1, 1)],
                SEMENTE_TESTE)

    def test_chave_do_manifesto_diferente_da_assinatura(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        # Assina com a semente de teste, mas o manifesto diz que a chave é
        # outra.  A assinatura é válida; o ID_DA_CHAVE não.
        pacote = sadrv.montar_pacote(sadrv.montar_manifesto(m), b"\xc3", 0, [],
                                     SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(pacote, sadrv.ed25519_chave_publica(SEMENTE_TESTE))
        self.assertEqual(ctx.exception.codigo, "CHAVE")

    def test_dependencia_de_si_mesmo_no_pacote(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        m.dependencias = [m.id]
        # montar_manifesto não decide a ordem do grafo; o analisador sim.
        pacote = sadrv.montar_pacote(sadrv.montar_manifesto(m), b"\xc3", 0, [],
                                     SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.analisar_pacote(pacote)
        self.assertEqual(ctx.exception.codigo, "DEPENDENCIA")

    def test_pacote_so_abre_id_autorizado(self):
        pacote, _m, publica = self._pacote()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ativo.txt").write_text("saguios.diagnostico\nsaguios.falta\n",
                                            encoding="ascii")
            (base / "saguios.diagnostico.sadrivers").write_bytes(pacote)
            # Este arquivo não está listado e é inválido de propósito.  Se a
            # função o abrisse, o erro seria de pacote, não NAO_LISTADO.
            (base / "saguios.solto.sadrivers").write_bytes(b"lixo")
            lido = sadrv.ler_pacote_autorizado(base, "saguios.diagnostico", publica)
            self.assertIsNotNone(lido)
            self.assertEqual(lido.manifesto.id, "saguios.diagnostico")
            with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                sadrv.ler_pacote_autorizado(base, "saguios.solto")
            self.assertEqual(ctx.exception.codigo, "NAO_LISTADO")
            self.assertIsNone(sadrv.ler_pacote_autorizado(base, "saguios.falta"))

    def test_pacote_autorizado_recusa_link_na_mesma_pasta(self):
        pacote, _m, publica = self._pacote()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ativo.txt").write_text("saguios.diagnostico\n", encoding="ascii")
            outro = base / "outro.sadrivers"
            outro.write_bytes(pacote)
            link = base / "saguios.diagnostico.sadrivers"
            try:
                os.symlink(outro.name, link)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            with self.assertRaises(sadrv.ErroUso) as ctx:
                sadrv.ler_pacote_autorizado(base, "saguios.diagnostico", publica)
            self.assertIn("link simbólico", str(ctx.exception))
            self.assertTrue(link.is_symlink())
            self.assertEqual(outro.read_bytes(), pacote)

    def test_pacote_autorizado_recusa_link_para_fora_da_pasta(self):
        pacote, _m, publica = self._pacote()
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            base = raiz / "pacotes"
            base.mkdir()
            (base / "ativo.txt").write_text("saguios.diagnostico\n", encoding="ascii")
            fora = raiz / "fora.sadrivers"
            fora.write_bytes(pacote)
            link = base / "saguios.diagnostico.sadrivers"
            try:
                os.symlink(fora, link)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            with self.assertRaises(sadrv.ErroUso) as ctx:
                sadrv.ler_pacote_autorizado(base, "saguios.diagnostico", publica)
            self.assertIn("link simbólico", str(ctx.exception))
            self.assertTrue(link.is_symlink())
            self.assertEqual(fora.read_bytes(), pacote)

    def test_id_do_manifesto_precisa_ser_o_nome_do_arquivo(self):
        pacote, _m, publica = self._pacote()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ativo.txt").write_text("saguios.outro\n", encoding="ascii")
            (base / "saguios.outro.sadrivers").write_bytes(pacote)
            with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                sadrv.ler_pacote_autorizado(base, "saguios.outro", publica)
            self.assertEqual(ctx.exception.codigo, "CAMPO")

    def test_arquivo_de_pacote_maior_que_o_limite(self):
        with tempfile.TemporaryDirectory() as tmp:
            caminho = Path(tmp) / "grande.sadrivers"
            caminho.write_bytes(b"\x00" * (sadrv.MAX_PACOTE + 1))
            with self.assertRaises(sadrv.ErroSadrivers) as ctx:
                sadrv._ler_arquivo_pacote(caminho)
            self.assertEqual(ctx.exception.codigo, "TAMANHO")

    def test_limites_do_pacote(self):
        m = sadrv.ler_manifesto_toml(TOML_EXEMPLO, b"12345678")
        m.entrada = 0
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(sadrv.montar_manifesto(m),
                                b"\xc3" * (sadrv.MAX_IMAGEM + 1), 0, [],
                                SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers):
            sadrv.montar_pacote(sadrv.montar_manifesto(m), b"\xc3",
                                sadrv.MAX_BSS + 1, [], SEMENTE_TESTE)
        with self.assertRaises(sadrv.ErroSadrivers) as ctx:
            sadrv.montar_pacote(
                sadrv.montar_manifesto(m), b"\xc3\xc3\xc3\xc3", 0,
                [sadrv.Realocacao(0, 0, 0)] * (sadrv.MAX_REALOCACOES + 1),
                SEMENTE_TESTE)
        self.assertEqual(ctx.exception.codigo, "TAMANHO")


class TesteCli(unittest.TestCase):
    def _pacote(self, base):
        obj, toml, chave, publica = escrever_arquivos(base)
        saida = base / "saguios.diagnostico.sadrivers"
        codigo, _texto, erro = rodar_cli([
            "embalar", "--objeto", str(obj), "--manifesto", str(toml),
            "--chave", str(chave), "--saida", str(saida)])
        self.assertEqual(codigo, 0, erro)
        return saida, publica

    def test_extrair_nao_sobrescreve_arquivo_existente(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pacote, _publica = self._pacote(base)
            pasta = base / "extraido"
            pasta.mkdir()
            preservado = pasta / "imagem.bin"
            preservado.write_bytes(b"nao mude")
            codigo, _texto, erro = rodar_cli(
                ["extrair", str(pacote), "--pasta", str(pasta)])
            self.assertEqual(codigo, 2)
            self.assertIn("já existe", erro)
            self.assertEqual(preservado.read_bytes(), b"nao mude")
            self.assertFalse((pasta / "manifesto.tlv").exists())

    def test_extrair_recusa_link_simbolico_preexistente(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pacote, _publica = self._pacote(base)
            pasta = base / "extraido"
            pasta.mkdir()
            fora = base / "fora.txt"
            fora.write_bytes(b"nao escreva aqui")
            alvo = pasta / "manifesto.tlv"
            try:
                os.symlink(fora, alvo)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            codigo, _texto, erro = rodar_cli(
                ["extrair", str(pacote), "--pasta", str(pasta)])
            self.assertEqual(codigo, 2)
            self.assertIn("já existe", erro)
            self.assertEqual(fora.read_bytes(), b"nao escreva aqui")
            self.assertTrue(alvo.is_symlink())

    def test_extrair_desfaz_arquivos_criados_se_uma_gravacao_falhar(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pacote, _publica = self._pacote(base)
            pasta = base / "extraido"
            pasta.mkdir()
            preservado = pasta / "nota.txt"
            preservado.write_text("nao apague\n", encoding="ascii")
            original = sadrv.os.fdopen
            escritas = {"n": 0}

            def fdopen_que_falha(descritor, modo="r", *args, **kwargs):
                # A terceira gravação (imagem.bin) deixa bytes parciais no
                # arquivo e falha; _gravar_novo precisa apagar esse arquivo.
                if modo == "wb":
                    escritas["n"] += 1
                    if escritas["n"] == 3:
                        os.write(descritor, b"parcial")
                        os.close(descritor)
                        raise OSError("falha simulada")
                return original(descritor, modo, *args, **kwargs)

            sadrv.os.fdopen = fdopen_que_falha
            try:
                codigo, _texto, erro = rodar_cli(
                    ["extrair", str(pacote), "--pasta", str(pasta)])
            finally:
                sadrv.os.fdopen = original
            self.assertEqual(codigo, 2)
            self.assertIn("falha simulada", erro)
            for nome in ("manifesto.tlv", "manifesto.txt", "imagem.bin",
                         "bss.bin", "resumo.bin", "assinatura.bin",
                         "realocacoes.txt"):
                self.assertFalse(os.path.lexists(pasta / nome), nome)
            self.assertEqual(preservado.read_text(encoding="ascii"), "nao apague\n")

            # Com a gravação normal, a mesma pasta extrai tudo.
            codigo, _texto, erro = rodar_cli(
                ["extrair", str(pacote), "--pasta", str(pasta)])
            self.assertEqual(codigo, 0, erro)
            for nome in ("manifesto.tlv", "manifesto.txt", "imagem.bin",
                         "bss.bin", "resumo.bin", "assinatura.bin",
                         "realocacoes.txt"):
                self.assertTrue((pasta / nome).is_file(), nome)
            self.assertEqual(preservado.read_text(encoding="ascii"), "nao apague\n")

    def test_extrair_recusa_pasta_de_destino_simbolica(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pacote, _publica = self._pacote(base)
            pasta = base / "real"
            pasta.mkdir()
            atalho = base / "atalho"
            try:
                os.symlink(pasta, atalho)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            codigo, _texto, erro = rodar_cli(
                ["extrair", str(pacote), "--pasta", str(atalho)])
            self.assertEqual(codigo, 2)
            self.assertIn("link simbólico", erro)
            self.assertEqual(list(pasta.iterdir()), [])

    def test_gerar_chave_nao_sobrescreve_sem_forcar(self):
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "chave.txt"
            destino.write_bytes(b"conteudo antigo")
            with self.assertRaises(sadrv.ErroUso):
                sadrv.gerar_chave_privada(destino)
            self.assertEqual(destino.read_bytes(), b"conteudo antigo")

    def test_gerar_chave_recusa_link_simbolico(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fora = base / "fora.txt"
            fora.write_bytes(b"nao mude")
            destino = base / "chave.txt"
            try:
                os.symlink(fora, destino)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            with self.assertRaises(sadrv.ErroUso):
                sadrv.gerar_chave_privada(destino, forcar=True)
            self.assertEqual(fora.read_bytes(), b"nao mude")
            self.assertTrue(destino.is_symlink())

    def test_gerar_chave_permissao_restrita_no_posix(self):
        if os.name != "posix":
            self.skipTest("permissões POSIX não existem neste Windows")
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "chave.txt"
            sadrv.gerar_chave_privada(destino)
            self.assertEqual(destino.stat().st_mode & 0o777, 0o600)

    def test_gerar_chave_e_publica(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            chave = base / "chave.txt"
            codigo, saida, erro = rodar_cli(["gerar-chave", "--saida", str(chave)])
            self.assertEqual(codigo, 0, erro)
            self.assertIn("ID_DA_CHAVE:", saida)
            self.assertTrue(chave.exists())
            # A semente não pode aparecer na saída.
            self.assertNotIn(SEMENTE_TESTE.hex(), saida)
            semente = bytes.fromhex(
                [l for l in chave.read_text().splitlines() if not l.startswith("#")][0])
            publica = sadrv.ed25519_chave_publica(semente)
            pub = base / "chave.pub"
            pub.write_text(publica.hex() + "\n", encoding="ascii")
            codigo, saida, erro = rodar_cli(["fingerprint", str(pub)])
            self.assertEqual(codigo, 0, erro)
            self.assertIn(hashlib.sha256(publica).hexdigest(), saida)
            self.assertIn("ID_DA_CHAVE:", saida)

    def test_chave_publica_c(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            chave = base / "chave.txt"
            chave.write_text(SEMENTE_TESTE.hex() + "\n", encoding="ascii")
            destino = base / "chave.c"
            codigo, saida, erro = rodar_cli(
                ["chave-publica", str(chave), "--c", str(destino)])
            self.assertEqual(codigo, 0, erro)
            texto = destino.read_text(encoding="ascii")
            self.assertIn("ID_DA_CHAVE:", texto)
            self.assertIn("sadrv_chave_publica[32]", texto)
            # A pública do vetor 1 do RFC 8032 começa em d7 5a; a semente
            # começa em 9d 61.  Só a pública pode aparecer no arquivo.
            self.assertIn("0xd7", texto)
            self.assertNotIn("0x9d", texto)
            self.assertNotIn(SEMENTE_TESTE.hex(), texto)

    def test_chave_publica_c_substitui_arquivo_regular(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            chave = base / "chave.txt"
            chave.write_text(SEMENTE_TESTE.hex() + "\n", encoding="ascii")
            destino = base / "chave.c"
            destino.write_text("conteudo antigo\n", encoding="ascii")
            codigo, _saida, erro = rodar_cli(
                ["chave-publica", str(chave), "--c", str(destino)])
            self.assertEqual(codigo, 0, erro)
            texto = destino.read_text(encoding="ascii")
            self.assertIn("sadrv_chave_publica[32]", texto)
            self.assertNotIn("conteudo antigo", texto)

    def test_chave_publica_c_recusa_link_simbolico(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            chave = base / "chave.txt"
            chave.write_text(SEMENTE_TESTE.hex() + "\n", encoding="ascii")
            alvo = base / "fora.c"
            alvo.write_bytes(b"nao mude")
            destino = base / "chave.c"
            try:
                os.symlink(alvo, destino)
            except (OSError, NotImplementedError):
                self.skipTest("criar link simbólico exige privilégio neste Windows")
            codigo, _saida, erro = rodar_cli(
                ["chave-publica", str(chave), "--c", str(destino)])
            self.assertEqual(codigo, 2)
            self.assertIn("link simbólico", erro)
            self.assertEqual(alvo.read_bytes(), b"nao mude")
            self.assertTrue(destino.is_symlink())

    def test_ciclo_embalar_verificar_inspecionar_extrair(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            obj, toml, chave, publica = escrever_arquivos(base)
            saida = base / "saguios.diagnostico.sadrivers"
            codigo, texto, erro = rodar_cli([
                "embalar", "--objeto", str(obj), "--manifesto", str(toml),
                "--chave", str(chave), "--saida", str(saida)])
            self.assertEqual(codigo, 0, erro)
            self.assertTrue(saida.exists())
            self.assertIn("ID_DA_CHAVE:", texto)

            codigo, texto, erro = rodar_cli(
                ["verificar", str(saida), "--chave-publica", str(base / "chave.pub")])
            self.assertEqual(codigo, 0, erro)
            self.assertIn("assinatura Ed25519 conferida", texto)

            codigo, texto, erro = rodar_cli(["verificar", str(saida)])
            self.assertEqual(codigo, 0, erro)
            self.assertIn("NÃO conferida", texto)

            codigo, texto, erro = rodar_cli(["inspecionar", str(saida)])
            self.assertEqual(codigo, 0, erro)
            self.assertIn("saguios.diagnostico", texto)
            self.assertIn("REALOCACOES:", texto)

            pasta = base / "extraido"
            codigo, texto, erro = rodar_cli(
                ["extrair", str(saida), "--pasta", str(pasta)])
            self.assertEqual(codigo, 0, erro)
            for nome in ("manifesto.tlv", "manifesto.txt", "imagem.bin",
                         "bss.bin", "resumo.bin", "assinatura.bin",
                         "realocacoes.txt"):
                self.assertTrue((pasta / nome).exists(), nome)
            self.assertEqual((pasta / "imagem.bin").read_bytes(),
                             sadrv.analisar_pacote(saida.read_bytes()).imagem)

    def test_nome_do_arquivo_obrigatorio(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            obj, toml, chave, _publica = escrever_arquivos(base)
            codigo, _texto, erro = rodar_cli([
                "embalar", "--objeto", str(obj), "--manifesto", str(toml),
                "--chave", str(chave), "--saida", str(base / "outro.sadrivers")])
            self.assertEqual(codigo, 2)
            self.assertIn("saguios.diagnostico.sadrivers", erro)

    def test_pacote_invalido_sai_com_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ruim = base / "ruim.sadrivers"
            ruim.write_bytes(b"x" * 176)
            for comando in (["verificar", str(ruim)],
                            ["inspecionar", str(ruim)]):
                codigo, _texto, erro = rodar_cli(comando)
                self.assertEqual(codigo, 1, comando)
                self.assertIn("erro:", erro)


class TesteGcc(unittest.TestCase):
    FONTE = r"""
typedef unsigned int u32;

static volatile u32 dado = 0x11223344u;
static volatile u32 bss[1024];

int sadrv_entrada(const void *api, const void *disp)
{
    u32 x = dado;
    (void)api;
    (void)disp;
    bss[0] = x + 1u;
    return (int)(bss[0] + dado);
}
"""
    FLAGS = [
        "-m32", "-march=i686", "-std=gnu11", "-O2",
        "-ffreestanding", "-fno-builtin", "-nostdlib", "-fno-pic", "-fno-pie",
        "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
        "-fno-common", "-fcf-protection=none", "-fno-omit-frame-pointer",
        "-mgeneral-regs-only", "-Wall", "-Wextra",
        "-Werror=implicit-function-declaration",
        "-finput-charset=UTF-8", "-fexec-charset=ISO-8859-1",
    ]

    @staticmethod
    def _achar(ambiente, nomes):
        valor = os.environ.get(ambiente)
        if valor:
            return valor
        for nome in nomes:
            caminho = shutil.which(nome)
            if caminho:
                return caminho
        return None

    def test_layout_das_estruturas_abi(self):
        gcc = self._achar("SADRV_GCC", ("gcc", "i686-elf-gcc",
                                        "i386-linux-gnu-gcc"))
        if not gcc:
            self.skipTest("GCC i386 não está instalado nesta máquina")
        fonte = RAIZ / "tests" / "h91_abi.c"
        with tempfile.TemporaryDirectory() as tmp:
            objeto = Path(tmp) / "h91_abi.o"
            resultado = subprocess.run(
                [gcc, "-m32", "-std=gnu11", "-ffreestanding", "-nostdlib",
                 "-Wall", "-Wextra", "-Werror", "-c", str(fonte),
                 "-o", str(objeto)],
                capture_output=True, text=True)
            if resultado.returncode != 0:
                self.fail("as verificações de layout não compilaram:\n%s\n%s" %
                          (resultado.stdout, resultado.stderr))

    def test_modulo_c_real_compilado_com_gcc_e_ld_r(self):
        gcc = self._achar("SADRV_GCC", ("gcc", "i686-elf-gcc",
                                        "i386-linux-gnu-gcc"))
        if not gcc:
            self.skipTest("GCC i386 não está instalado nesta máquina")
        candidatos_ld = ("ld", "i686-elf-ld", "i386-linux-gnu-ld")
        if Path(gcc).name == "i686-elf-gcc":
            candidatos_ld = ("i686-elf-ld",) + candidatos_ld
        ld = self._achar("SADRV_LD", candidatos_ld)
        if not ld:
            self.skipTest("ld i386 não está instalado nesta máquina")

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fonte = base / "modulo.c"
            objeto_c = base / "modulo_c.o"
            objeto = base / "modulo.o"
            fonte.write_text(self.FONTE, encoding="ascii")

            def rodar(comando, aceitar_falta_de_iconv=False):
                resultado = subprocess.run(
                    comando, cwd=str(base), capture_output=True, text=True)
                if resultado.returncode != 0:
                    if (aceitar_falta_de_iconv and
                            "no iconv implementation" in resultado.stderr):
                        self.skipTest(
                            "GCC desta máquina foi compilado sem iconv; "
                            "use o GCC do CI ou do WSL")
                    self.fail("comando falhou: %r\n%s\n%s" %
                              (comando, resultado.stdout, resultado.stderr))

            rodar([gcc] + self.FLAGS + ["-c", str(fonte), "-o", str(objeto_c)],
                  aceitar_falta_de_iconv=True)
            rodar([ld, "-m", "elf_i386", "-r", "-o", str(objeto),
                   str(objeto_c)])
            obj = sadrv.ler_objeto_elf(objeto, "sadrv_entrada")
            self.assertGreater(len(obj.imagem), 0)
            self.assertGreaterEqual(obj.tamanho_bss, 4096)
            m = sadrv.ler_manifesto_toml(TOML_EXEMPLO)
            m = sadrv.replace(m, entrada=obj.entrada)
            pacote, m = sadrv.empacotar(m, obj.imagem, obj.tamanho_bss,
                                        obj.realocacoes, SEMENTE_TESTE)
            lido = sadrv.analisar_pacote(
                pacote, sadrv.ed25519_chave_publica(SEMENTE_TESTE))
            self.assertEqual(lido.manifesto.id, "saguios.diagnostico")


if __name__ == "__main__":
    unittest.main(verbosity=2)
