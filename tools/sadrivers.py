#!/usr/bin/env python3
"""sadrivers.py - monta, lê e confere pacotes de driver do SaguiOS.

O formato está descrito em docs/sadrivers.md, versão experimental 0.1.  Este
programa é a ferramenta de build: ele lê um objeto ELF32 i386 relocável e um
manifesto TOML, resolve as realocações que já podem ser resolvidas, monta a
imagem do módulo e embrulha tudo num pacote .sadrivers assinado com Ed25519.

O que fica para o carregador do kernel (que ainda não existe nesta etapa) é
só o que depende do endereço de carga: as realocações absolutas internas e as
três funções externas permitidas (memcpy, memset e memmove).  O kernel não lê
ELF nem TOML.

Conhecimento usado, sem código de outro sistema operacional:

  - Tool Interface Standard (TIS) ELF Specification 1.2, para o ELF32, as
    seções, a tabela de símbolos e as realocações R_386_32/R_386_PC32;
  - RFC 8032, para o Ed25519 (a variante pura, sem pré-hash);
  - FIPS 180-4, para o SHA-256 do pacote e o SHA-512 interno do Ed25519;
  - a especificação do formato em docs/sadrivers.md.

O Ed25519 foi escrito aqui em Python puro para a ferramenta não depender de
biblioteca externa.  A implementação do kernel é outra (userland/cripto/
curva25519.c); as duas são conferidas contra os mesmos vetores do RFC 8032.
O SHA-256/SHA-512 da ferramenta usam hashlib, que faz parte da biblioteca
padrão do Python; no kernel as rotinas são as do projeto.

Uso:
  python3 tools/sadrivers.py embalar --objeto x.o --manifesto x.toml \\
                                      --chave chave.txt \\
                                      --saida build/modulos/id.sadrivers
  python3 tools/sadrivers.py inspecionar x.sadrivers
  python3 tools/sadrivers.py verificar x.sadrivers [--chave-publica k.pub]
  python3 tools/sadrivers.py extrair x.sadrivers --pasta saida/
  python3 tools/sadrivers.py gerar-chave --saida chave.txt
  python3 tools/sadrivers.py chave-publica chave.txt --c chave.c
  python3 tools/sadrivers.py fingerprint chave.pub

Códigos de saída: 0 = certo; 1 = pacote recusado; 2 = uso/entrada inválida.

A assinatura não é uma caixa de areia.  Um módulo assinado roda em ring 0 e
pode tudo; a chave reconhecida pelo projeto só diz quem responde pelo código.
Veja docs/sadrivers.md, seção 15.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import stat
import struct
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


# ------------------------------------------------------------------ limites

MAGIC = b"SADRV\x01\r\n"
TAMANHO_CABECALHO = 80
TAMANHO_ASSINATURA = 64
TAMANHO_MINIMO = TAMANHO_CABECALHO + TAMANHO_ASSINATURA + 32
MAX_PACOTE = 262144                 # 256 KiB
MAX_MANIFESTO = 8192                # 8 KiB
MAX_IMAGEM = 131072                 # 128 KiB
MAX_BSS = 65536                     # 64 KiB
MAX_CARREGADO = 196608              # 192 KiB
MAX_REALOCACOES = 4096
MAX_DISPOSITIVOS = 16
MAX_DEPENDENCIAS = 8
MAX_PACOTES = 32
MAX_ATIVO_TXT = 2048
MAX_TOML = 65536
MAX_CHAVE = 4096
MAX_OBJETO = 16 * 1024 * 1024

ABI_VERSAO = 1
ARQUITETURA_X86 = 1

# Códigos da especificação (seção 9).  A ferramenta usa o nome; o número fica
# disponível para quem for integrar a ferramenta ao build ou ao painel.
SADRV_OK = 0
SADRV_ERRO_ASSINATURA = 1
SADRV_ERRO_TAMANHO = 2
SADRV_ERRO_LAYOUT = 3
SADRV_ERRO_VERSAO = 4
SADRV_ERRO_RESUMO = 5
SADRV_ERRO_CHAVE = 6
SADRV_ERRO_ASSINATURA_CRIPTO = 7
SADRV_ERRO_MANIFESTO = 8
SADRV_ERRO_CAMPO = 9
SADRV_ERRO_REALOCACAO = 10
SADRV_ERRO_DEPENDENCIA = 11
SADRV_ERRO_MEMORIA = 12
SADRV_ERRO_ENTRADA = 13
SADRV_ERRO_JA_CARREGADO = 14
SADRV_ERRO_NAO_LISTADO = 15

CODIGOS = {
    0: "SADRV_OK",
    1: "SADRV_ERRO_ASSINATURA",
    2: "SADRV_ERRO_TAMANHO",
    3: "SADRV_ERRO_LAYOUT",
    4: "SADRV_ERRO_VERSAO",
    5: "SADRV_ERRO_RESUMO",
    6: "SADRV_ERRO_CHAVE",
    7: "SADRV_ERRO_ASSINATURA_CRIPTO",
    8: "SADRV_ERRO_MANIFESTO",
    9: "SADRV_ERRO_CAMPO",
    10: "SADRV_ERRO_REALOCACAO",
    11: "SADRV_ERRO_DEPENDENCIA",
    12: "SADRV_ERRO_MEMORIA",
    13: "SADRV_ERRO_ENTRADA",
    14: "SADRV_ERRO_JA_CARREGADO",
    15: "SADRV_ERRO_NAO_LISTADO",
}

LICENCAS = {
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "GPL-2.0-or-later",
    "LGPL-3.0-or-later",
    "LGPL-2.1-or-later",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "ISC",
    "Zlib",
    "0BSD",
    "CC0-1.0",
}

SIMBOLOS_EXTERNOS = {
    "memcpy": 1,
    "memset": 2,
    "memmove": 3,
}

RE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
RE_VERSAO = re.compile(r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$")
RE_SIMBOLO = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# ------------------------------------------------------------------ erros

class ErroSadrivers(Exception):
    """Pacote inválido, no sentido da seção 9 da especificação."""

    def __init__(self, codigo: str, mensagem: str):
        super().__init__(mensagem)
        self.codigo = codigo
        self.mensagem = mensagem

    def __str__(self) -> str:
        numero = next((n for n, nome in CODIGOS.items() if nome == self.codigo), -1)
        if numero >= 0:
            return f"{self.mensagem} ({self.codigo}, código {numero})"
        return f"{self.mensagem} ({self.codigo})"


class ErroUso(Exception):
    """Entrada da ferramenta errada: TOML, ELF, chave, argumento ou arquivo."""


# ------------------------------------------------------------------ utilidades

def alinhar16(n: int) -> int:
    """Arredonda para o próximo múltiplo de 16 (a mesma conta do kernel)."""
    return (n + 15) & ~15


def _registrar_intervalo(ocupados: set, deslocamento: int) -> None:
    """Marca [deslocamento, deslocamento+4), recusando qualquer sobreposição."""
    faixa = range(deslocamento, deslocamento + 4)
    if any(byte in ocupados for byte in faixa):
        raise ErroSadrivers(
            "REALOCACAO", "intervalos de realocação sobrepostos")
    ocupados.update(faixa)


def _u16(valor: int, campo: str) -> int:
    if not isinstance(valor, int) or not 0 <= valor <= 0xFFFF:
        raise ErroSadrivers("CAMPO", f"{campo} fora de 0..65535")
    return valor


def _u32(valor: int, campo: str) -> int:
    if not isinstance(valor, int) or not 0 <= valor <= 0xFFFFFFFF:
        raise ErroSadrivers("CAMPO", f"{campo} fora de 0..4294967295")
    return valor


def _zeros(dados: bytes, inicio: int, fim: int) -> bool:
    return not any(dados[inicio:fim])


def _ler_bytes_ate(caminho: os.PathLike, limite: int, descricao: str) -> bytes:
    """Lê no máximo ``limite`` bytes e recusa o que passar.

    Ler o arquivo inteiro e só depois conferir o tamanho deixaria um arquivo
    enorme consumir memória à toa.  O ``limite + 1`` é o suficiente para
    saber que passou; não é preciso ler o resto.
    """
    with Path(caminho).open("rb") as arquivo:
        dados = arquivo.read(limite + 1)
    if len(dados) > limite:
        raise ErroUso(f"{descricao} maior que {limite} bytes")
    return dados


def _id_da_chave(publica: bytes) -> bytes:
    if not isinstance(publica, (bytes, bytearray)):
        raise ErroUso("a chave pública Ed25519 deve ser bytes")
    if len(publica) != 32:
        raise ErroUso("a chave pública Ed25519 deve ter 32 bytes")
    return hashlib.sha256(bytes(publica)).digest()[:8]


# ------------------------------------------------------------------ Ed25519
#
# Esta é uma implementação didática e fora do caminho crítico do kernel.  Ela
# não promete tempo constante: o Python não oferece isso.  A implementação do
# kernel (curva25519.c) é a que roda na máquina do usuário; esta serve para
# criar e conferir pacotes no computador de build.
#
# Coordenadas estendidas (X, Y, Z, T), com x = X/Z, y = Y/Z e T = XY/Z.  As
# fórmulas são as da RFC 8032, seção 5.1.4.

PRIMO = (1 << 255) - 19
ORDEM = (1 << 252) + 27742317777372353535851937790883648493
D_CURVA = (-121665 * pow(121666, PRIMO - 2, PRIMO)) % PRIMO
RAIZ_MENOS_UM = pow(2, (PRIMO - 1) // 4, PRIMO)


def _inv(valor: int) -> int:
    return pow(valor % PRIMO, PRIMO - 2, PRIMO)


def _recuperar_x(y: int, sinal: int) -> int:
    """Dá a coordenada x de um ponto a partir de y (RFC 8032, 5.1.3)."""
    if not 0 <= y < PRIMO:
        raise ValueError("y fora do corpo")
    u = (y * y - 1) % PRIMO
    v = (D_CURVA * y * y + 1) % PRIMO
    x = (u * pow(v, 3, PRIMO) * pow((u * pow(v, 7, PRIMO)) % PRIMO,
                                    (PRIMO - 5) // 8, PRIMO)) % PRIMO
    if (v * x * x - u) % PRIMO != 0:
        if (v * x * x + u) % PRIMO != 0:
            raise ValueError("y não pertence à curva")
        x = (x * RAIZ_MENOS_UM) % PRIMO
    if x == 0 and sinal:
        raise ValueError("x = 0 com sinal 1")
    if (x & 1) != sinal:
        x = PRIMO - x
    return x


def _ponto(x: int, y: int, z: int = 1, t: Optional[int] = None) -> Tuple[int, int, int, int]:
    x %= PRIMO
    y %= PRIMO
    z %= PRIMO
    if t is None:
        t = (x * y) % PRIMO
    return (x, y, z, t % PRIMO)


PONTO_NEUTRO = _ponto(0, 1)
_Y_BASE = (4 * _inv(5)) % PRIMO
PONTO_BASE = _ponto(_recuperar_x(_Y_BASE, 0), _Y_BASE)


def _somar(p: Tuple[int, int, int, int],
           q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % PRIMO
    b = ((y1 + x1) * (y2 + x2)) % PRIMO
    c = (t1 * 2 * D_CURVA * t2) % PRIMO
    d = (z1 * 2 * z2) % PRIMO
    e = (b - a) % PRIMO
    f = (d - c) % PRIMO
    g = (d + c) % PRIMO
    h = (b + a) % PRIMO
    return ((e * f) % PRIMO, (g * h) % PRIMO,
            (f * g) % PRIMO, (e * h) % PRIMO)


def _dobrar(p: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x, y, z, _t = p
    a = (x * x) % PRIMO
    b = (y * y) % PRIMO
    c = (2 * z * z) % PRIMO
    d = (-a) % PRIMO
    e = (((x + y) * (x + y)) - a - b) % PRIMO
    g = (d + b) % PRIMO
    f = (g - c) % PRIMO
    h = (d - b) % PRIMO
    return ((e * f) % PRIMO, (g * h) % PRIMO,
            (f * g) % PRIMO, (e * h) % PRIMO)


def _escalar(k: int, p: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """[k]p.  Simples e legível; não é o caminho de tempo constante do kernel."""
    r = PONTO_NEUTRO
    for bit in range(255, -1, -1):
        r = _dobrar(r)
        if (k >> bit) & 1:
            r = _somar(r, p)
    return r


def _negativo(p: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x, y, z, t = p
    return ((-x) % PRIMO, y, z, (-t) % PRIMO)


def _codificar(p: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % PRIMO
    y = (y * zi) % PRIMO
    b = bytearray(y.to_bytes(32, "little"))
    b[31] |= (x & 1) << 7
    return bytes(b)


PONTO_IDENTIDADE_CODIFICADO = b"\x01" + b"\x00" * 31


def _decodificar(b: bytes) -> Tuple[int, int, int, int]:
    if len(b) != 32:
        raise ValueError("ponto codificado com tamanho errado")
    sinal = b[31] >> 7
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= PRIMO:
        raise ValueError("y não reduzido")
    x = _recuperar_x(y, sinal)
    return _ponto(x, y, 1, (x * y) % PRIMO)


def _validar_ponto(p: Tuple[int, int, int, int]) -> None:
    """Recusa identidade, torção e ponto fora do subgrupo de ordem L.

    A curva de Ed25519 tem ordem 8L.  Um ponto só é aceitável como chave
    pública (ou como R de uma assinatura) se estiver no subgrupo de ordem L:
    [L]P = O.  Antes disso, [8]P = O pega os pontos de ordem 1, 2, 4 e 8 sem
    uma multiplicação longa; a identidade tem um teste próprio para deixar a
    política explícita.  Sem isso, uma chave identidade aceita a assinatura
    falsa R = O, S = 0 para qualquer mensagem.
    """
    if _codificar(p) == PONTO_IDENTIDADE_CODIFICADO:
        raise ValueError("ponto identidade recusado")
    if _codificar(_escalar(8, p)) == PONTO_IDENTIDADE_CODIFICADO:
        raise ValueError("ponto de ordem pequena recusado")
    if _codificar(_escalar(ORDEM, p)) != PONTO_IDENTIDADE_CODIFICADO:
        raise ValueError("ponto fora do subgrupo de ordem L")


def _abrir_semente(semente: bytes) -> Tuple[int, bytes]:
    if not isinstance(semente, (bytes, bytearray)):
        raise ErroUso("a semente Ed25519 deve ser bytes")
    semente = bytes(semente)
    if len(semente) != 32:
        raise ErroUso("a semente Ed25519 deve ter 32 bytes")
    h = hashlib.sha512(semente).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little"), h[32:]


def ed25519_chave_publica(semente: bytes) -> bytes:
    """Deriva a chave pública de 32 bytes a partir da semente do RFC 8032."""
    a, _prefixo = _abrir_semente(semente)
    return _codificar(_escalar(a, PONTO_BASE))


def ed25519_assinar(semente: bytes, mensagem: bytes) -> bytes:
    """Assina a mensagem com a semente Ed25519 (variante pura)."""
    if not isinstance(mensagem, (bytes, bytearray)):
        raise ErroUso("a mensagem Ed25519 deve ser bytes")
    mensagem = bytes(mensagem)
    a, prefixo = _abrir_semente(semente)
    publica = _codificar(_escalar(a, PONTO_BASE))
    r = int.from_bytes(hashlib.sha512(prefixo + mensagem).digest(), "little") % ORDEM
    r_bytes = _codificar(_escalar(r, PONTO_BASE))
    k = int.from_bytes(hashlib.sha512(r_bytes + publica + mensagem).digest(),
                       "little") % ORDEM
    s = (r + k * a) % ORDEM
    return r_bytes + s.to_bytes(32, "little")


def ed25519_verificar(publica: bytes, mensagem: bytes, assinatura: bytes) -> bool:
    """Confere uma assinatura Ed25519 pura, sem exceção para dados ruins."""
    if not isinstance(publica, (bytes, bytearray)) or \
            not isinstance(mensagem, (bytes, bytearray)) or \
            not isinstance(assinatura, (bytes, bytearray)):
        return False
    publica = bytes(publica)
    mensagem = bytes(mensagem)
    assinatura = bytes(assinatura)
    if len(publica) != 32 or len(assinatura) != 64:
        return False
    s = int.from_bytes(assinatura[32:], "little")
    if s >= ORDEM:
        return False
    try:
        a = _decodificar(publica)
        _validar_ponto(a)
        r = _decodificar(assinatura[:32])
        _validar_ponto(r)
    except ValueError:
        return False
    k = int.from_bytes(hashlib.sha512(assinatura[:32] + publica + mensagem).digest(),
                       "little") % ORDEM
    # [S]B + [k](-A) deve ser R.  Como A e R já estão no subgrupo de ordem L,
    # a igualdade sem o fator 8 é equivalente à verificação cofatorada.
    calculado = _somar(_escalar(s, PONTO_BASE), _escalar(k, _negativo(a)))
    return _codificar(calculado) == _codificar(r)


# ------------------------------------------------------------------ IDs e caminhos

def validar_id(valor: str, campo: str = "ID", codigo: str = "CAMPO") -> str:
    """Confere um ID e recusa qualquer coisa que possa virar caminho.

    O ponto simples separa as partes do ID (saguios.e1000).  O que não pode
    existir é um componente "." ou "..", uma barra, uma contrabarra, dois
    pontos seguidos, um caminho absoluto ou um byte de controle.  O ID é usado
    como nome de arquivo (<ID>.sadrivers), então essa conferência é de
    segurança, não só de estilo.
    """
    if not isinstance(valor, str):
        raise ErroSadrivers(codigo, f"{campo} deve ser texto")
    try:
        bruto = valor.encode("ascii")
    except UnicodeEncodeError:
        raise ErroSadrivers(codigo, f"{campo} deve ser ASCII")
    if not 1 <= len(bruto) <= 31:
        raise ErroSadrivers(codigo, f"{campo} deve ter 1..31 bytes")
    if "/" in valor or "\\" in valor or "\x00" in valor:
        raise ErroSadrivers(codigo, f"{campo} não pode conter barra, contrabarra ou NUL")
    if valor in (".", "..") or valor.startswith("/") or re.match(r"^[A-Za-z]:", valor):
        raise ErroSadrivers(codigo, f"{campo} não pode ser caminho absoluto ou relativo")
    if not RE_ID.fullmatch(valor):
        raise ErroSadrivers(codigo, f"{campo} fora da regra [a-z0-9][a-z0-9._-]*")
    if "." not in valor:
        raise ErroSadrivers(codigo, f"{campo} deve ter pelo menos um ponto")
    if ".." in valor:
        raise ErroSadrivers(codigo, f"{campo} não pode ter ponto duplo")
    if valor.endswith((".", "-", "_")):
        raise ErroSadrivers(codigo, f"{campo} não pode terminar em ponto, hífen ou sublinhado")
    return valor


def caminho_pacote(pasta: os.PathLike, id_driver: str) -> Path:
    """Monta <pasta>/<ID>.sadrivers sem permitir sair da pasta.

    O ID já é validado antes de tocar no sistema de arquivos.  Só a pasta é
    resolvida; o nome final **não** passa por ``Path.resolve()``.  Resolver o
    último componente seguiria um link simbólico e trocaria o pacote
    autorizado pelo alvo do link.  Quem abre faz a recusa do link e confere
    que o descritor é de um arquivo regular (``_abrir_arquivo_regular``).
    """
    validar_id(id_driver, "ID")
    base = Path(pasta).resolve()
    destino = base / (id_driver + ".sadrivers")
    try:
        destino.relative_to(base)
    except ValueError:
        raise ErroSadrivers("CAMPO", "o ID tentou sair da pasta de pacotes")
    if destino.parent != base:
        raise ErroSadrivers("CAMPO", "o ID tentou sair da pasta de pacotes")
    return destino


def _e_arquivo_regular(caminho: Path) -> bool:
    """Diz se o caminho é um arquivo regular, sem seguir link simbólico.

    ``Path.is_file()`` segue links e devolveria verdadeiro para um link
    apontando para um pacote qualquer.  Aqui o ``lstat`` examina o próprio
    nome; um link não conta como pacote presente.  Só ``FileNotFoundError``
    significa "ausente"; outro erro de acesso vira ``ErroUso``, para não
    esconder uma permissão negada atrás de um pacote que parece não existir.
    """
    try:
        info = os.lstat(caminho)
    except FileNotFoundError:
        return False
    except OSError as erro:
        raise ErroUso(f"não foi possível examinar o pacote {caminho}: {erro}")
    return stat.S_ISREG(info.st_mode)


def ler_lista_autorizada(caminho: os.PathLike) -> List[str]:
    """Lê o ativo.txt: IDs válidos, sem duplicata, no máximo 32.

    Linhas inválidas são ignoradas, como manda a especificação.  O arquivo é
    ASCII e tem no máximo 2 KiB; um arquivo maior é recusado em vez de lido
    pela metade.
    """
    caminho = Path(caminho)
    try:
        bruto = _ler_bytes_ate(caminho, MAX_ATIVO_TXT, "ativo.txt")
    except FileNotFoundError:
        return []
    try:
        texto = bruto.decode("ascii")
    except UnicodeDecodeError:
        raise ErroUso("ativo.txt deve ser ASCII")
    ids: List[str] = []
    vistos = set()
    for linha in texto.splitlines():
        linha = linha.split("#", 1)[0].strip()
        if not linha:
            continue
        try:
            id_ok = validar_id(linha, "ID do ativo.txt", "MANIFESTO")
        except ErroSadrivers:
            continue
        if id_ok in vistos:
            continue
        vistos.add(id_ok)
        ids.append(id_ok)
    if len(ids) > MAX_PACOTES:
        raise ErroSadrivers("TAMANHO", f"ativo.txt tem mais de {MAX_PACOTES} IDs")
    return ids


@dataclass
class PacoteNaPasta:
    id: str
    caminho: Optional[Path]
    estado: str             # "presente", "ausente" ou "nao_listado"


def listar_pacotes(pasta: os.PathLike) -> List[PacoteNaPasta]:
    """Lista o que o carregador veria, sem abrir arquivo não listado.

    A ordem é a do ativo.txt (incluindo ausentes) e depois os arquivos soltos,
    como na especificação.  Um arquivo não listado aparece pelo nome, mas não
    é aberto nem verificado.
    """
    base = Path(pasta)
    ids = ler_lista_autorizada(base / "ativo.txt")
    resultado: List[PacoteNaPasta] = []
    for id_driver in ids:
        caminho = caminho_pacote(base, id_driver)
        if _e_arquivo_regular(caminho):
            resultado.append(PacoteNaPasta(id_driver, caminho, "presente"))
        else:
            resultado.append(PacoteNaPasta(id_driver, None, "ausente"))
    vistos = set(ids)
    if base.is_dir():
        for entrada in sorted(base.iterdir(), key=lambda p: p.name):
            if not entrada.name.endswith(".sadrivers"):
                continue
            id_driver = entrada.name[:-len(".sadrivers")]
            try:
                validar_id(id_driver, "nome de pacote", "MANIFESTO")
            except ErroSadrivers:
                continue
            if id_driver in vistos:
                continue
            if len(resultado) >= MAX_PACOTES:
                break
            # Não chama is_file() nem abre: um arquivo não listado não é
            # examinado.  O carregador só mostra o nome.
            resultado.append(PacoteNaPasta(id_driver, None, "nao_listado"))
    return resultado


def ler_pacote_autorizado(pasta: os.PathLike, id_driver: str,
                          chave_publica: Optional[bytes] = None) -> Optional[Pacote]:
    """Abre um pacote só se o ID estiver no ativo.txt.

    Devolve None quando o ID está autorizado mas o arquivo não existe (o
    carregador mostra "ausente" e continua).  Um ID fora da lista gera
    NAO_LISTADO antes de qualquer leitura: o conteúdo de um arquivo não
    listado não é aberto, exatamente como na especificação.

    Esta função é a ponte entre a lista e o analisador; ela não carrega nem
    executa código.  O carregador do kernel é assunto de outra história.
    """
    validar_id(id_driver, "ID")
    base = Path(pasta)
    if id_driver not in ler_lista_autorizada(base / "ativo.txt"):
        raise ErroSadrivers("NAO_LISTADO", f"o ID {id_driver} não está no ativo.txt")
    caminho = caminho_pacote(base, id_driver)
    try:
        dados = _ler_arquivo_pacote(caminho)
    except FileNotFoundError:
        return None
    pacote = analisar_pacote(dados, chave_publica)
    if pacote.manifesto.id != id_driver:
        raise ErroSadrivers(
            "CAMPO",
            f"o ID do manifesto ({pacote.manifesto.id}) não é o nome do arquivo ({id_driver})")
    return pacote


# ------------------------------------------------------------------ TOML mínimo

def _remover_comentario(linha: str) -> str:
    dentro = False
    escape = False
    for i, c in enumerate(linha):
        if escape:
            escape = False
            continue
        if dentro and c == "\\":
            escape = True
            continue
        if c == '"':
            dentro = not dentro
        elif c == "#" and not dentro:
            return linha[:i]
    if dentro:
        raise ErroUso("string TOML não terminada")
    return linha


def _ler_string_toml(valor: str) -> str:
    if len(valor) < 2 or valor[0] != '"' or valor[-1] != '"':
        raise ErroUso("valor de texto TOML deve estar entre aspas duplas")
    corpo = valor[1:-1]
    saida: List[str] = []
    i = 0
    simples = {'"': '"', "\\": "\\", "b": "\b", "f": "\f", "n": "\n",
               "r": "\r", "t": "\t"}
    while i < len(corpo):
        c = corpo[i]
        if c == '"':
            raise ErroUso("aspas duplas sem escape dentro de string TOML")
        if c != "\\":
            saida.append(c)
            i += 1
            continue
        i += 1
        if i >= len(corpo):
            raise ErroUso("escape incompleto em string TOML")
        e = corpo[i]
        if e in simples:
            saida.append(simples[e])
            i += 1
            continue
        if e in ("u", "U"):
            n = 4 if e == "u" else 8
            if i + n >= len(corpo):
                raise ErroUso("escape unicode incompleto em string TOML")
            digitos = corpo[i + 1:i + 1 + n]
            if not re.fullmatch(r"[0-9A-Fa-f]{%d}" % n, digitos):
                raise ErroUso("escape unicode inválido em string TOML")
            codigo = int(digitos, 16)
            if codigo > 0x10FFFF:
                raise ErroUso("escape unicode fora de faixa")
            saida.append(chr(codigo))
            i += n + 1
            continue
        raise ErroUso(f"escape TOML desconhecido: \\{e}")
    return "".join(saida)


def _ler_inteiro_toml(valor: str) -> int:
    if re.fullmatch(r"0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*", valor):
        return int(valor.replace("_", ""), 16)
    if re.fullmatch(r"0|[1-9][0-9]*(?:_[0-9]+)*", valor):
        return int(valor.replace("_", ""), 10)
    raise ErroUso(f"inteiro TOML inválido: {valor}")


def _separar_chave_valor(linha: str) -> Tuple[str, str]:
    dentro = False
    escape = False
    pos = -1
    for i, c in enumerate(linha):
        if escape:
            escape = False
            continue
        if dentro and c == "\\":
            escape = True
            continue
        if c == '"':
            dentro = not dentro
        elif c == "=" and not dentro:
            pos = i
            break
    if pos < 0:
        raise ErroUso(f"linha TOML sem '=': {linha!r}")
    chave = linha[:pos].strip()
    valor = linha[pos + 1:].strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", chave):
        raise ErroUso(f"chave TOML inválida: {chave!r}")
    if not valor:
        raise ErroUso(f"valor vazio para {chave}")
    return chave, valor


def _valor_toml(texto: str):
    if texto.startswith('"'):
        return _ler_string_toml(texto)
    if texto.startswith("'"):
        raise ErroUso("use aspas duplas no TOML desta ferramenta")
    return _ler_inteiro_toml(texto)


@dataclass
class _Toml:
    topo: Dict[str, object] = field(default_factory=dict)
    dispositivos: List[Dict[str, object]] = field(default_factory=list)
    dependencias: List[Dict[str, object]] = field(default_factory=list)


def _ler_toml(texto: str) -> _Toml:
    """Lê só o subconjunto de TOML descrito na especificação (seção 12.1)."""
    dados = _Toml()
    atual: Optional[Dict[str, object]] = None
    vistos_topo = set()
    tabela_iniciada = False
    for numero, linha_bruta in enumerate(texto.splitlines(), 1):
        linha = _remover_comentario(linha_bruta).strip()
        if not linha:
            continue
        if linha.startswith("[["):
            if not linha.endswith("]]"):
                raise ErroUso(f"linha {numero}: cabeçalho de tabela inválido")
            nome = linha[2:-2].strip()
            if nome == "dispositivo":
                atual = {}
                dados.dispositivos.append(atual)
            elif nome == "dependencia":
                atual = {}
                dados.dependencias.append(atual)
            else:
                raise ErroUso(f"linha {numero}: tabela desconhecida [[{nome}]]")
            tabela_iniciada = True
            continue
        if linha.startswith("["):
            raise ErroUso(f"linha {numero}: tabela TOML não suportada")
        chave, valor = _separar_chave_valor(linha)
        if atual is None:
            if tabela_iniciada:
                raise ErroUso(f"linha {numero}: chave de topo depois de uma tabela")
            if chave in vistos_topo:
                raise ErroUso(f"linha {numero}: chave repetida: {chave}")
            vistos_topo.add(chave)
            dados.topo[chave] = _valor_toml(valor)
        else:
            if chave in atual:
                raise ErroUso(f"linha {numero}: chave repetida na tabela: {chave}")
            atual[chave] = _valor_toml(valor)
    return dados


# ------------------------------------------------------------------ manifesto

@dataclass
class Dispositivo:
    bandeiras: int
    classe: int = 0
    subclasse: int = 0
    interface: int = 0
    fabricante: int = 0
    modelo: int = 0
    tipo: int = 1
    reservado: int = 0


@dataclass
class Manifesto:
    id: str
    nome: str
    descricao: str
    autor: str
    versao: str
    licenca: str
    id_chave: bytes
    entrada: int
    dispositivos: List[Dispositivo] = field(default_factory=list)
    dependencias: List[str] = field(default_factory=list)
    # Só existe no TOML: o nome do símbolo que a ferramenta transforma em
    # deslocamento.  O TLV guarda o deslocamento (tag 8).
    simbolo_entrada: str = ""


@dataclass
class Realocacao:
    deslocamento: int
    tipo: int
    alvo: int


@dataclass
class Pacote:
    dados: bytes
    manifesto: Manifesto
    manifesto_tlv: bytes
    imagem: bytes
    tamanho_bss: int
    realocacoes: List[Realocacao]
    resumo: bytes
    assinatura: bytes
    deslocamento_manifesto: int
    deslocamento_imagem: int
    deslocamento_realocacoes: int
    tamanho_total: int


def _texto_latin1(valor: object, campo: str, minimo: int, maximo: int) -> str:
    if not isinstance(valor, str):
        raise ErroSadrivers("CAMPO", f"{campo} deve ser texto")
    try:
        bruto = valor.encode("latin-1")
    except UnicodeEncodeError:
        raise ErroSadrivers("CAMPO", f"{campo} não cabe em Latin-1")
    if not minimo <= len(bruto) <= maximo:
        raise ErroSadrivers("CAMPO", f"{campo} deve ter {minimo}..{maximo} bytes")
    for b in bruto:
        if not (0x20 <= b <= 0x7E or 0xA0 <= b <= 0xFF):
            raise ErroSadrivers("CAMPO", f"{campo} tem byte não imprimível")
    return valor


def _texto_ascii(valor: object, campo: str, minimo: int, maximo: int) -> bytes:
    if not isinstance(valor, str):
        raise ErroSadrivers("CAMPO", f"{campo} deve ser texto")
    try:
        bruto = valor.encode("ascii")
    except UnicodeEncodeError:
        raise ErroSadrivers("CAMPO", f"{campo} deve ser ASCII")
    if not minimo <= len(bruto) <= maximo:
        raise ErroSadrivers("CAMPO", f"{campo} deve ter {minimo}..{maximo} bytes")
    return bruto


def _validar_versao(valor: object) -> str:
    if not isinstance(valor, str):
        raise ErroSadrivers("CAMPO", "VERSAO deve ser texto")
    if len(valor.encode("ascii", "ignore")) != len(valor):
        raise ErroSadrivers("CAMPO", "VERSAO deve ser ASCII")
    if len(valor) > 16 or not RE_VERSAO.fullmatch(valor):
        raise ErroSadrivers("CAMPO", "VERSAO deve ser X.Y.Z com partes de 0..9999")
    return valor


def _validar_licenca(valor: object) -> str:
    if not isinstance(valor, str):
        raise ErroSadrivers("CAMPO", "LICENCA deve ser texto")
    if len(valor) > 32 or valor not in LICENCAS:
        raise ErroSadrivers("CAMPO", f"LICENCA não permitida: {valor!r}")
    return valor


def validar_dispositivo(d: Dispositivo) -> None:
    """Confere a entrada de 10 bytes da seção 4."""
    if d.tipo != 1:
        raise ErroSadrivers("CAMPO", "na v1 só existe dispositivo PCI (tipo 1)")
    if d.reservado != 0:
        raise ErroSadrivers("CAMPO", "o byte reservado do dispositivo deve ser 0")
    if d.bandeiras & ~0x07:
        raise ErroSadrivers("CAMPO", "bandeiras do dispositivo têm bit desconhecido")
    if not (d.bandeiras & 0x03):
        raise ErroSadrivers("CAMPO", "o dispositivo precisa casar por classe ou por fabricante")
    if (d.bandeiras & 0x04) and not (d.bandeiras & 0x01):
        raise ErroSadrivers("CAMPO", "interface só pode ser usada junto com classe")
    for campo, valor in (("classe", d.classe), ("subclasse", d.subclasse),
                         ("interface", d.interface)):
        if not 0 <= valor <= 0xFF:
            raise ErroSadrivers("CAMPO", f"{campo} do dispositivo fora de 0..255")
    if not 0 <= d.fabricante <= 0xFFFF or not 0 <= d.modelo <= 0xFFFF:
        raise ErroSadrivers("CAMPO", "fabricante/modelo do dispositivo fora de 0..65535")
    if (d.bandeiras & 0x02) and d.fabricante == 0xFFFF:
        raise ErroSadrivers("CAMPO", "fabricante 0xFFFF não existe; use modelo 0xFFFF como curinga")


def _codificar_dispositivo(d: Dispositivo) -> bytes:
    validar_dispositivo(d)
    return struct.pack("<BBBBBBHH", d.tipo, d.bandeiras, d.classe, d.subclasse,
                       d.interface, d.reservado, d.fabricante, d.modelo)


def _decodificar_dispositivo(bruto: bytes) -> Dispositivo:
    if len(bruto) != 10:
        raise ErroSadrivers("MANIFESTO", "DISPOSITIVO deve ter exatamente 10 bytes")
    tipo, bandeiras, classe, subclasse, interface, reservado, fabricante, modelo = \
        struct.unpack("<BBBBBBHH", bruto)
    d = Dispositivo(bandeiras=bandeiras, classe=classe, subclasse=subclasse,
                    interface=interface, fabricante=fabricante, modelo=modelo,
                    tipo=tipo, reservado=reservado)
    validar_dispositivo(d)
    return d


def validar_manifesto(m: Manifesto, exigir_chave: bool = True) -> None:
    validar_id(m.id, "ID")
    _texto_latin1(m.nome, "NOME", 1, 64)
    _texto_latin1(m.descricao, "DESCRICAO", 1, 256)
    _texto_latin1(m.autor, "AUTOR", 1, 64)
    _validar_versao(m.versao)
    _validar_licenca(m.licenca)
    if m.id_chave or exigir_chave:
        if not isinstance(m.id_chave, (bytes, bytearray)) or len(m.id_chave) != 8:
            raise ErroSadrivers("CAMPO", "ID_DA_CHAVE deve ter 8 bytes")
    _u32(m.entrada, "ENTRADA")
    if not 1 <= len(m.dispositivos) <= MAX_DISPOSITIVOS:
        raise ErroSadrivers("CAMPO", f"o manifesto precisa de 1..{MAX_DISPOSITIVOS} dispositivos")
    for d in m.dispositivos:
        validar_dispositivo(d)
    if len(m.dependencias) > MAX_DEPENDENCIAS:
        raise ErroSadrivers("CAMPO", f"no máximo {MAX_DEPENDENCIAS} dependências")
    for dep in m.dependencias:
        validar_id(dep, "DEPENDENCIA", "DEPENDENCIA")


def _tlv(tag: int, valor: bytes) -> bytes:
    if not 1 <= tag <= 10:
        raise ErroSadrivers("MANIFESTO", f"tag TLV desconhecida: {tag}")
    if len(valor) > 0xFFFF:
        raise ErroSadrivers("MANIFESTO", "valor TLV grande demais")
    return struct.pack("<HH", tag, len(valor)) + valor


def montar_manifesto(m: Manifesto) -> bytes:
    validar_manifesto(m)
    partes: List[bytes] = [
        _tlv(1, _texto_ascii(m.id, "ID", 1, 31)),
        _tlv(2, _texto_latin1(m.nome, "NOME", 1, 64).encode("latin-1")),
        _tlv(3, _texto_latin1(m.descricao, "DESCRICAO", 1, 256).encode("latin-1")),
        _tlv(4, _texto_latin1(m.autor, "AUTOR", 1, 64).encode("latin-1")),
        _tlv(5, _validar_versao(m.versao).encode("ascii")),
        _tlv(6, _validar_licenca(m.licenca).encode("ascii")),
        _tlv(7, bytes(m.id_chave)),
        _tlv(8, struct.pack("<I", m.entrada)),
    ]
    for d in m.dispositivos:
        partes.append(_tlv(9, _codificar_dispositivo(d)))
    for dep in m.dependencias:
        partes.append(_tlv(10, dep.encode("ascii")))
    manifesto = b"".join(partes)
    if not 1 <= len(manifesto) <= MAX_MANIFESTO:
        raise ErroSadrivers("TAMANHO", "manifesto fora de 1..8192 bytes")
    return manifesto


def _ler_cstring(dados: bytes, inicio: int, limite: int, campo: str) -> str:
    if not 0 <= inicio < limite:
        raise ErroUso(f"{campo}: deslocamento de texto fora da tabela")
    fim = dados.find(b"\x00", inicio, limite)
    if fim < 0:
        raise ErroUso(f"{campo}: texto sem terminador")
    try:
        return dados[inicio:fim].decode("ascii")
    except UnicodeDecodeError:
        raise ErroUso(f"{campo}: texto não ASCII")


def ler_manifesto(bruto: bytes) -> Manifesto:
    """Lê e valida o TLV, sem ainda olhar imagem ou realocações."""
    if not isinstance(bruto, (bytes, bytearray)):
        raise ErroSadrivers("MANIFESTO", "manifesto não é uma sequência de bytes")
    bruto = bytes(bruto)
    if not 1 <= len(bruto) <= MAX_MANIFESTO:
        raise ErroSadrivers("TAMANHO", "manifesto fora de 1..8192 bytes")
    entradas: List[Tuple[int, bytes]] = []
    i = 0
    anterior = 0
    while i < len(bruto):
        if len(bruto) - i < 4:
            raise ErroSadrivers("MANIFESTO", "TLV truncado")
        tag, tamanho = struct.unpack_from("<HH", bruto, i)
        i += 4
        if not 1 <= tag <= 10:
            raise ErroSadrivers("MANIFESTO", f"tag TLV desconhecida: {tag}")
        if tag < anterior:
            raise ErroSadrivers("MANIFESTO", "tags TLV fora de ordem")
        if tag == anterior and tag not in (9, 10):
            raise ErroSadrivers("MANIFESTO", f"tag {tag} repetida")
        if tamanho > len(bruto) - i:
            raise ErroSadrivers("MANIFESTO", "valor TLV maior que o manifesto")
        entradas.append((tag, bruto[i:i + tamanho]))
        anterior = tag
        i += tamanho
    if i != len(bruto):
        raise ErroSadrivers("MANIFESTO", "sobrou byte no fim do manifesto")
    contagem: Dict[int, int] = {}
    for tag, _valor in entradas:
        contagem[tag] = contagem.get(tag, 0) + 1
    for tag in range(1, 10):
        if contagem.get(tag, 0) != 1:
            if tag == 9 and contagem.get(9, 0) >= 1:
                continue
            raise ErroSadrivers("MANIFESTO", f"tag obrigatória {tag} ausente ou repetida")
    if contagem.get(9, 0) > MAX_DISPOSITIVOS:
        raise ErroSadrivers("CAMPO", f"no máximo {MAX_DISPOSITIVOS} dispositivos")
    if contagem.get(10, 0) > MAX_DEPENDENCIAS:
        raise ErroSadrivers("CAMPO", f"no máximo {MAX_DEPENDENCIAS} dependências")

    valores: Dict[int, bytes] = {}
    dispositivos: List[Dispositivo] = []
    dependencias: List[str] = []
    for tag, valor in entradas:
        if tag in (9, 10):
            if tag == 9:
                dispositivos.append(_decodificar_dispositivo(valor))
            else:
                try:
                    dep = valor.decode("ascii")
                except UnicodeDecodeError:
                    raise ErroSadrivers("CAMPO", "DEPENDENCIA deve ser ASCII")
                dependencias.append(validar_id(dep, "DEPENDENCIA", "DEPENDENCIA"))
        else:
            valores[tag] = valor

    try:
        id_driver = valores[1].decode("ascii")
    except (KeyError, UnicodeDecodeError):
        raise ErroSadrivers("MANIFESTO", "ID ausente ou não ASCII")
    id_driver = validar_id(id_driver, "ID")
    try:
        nome = valores[2].decode("latin-1")
        descricao = valores[3].decode("latin-1")
        autor = valores[4].decode("latin-1")
        versao = valores[5].decode("ascii")
        licenca = valores[6].decode("ascii")
    except (KeyError, UnicodeDecodeError):
        raise ErroSadrivers("MANIFESTO", "texto obrigatório ausente ou inválido")
    _texto_latin1(nome, "NOME", 1, 64)
    _texto_latin1(descricao, "DESCRICAO", 1, 256)
    _texto_latin1(autor, "AUTOR", 1, 64)
    versao = _validar_versao(versao)
    licenca = _validar_licenca(licenca)
    if len(valores[7]) != 8:
        raise ErroSadrivers("CAMPO", "ID_DA_CHAVE deve ter 8 bytes")
    if len(valores[8]) != 4:
        raise ErroSadrivers("CAMPO", "ENTRADA deve ter 4 bytes")
    entrada = struct.unpack("<I", valores[8])[0]
    m = Manifesto(id=id_driver, nome=nome, descricao=descricao, autor=autor,
                  versao=versao, licenca=licenca, id_chave=valores[7],
                  entrada=entrada, dispositivos=dispositivos,
                  dependencias=dependencias, simbolo_entrada="")
    validar_manifesto(m)
    return m


def _inteiro_campo(tabela: Dict[str, object], chave: str, campo: str,
                   minimo: int, maximo: int, padrao: Optional[int] = None) -> int:
    if chave not in tabela:
        if padrao is not None:
            return padrao
        raise ErroUso(f"{campo}: campo obrigatório")
    valor = tabela[chave]
    if not isinstance(valor, int):
        raise ErroUso(f"{campo}: deve ser inteiro")
    if not minimo <= valor <= maximo:
        raise ErroUso(f"{campo}: fora de {minimo}..{maximo}")
    return valor


def _texto_campo(tabela: Dict[str, object], chave: str, campo: str) -> str:
    if chave not in tabela:
        raise ErroUso(f"{campo}: campo obrigatório")
    valor = tabela[chave]
    if not isinstance(valor, str):
        raise ErroUso(f"{campo}: deve ser texto")
    return valor


def _dispositivo_de_toml(tabela: Dict[str, object]) -> Dispositivo:
    chaves = {"tipo", "classe", "subclasse", "interface",
              "fabricante", "modelo"}
    desconhecidas = set(tabela) - chaves
    if desconhecidas:
        raise ErroUso(f"dispositivo: campo desconhecido: {sorted(desconhecidas)[0]}")
    tipo = _texto_campo(tabela, "tipo", "dispositivo.tipo")
    if tipo != "pci":
        raise ErroUso("dispositivo.tipo: na v1 só existe \"pci\"")
    flags = 0
    classe = subclasse = interface = 0
    tem_classe = "classe" in tabela or "subclasse" in tabela
    if tem_classe:
        classe = _inteiro_campo(tabela, "classe", "dispositivo.classe", 0, 0xFF)
        subclasse = _inteiro_campo(tabela, "subclasse", "dispositivo.subclasse", 0, 0xFF)
        flags |= 0x01
        if "interface" in tabela:
            interface = _inteiro_campo(tabela, "interface", "dispositivo.interface", 0, 0xFF)
            flags |= 0x04
    elif "interface" in tabela:
        raise ErroUso("dispositivo.interface: só pode ser usada junto com classe")
    fabricante = modelo = 0
    if "fabricante" in tabela or "modelo" in tabela:
        fabricante = _inteiro_campo(tabela, "fabricante", "dispositivo.fabricante", 0, 0xFFFF)
        modelo = _inteiro_campo(tabela, "modelo", "dispositivo.modelo", 0, 0xFFFF, 0xFFFF)
        flags |= 0x02
        if fabricante == 0xFFFF:
            raise ErroUso("dispositivo.fabricante: 0xFFFF não é fabricante; o curinga é no modelo")
    if not (flags & 0x03):
        raise ErroUso("dispositivo: declare classe/subclasse ou fabricante/modelo")
    d = Dispositivo(bandeiras=flags, classe=classe, subclasse=subclasse,
                    interface=interface, fabricante=fabricante, modelo=modelo)
    validar_dispositivo(d)
    return d


def ler_manifesto_toml(texto: str, id_chave: bytes = b"") -> Manifesto:
    """Transforma o TOML da seção 12.1 no manifesto do formato."""
    if not isinstance(id_chave, (bytes, bytearray)):
        raise ErroUso("id_chave deve ser bytes")
    if len(id_chave) not in (0, 8):
        raise ErroUso("id_chave deve ter 0 (ainda sem chave) ou 8 bytes")
    if len(texto.encode("utf-8")) > MAX_TOML:
        raise ErroUso(f"manifesto TOML maior que {MAX_TOML} bytes")
    dados = _ler_toml(texto)
    permitidas = {"id", "nome", "descricao", "autor", "versao", "licenca", "entrada"}
    desconhecidas = set(dados.topo) - permitidas
    if desconhecidas:
        raise ErroUso(f"manifesto: campo desconhecido: {sorted(desconhecidas)[0]}")
    for chave in permitidas:
        if chave not in dados.topo:
            raise ErroUso(f"manifesto: campo obrigatório ausente: {chave}")
    id_driver = _texto_campo(dados.topo, "id", "id")
    validar_id(id_driver, "id", "CAMPO")
    nome = _texto_campo(dados.topo, "nome", "nome")
    descricao = _texto_campo(dados.topo, "descricao", "descricao")
    autor = _texto_campo(dados.topo, "autor", "autor")
    versao = _texto_campo(dados.topo, "versao", "versao")
    licenca = _texto_campo(dados.topo, "licenca", "licenca")
    simbolo = _texto_campo(dados.topo, "entrada", "entrada")
    if not RE_SIMBOLO.fullmatch(simbolo):
        raise ErroUso("entrada: nome de símbolo inválido")
    _texto_latin1(nome, "NOME", 1, 64)
    _texto_latin1(descricao, "DESCRICAO", 1, 256)
    _texto_latin1(autor, "AUTOR", 1, 64)
    _validar_versao(versao)
    _validar_licenca(licenca)
    if len(dados.dispositivos) < 1:
        raise ErroUso("manifesto: declare pelo menos um [[dispositivo]]")
    if len(dados.dispositivos) > MAX_DISPOSITIVOS:
        raise ErroUso(f"manifesto: no máximo {MAX_DISPOSITIVOS} dispositivos")
    dispositivos = [_dispositivo_de_toml(t) for t in dados.dispositivos]
    if len(dados.dependencias) > MAX_DEPENDENCIAS:
        raise ErroUso(f"manifesto: no máximo {MAX_DEPENDENCIAS} dependências")
    dependencias: List[str] = []
    for tabela in dados.dependencias:
        desconhecidas = set(tabela) - {"id"}
        if desconhecidas:
            raise ErroUso(f"dependencia: campo desconhecido: {sorted(desconhecidas)[0]}")
        dep = _texto_campo(tabela, "id", "dependencia.id")
        validar_id(dep, "dependencia.id", "DEPENDENCIA")
        if dep == id_driver:
            raise ErroUso("dependencia.id: um driver não pode depender de si mesmo")
        dependencias.append(dep)
    m = Manifesto(id=id_driver, nome=nome, descricao=descricao, autor=autor,
                  versao=versao, licenca=licenca, id_chave=bytes(id_chave),
                  entrada=0, dispositivos=dispositivos,
                  dependencias=dependencias, simbolo_entrada=simbolo)
    # O TOML ainda não tem a chave: ela é calculada na hora de embalar.
    validar_manifesto(m, exigir_chave=False)
    return m


# ------------------------------------------------------------------ ELF32

@dataclass
class SecaoElf:
    indice: int
    nome: str
    tipo: int
    bandeiras: int
    endereco: int
    deslocamento: int
    tamanho: int
    link: int
    info: int
    alinhamento: int
    entrada_tamanho: int
    dados: bytes = b""
    deslocamento_imagem: Optional[int] = None
    deslocamento_bss: Optional[int] = None


@dataclass
class SimboloElf:
    indice: int
    nome: str
    valor: int
    tamanho: int
    info: int
    outro: int
    secao: int
    ligacao: int
    tipo: int
    endereco: Optional[int] = None
    externo: Optional[int] = None
    absoluto: bool = False


@dataclass
class ObjetoElf:
    imagem: bytes
    tamanho_bss: int
    realocacoes: List[Realocacao]
    entrada: int
    simbolos: List[SimboloElf]


SHF_ALLOC = 0x2
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
R_386_32 = 1
R_386_PC32 = 2


def _secao_de_dados(nome: str) -> Optional[str]:
    """Devolve o grupo da seção, ou None se ela não for permitida."""
    if nome == ".text" or nome.startswith(".text."):
        return ".text"
    if nome == ".rodata" or nome.startswith(".rodata."):
        return ".rodata"
    if nome == ".data" or nome.startswith(".data."):
        return ".data"
    return None


def _secao_de_bss(nome: str) -> bool:
    return nome == ".bss" or nome.startswith(".bss.")


def ler_objeto_elf(caminho: os.PathLike, nome_entrada: str) -> ObjetoElf:
    """Lê o objeto ELF32 relocável e devolve a imagem já posicionada.

    Não é um linker: só entende as seções que o formato aceita e as duas
    realocações i386 que a especificação permite.  Qualquer outra coisa é
    recusada antes de gerar um pacote.
    """
    if not RE_SIMBOLO.fullmatch(nome_entrada):
        raise ErroUso("nome do símbolo de entrada inválido")
    dados = _ler_bytes_ate(caminho, MAX_OBJETO, "objeto ELF")
    if len(dados) < 52:
        raise ErroUso("objeto ELF truncado")
    if dados[:4] != b"\x7fELF":
        raise ErroUso("o objeto não é ELF")
    if dados[4] != 1 or dados[5] != 1 or dados[6] != 1:
        raise ErroUso("o objeto deve ser ELF32 little-endian versão 1")
    try:
        (ident, e_type, e_machine, e_version, _e_entry, _e_phoff, e_shoff,
         _e_flags, e_ehsize, _e_phentsize, _e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from("<16sHHIIIIIHHHHHH", dados, 0)
    except struct.error:
        raise ErroUso("cabeçalho ELF truncado")
    if e_type != 1:
        raise ErroUso("o objeto deve ser ELF relocável (ET_REL)")
    if e_machine != 3:
        raise ErroUso("o objeto deve ser i386 (EM_386)")
    if e_version != 1 or e_ehsize != 52:
        raise ErroUso("cabeçalho ELF inválido")
    if e_shentsize != 40 or e_shnum < 2 or e_shnum > 1024:
        raise ErroUso("tabela de seções ELF inválida")
    if e_shstrndx >= e_shnum:
        raise ErroUso("índice do shstrtab inválido")
    if e_shoff + e_shnum * e_shentsize > len(dados):
        raise ErroUso("tabela de seções fora do arquivo")

    secoes: List[SecaoElf] = []
    for i in range(e_shnum):
        pos = e_shoff + i * e_shentsize
        try:
            (nome_off, tipo, flags, endereco, deslocamento, tamanho,
             link, info, alinhamento, entrada_tamanho) = \
                struct.unpack_from("<IIIIIIIIII", dados, pos)
        except struct.error:
            raise ErroUso("seção ELF truncada")
        if tipo != SHT_NOBITS:
            if deslocamento + tamanho > len(dados):
                raise ErroUso("dados de seção ELF fora do arquivo")
            conteudo = dados[deslocamento:deslocamento + tamanho]
        else:
            conteudo = b""
        secoes.append(SecaoElf(i, "", tipo, flags, endereco, deslocamento,
                               tamanho, link, info, alinhamento,
                               entrada_tamanho, conteudo))
    shstr = secoes[e_shstrndx]
    if shstr.tipo != SHT_STRTAB:
        raise ErroUso("shstrtab não é uma tabela de textos")
    for secao in secoes:
        pos = e_shoff + secao.indice * e_shentsize
        nome_off = struct.unpack_from("<I", dados, pos)[0]
        secao.nome = _ler_cstring(shstr.dados, nome_off, len(shstr.dados), "shstrtab")

    # Uma única tabela de símbolos; ela é a dona das realocações.
    symtabs = [s for s in secoes if s.tipo == SHT_SYMTAB]
    if len(symtabs) > 1:
        raise ErroUso("o objeto tem mais de uma tabela de símbolos")
    symtab = symtabs[0] if symtabs else None
    simbolos: List[SimboloElf] = []
    if symtab is not None:
        if symtab.link >= len(secoes) or secoes[symtab.link].tipo != SHT_STRTAB:
            raise ErroUso("tabela de símbolos sem strtab")
        strtab = secoes[symtab.link].dados
        if symtab.entrada_tamanho != 16 or symtab.tamanho % 16:
            raise ErroUso("entrada da tabela de símbolos deve ter 16 bytes")
        for i in range(symtab.tamanho // 16):
            pos = symtab.deslocamento + i * 16
            try:
                nome_off, valor, tamanho, info, outro, shndx = \
                    struct.unpack_from("<IIIBBH", dados, pos)
            except struct.error:
                raise ErroUso("símbolo ELF truncado")
            nome = _ler_cstring(strtab, nome_off, len(strtab), "strtab")
            simbolos.append(SimboloElf(i, nome, valor, tamanho, info,
                                       outro, shndx, info >> 4, info & 0xF))

    # Separa as seções que entram na imagem e confere o resto.
    dados_incluidos: List[SecaoElf] = []
    bss_incluidos: List[SecaoElf] = []
    for secao in secoes[1:]:
        if not (secao.bandeiras & SHF_ALLOC):
            continue
        if secao.tipo == SHT_NOBITS and _secao_de_bss(secao.nome):
            bss_incluidos.append(secao)
        elif secao.tipo == SHT_PROGBITS and _secao_de_dados(secao.nome):
            dados_incluidos.append(secao)
        elif (secao.tipo == SHT_NOTE and secao.nome.startswith(".note")
              and not (secao.bandeiras & 0x4)):
            # O GCC/ld moderno grava notas de propriedades (CET, ABI) com
            # SHF_ALLOC.  São metadados, não código nem dados do módulo; não
            # entram na imagem e não podem ser executáveis.
            continue
        else:
            raise ErroUso(f"seção alocada não suportada: {secao.nome}")

    def conferir_alinhamento(secao: SecaoElf) -> int:
        # sh_addralign precisa ser potência de 2 (ELF) e ter um teto são.
        # Sem o teto, um alinhamento enorme faria o while abaixo andar
        # milhares de vezes só para preencher zero.
        valor = secao.alinhamento or 1
        if valor & (valor - 1) or valor > 4096:
            raise ErroUso(f"alinhamento inválido na seção {secao.nome}")
        return max(16, valor)

    imagem = bytearray()
    for grupo in (".text", ".rodata", ".data"):
        for secao in dados_incluidos:
            if _secao_de_dados(secao.nome) != grupo or secao.tamanho == 0:
                continue
            alinhamento = conferir_alinhamento(secao)
            while len(imagem) % alinhamento:
                imagem.append(0)
            secao.deslocamento_imagem = len(imagem)
            imagem.extend(secao.dados)
    if not 1 <= len(imagem) <= MAX_IMAGEM:
        raise ErroSadrivers("TAMANHO", "imagem fora de 1..131072 bytes")

    # O BSS é contíguo e começa em base_bss.  O alinhamento de cada seção
    # vale para o endereço absoluto base_bss + deslocamento_bss, não só para
    # o deslocamento relativo; o preenchimento necessário entra no tamanho
    # total do BSS.  O carregador zera tudo depois da imagem.
    base_bss = alinhar16(len(imagem))
    tamanho_bss = 0
    for secao in bss_incluidos:
        if secao.tamanho == 0:
            continue
        alinhamento = conferir_alinhamento(secao)
        while (base_bss + tamanho_bss) % alinhamento:
            tamanho_bss += 1
        secao.deslocamento_bss = tamanho_bss
        tamanho_bss += secao.tamanho
    if tamanho_bss > MAX_BSS:
        raise ErroSadrivers("TAMANHO", "BSS fora de 0..65536 bytes")
    if base_bss + tamanho_bss > MAX_CARREGADO:
        raise ErroSadrivers("TAMANHO", "imagem + BSS passam de 192 KiB")
    carregado = base_bss + tamanho_bss

    # Endereço de cada símbolo dentro da área carregada.  Símbolos de seções
    # que não entram na imagem ficam sem endereço; se uma realocação precisar
    # deles, a ferramenta recusa em vez de inventar.
    for simbolo in simbolos:
        if simbolo.indice == 0:
            continue
        if simbolo.secao == SHN_UNDEF:
            if simbolo.nome in SIMBOLOS_EXTERNOS:
                simbolo.externo = SIMBOLOS_EXTERNOS[simbolo.nome]
            elif simbolo.nome:
                raise ErroUso(f" símbolo indefinido não permitido: {simbolo.nome}")
            continue
        if simbolo.secao == SHN_ABS:
            simbolo.absoluto = True
            continue
        if simbolo.secao == SHN_COMMON:
            raise ErroUso(f"símbolo comum não suportado: {simbolo.nome}")
        if not 0 <= simbolo.secao < len(secoes):
            raise ErroUso(f"símbolo com seção inválida: {simbolo.nome}")
        secao = secoes[simbolo.secao]
        if secao.deslocamento_imagem is not None:
            if simbolo.valor > secao.tamanho or \
                    simbolo.valor + simbolo.tamanho > secao.tamanho:
                raise ErroUso(f"símbolo fora da seção: {simbolo.nome}")
            simbolo.endereco = secao.deslocamento_imagem + simbolo.valor
        elif secao.deslocamento_bss is not None:
            if simbolo.valor > secao.tamanho or \
                    simbolo.valor + simbolo.tamanho > secao.tamanho:
                raise ErroUso(f"símbolo fora da seção BSS: {simbolo.nome}")
            simbolo.endereco = base_bss + secao.deslocamento_bss + simbolo.valor
        # Caso contrário, fica sem endereço.  Só é erro se for usado.

    realocacoes: List[Realocacao] = []
    destinos = set()
    vistos_reloc = set()
    # As realocações são aplicadas na imagem já concatenada.  O conjunto
    # abaixo guarda cada byte ocupado por um campo de quatro bytes, para que
    # dois intervalos que se cruzem sejam recusados mesmo quando vêm de
    # tabelas de relocação diferentes.
    ocupados = set()
    for secao_rel in [s for s in secoes if s.tipo in (SHT_REL, SHT_RELA)]:
        if secao_rel.tipo == SHT_RELA:
            raise ErroUso("RELA não é suportado; o i386 usa REL")
        # sh_info é o índice da seção-alvo.  Zero ou fora da tabela é uma
        # tabela de relocações malformada, mesmo quando a seção não entraria
        # na imagem; não pode ser descartada em silêncio.
        if secao_rel.info <= 0 or secao_rel.info >= len(secoes):
            raise ErroUso("relocação com sh_info fora da tabela de seções")
        if secao_rel.entrada_tamanho != 8 or secao_rel.tamanho % 8:
            raise ErroUso("entrada de relocação deve ter 8 bytes")
        if symtab is None or secao_rel.link != symtab.indice:
            raise ErroUso("relocação sem a tabela de símbolos certa")
        alvo = secoes[secao_rel.info]
        if alvo.deslocamento_bss is not None:
            raise ErroUso("não há realocação dentro do BSS")
        if alvo.deslocamento_imagem is None:
            # Seção válida que não entra na imagem (depuração): a tabela é
            # estruturalmente válida, mas não precisa ser percorrida.
            continue
        for i in range(secao_rel.tamanho // 8):
            pos = secao_rel.deslocamento + i * 8
            try:
                deslocamento, info = struct.unpack_from("<II", dados, pos)
            except struct.error:
                raise ErroUso("relocação ELF truncada")
            indice_simbolo = info >> 8
            tipo_rel = info & 0xFF
            if indice_simbolo >= len(simbolos):
                raise ErroUso("relocação aponta para símbolo inexistente")
            if deslocamento + 4 > alvo.tamanho:
                raise ErroSadrivers("REALOCACAO", "relocação fora da seção")
            chave_reloc = (alvo.indice, deslocamento)
            if chave_reloc in vistos_reloc:
                raise ErroSadrivers("REALOCACAO", "duas relocações no mesmo lugar")
            vistos_reloc.add(chave_reloc)
            p = alvo.deslocamento_imagem + deslocamento
            _registrar_intervalo(ocupados, p)
            if tipo_rel not in (R_386_32, R_386_PC32):
                raise ErroUso(f"tipo de relocação não suportado: {tipo_rel}")
            adendo = struct.unpack_from("<i", imagem, p)[0]
            simbolo = simbolos[indice_simbolo]
            if simbolo.externo is not None:
                # O campo guarda o adendo; o carregador soma o endereço do
                # símbolo (tipo 1) ou a diferença dele com o ponto de uso
                # (tipo 2).
                tipo = 1 if tipo_rel == R_386_32 else 2
                if p in destinos:
                    raise ErroSadrivers("REALOCACAO", "duas realocações no mesmo lugar")
                destinos.add(p)
                realocacoes.append(Realocacao(p, tipo, simbolo.externo))
            elif simbolo.endereco is not None:
                s = simbolo.endereco
                if tipo_rel == R_386_32:
                    valor = (s + adendo) & 0xFFFFFFFF
                    # O campo gravado na imagem é o ponteiro efetivo S + A.
                    # O alvo da tabela (S) não basta: um adendo negativo ou
                    # 0xFFFFFFFF poderia deixar a palavra fora da área
                    # carregada, e o carregador somaria base a ela.
                    if s >= carregado or valor >= carregado:
                        raise ErroSadrivers(
                            "REALOCACAO",
                            "ponteiro interno efetivo fora da área carregada")
                    struct.pack_into("<I", imagem, p, valor)
                    if p in destinos:
                        raise ErroSadrivers("REALOCACAO", "duas realocações no mesmo lugar")
                    destinos.add(p)
                    realocacoes.append(Realocacao(p, 0, s))
                else:
                    # Numa referência relativa entre dois pontos da mesma
                    # imagem, o endereço de carga se cancela.
                    valor = (s + adendo - p) & 0xFFFFFFFF
                    struct.pack_into("<I", imagem, p, valor)
            else:
                raise ErroUso(f"relocação para símbolo sem endereço: {simbolo.nome}")
            if len(realocacoes) > MAX_REALOCACOES:
                raise ErroSadrivers("TAMANHO", "mais de 4096 realocações")

    # A entrada é um símbolo definido em código (não em BSS).
    entradas = [s for s in simbolos if s.nome == nome_entrada and s.indice != 0]
    if len(entradas) != 1:
        raise ErroUso(f"o símbolo de entrada {nome_entrada!r} não aparece uma vez")
    entrada_sym = entradas[0]
    if entrada_sym.secao == SHN_UNDEF or entrada_sym.endereco is None:
        raise ErroUso("o símbolo de entrada não está definido em uma seção carregada")
    if entrada_sym.tipo not in (0, 2):       # NOTYPE ou FUNC
        raise ErroUso("o símbolo de entrada não é uma função")
    if not 0 < entrada_sym.secao < len(secoes):
        raise ErroUso("o símbolo de entrada não aponta para uma seção")
    secao_entrada = secoes[entrada_sym.secao]
    if _secao_de_dados(secao_entrada.nome) != ".text" or \
            not (secao_entrada.bandeiras & 0x4):
        raise ErroUso("o símbolo de entrada não está em uma seção .text executável")
    # O início da função precisa estar estritamente dentro da seção que a
    # contém.  O fim exato da seção não é código: aceitá-lo permitiria uma
    # entrada que aponta para a primeira seção seguinte da imagem.
    if entrada_sym.valor >= secao_entrada.tamanho:
        raise ErroUso("o símbolo de entrada está no fim ou fora da seção")
    if entrada_sym.endereco >= len(imagem):
        raise ErroUso("o símbolo de entrada não está na imagem")
    if entrada_sym.endereco < 0:
        raise ErroUso("entrada negativa")

    return ObjetoElf(bytes(imagem), tamanho_bss, realocacoes,
                     entrada_sym.endereco, simbolos)


# ------------------------------------------------------------------ pacote

def montar_pacote(manifesto_tlv: bytes, imagem: bytes, tamanho_bss: int,
                  realocacoes: Sequence[Realocacao], semente: bytes) -> bytes:
    """Monta o contêiner.  O chamador já resolveu o ID_DA_CHAVE no TLV."""
    if not isinstance(manifesto_tlv, (bytes, bytearray)):
        raise ErroUso("manifesto TLV deve ser bytes")
    manifesto_tlv = bytes(manifesto_tlv)
    if not 1 <= len(manifesto_tlv) <= MAX_MANIFESTO:
        raise ErroSadrivers("TAMANHO", "manifesto fora de 1..8192 bytes")
    if not isinstance(imagem, (bytes, bytearray)):
        raise ErroUso("imagem do módulo deve ser bytes")
    imagem = bytes(imagem)
    if not 1 <= len(imagem) <= MAX_IMAGEM:
        raise ErroSadrivers("TAMANHO", "imagem fora de 1..131072 bytes")
    if not 0 <= tamanho_bss <= MAX_BSS:
        raise ErroSadrivers("TAMANHO", "BSS fora de 0..65536 bytes")
    if len(realocacoes) > MAX_REALOCACOES:
        raise ErroSadrivers("TAMANHO", "mais de 4096 realocações")
    carregado = alinhar16(len(imagem)) + tamanho_bss
    if carregado > MAX_CARREGADO:
        raise ErroSadrivers("TAMANHO", "imagem + BSS passam de 192 KiB")
    vistos = set()
    ocupados = set()
    for r in realocacoes:
        if not 0 <= r.deslocamento <= 0xFFFFFFFF:
            raise ErroSadrivers("REALOCACAO", "deslocamento de realocação inválido")
        if r.deslocamento + 4 > len(imagem):
            raise ErroSadrivers("REALOCACAO", "realocação fora da imagem")
        if r.deslocamento in vistos:
            raise ErroSadrivers("REALOCACAO", "duas realocações no mesmo lugar")
        vistos.add(r.deslocamento)
        _registrar_intervalo(ocupados, r.deslocamento)
        if r.tipo not in (0, 1, 2):
            raise ErroSadrivers("REALOCACAO", "tipo de realocação inválido")
        if r.tipo == 0:
            if not 0 <= r.alvo < carregado:
                raise ErroSadrivers("REALOCACAO", "alvo interno fora da área carregada")
            valor_efetivo = struct.unpack_from("<I", imagem, r.deslocamento)[0]
            if valor_efetivo >= carregado:
                raise ErroSadrivers(
                    "REALOCACAO", "ponteiro interno efetivo fora da área carregada")
        elif not 1 <= r.alvo <= 3:
            raise ErroSadrivers("REALOCACAO", "símbolo externo desconhecido")
        if r.alvo >= (1 << 30):
            raise ErroSadrivers("REALOCACAO", "alvo não cabe nos 30 bits")

    deslocamento_imagem = TAMANHO_CABECALHO + alinhar16(len(manifesto_tlv))
    deslocamento_realocacoes = deslocamento_imagem + alinhar16(len(imagem))
    total = deslocamento_realocacoes + alinhar16(len(realocacoes) * 8) + TAMANHO_ASSINATURA
    if not TAMANHO_MINIMO <= total <= MAX_PACOTE:
        raise ErroSadrivers("TAMANHO", "pacote fora de 176..262144 bytes")
    if total % 16:
        raise ErroSadrivers("LAYOUT", "tamanho total não é múltiplo de 16")

    pacote = bytearray(total)
    pacote[:8] = MAGIC
    struct.pack_into("<IIIIIIIIHHI", pacote, 8, total, TAMANHO_CABECALHO,
                     len(manifesto_tlv), deslocamento_imagem, len(imagem),
                     tamanho_bss, deslocamento_realocacoes, len(realocacoes),
                     ABI_VERSAO, ARQUITETURA_X86, 0)
    pacote[TAMANHO_CABECALHO:TAMANHO_CABECALHO + len(manifesto_tlv)] = manifesto_tlv
    pacote[deslocamento_imagem:deslocamento_imagem + len(imagem)] = imagem
    for i, r in enumerate(realocacoes):
        struct.pack_into("<II", pacote, deslocamento_realocacoes + i * 8,
                         r.deslocamento, (r.tipo << 30) | r.alvo)
    # O resumo cobre [0,48) do cabeçalho e todo o corpo até a assinatura.
    resumo = hashlib.sha256(pacote[:48] + pacote[80:total - TAMANHO_ASSINATURA]).digest()
    pacote[48:80] = resumo
    assinatura = ed25519_assinar(semente, resumo)
    if len(assinatura) != TAMANHO_ASSINATURA:
        raise ErroUso("falha interna: assinatura com tamanho errado")
    pacote[total - TAMANHO_ASSINATURA:total] = assinatura
    return bytes(pacote)


def empacotar(manifesto: Manifesto, imagem: bytes, tamanho_bss: int,
              realocacoes: Sequence[Realocacao], semente: bytes) -> Tuple[bytes, Manifesto]:
    publica = ed25519_chave_publica(semente)
    manifesto = replace(manifesto, id_chave=_id_da_chave(publica))
    tlv = montar_manifesto(manifesto)
    pacote = montar_pacote(tlv, imagem, tamanho_bss, realocacoes, semente)
    # Autoconferência: se a ferramenta gerou um pacote que ela mesma recusa,
    # o erro aparece no build, não só no kernel.
    analisar_pacote(pacote, publica)
    return pacote, manifesto


def _ler_campo_header(dados: bytes) -> Tuple[int, int, int, int, int, int, int, int, int, int, int]:
    return struct.unpack_from("<IIIIIIIIHHI", dados, 8)


def analisar_pacote(dados: bytes, chave_publica: Optional[bytes] = None) -> Pacote:
    """Valida o pacote na ordem da seção 9 e devolve os campos."""
    if not isinstance(dados, (bytes, bytearray)):
        raise ErroSadrivers("TAMANHO", "pacote não é uma sequência de bytes")
    dados = bytes(dados)
    total_arquivo = len(dados)
    if total_arquivo < TAMANHO_MINIMO or total_arquivo > MAX_PACOTE or total_arquivo % 16:
        raise ErroSadrivers(
            "TAMANHO",
            "tamanho do pacote fora de 176..262144 ou não múltiplo de 16")
    if dados[:8] != MAGIC:
        raise ErroSadrivers("ASSINATURA", "magic do pacote não confere")
    (total, deslocamento_manifesto, tamanho_manifesto, deslocamento_imagem,
     tamanho_imagem, tamanho_bss, deslocamento_realocacoes,
     quantidade_realocacoes, versao_abi, arquitetura, bandeiras) = \
        _ler_campo_header(dados)
    if total != total_arquivo:
        raise ErroSadrivers("TAMANHO", "tamanho_total não é o tamanho do arquivo")
    if deslocamento_manifesto != TAMANHO_CABECALHO:
        raise ErroSadrivers("LAYOUT", "o manifesto deve começar em 80")
    if not 1 <= tamanho_manifesto <= MAX_MANIFESTO:
        raise ErroSadrivers("TAMANHO", "tamanho do manifesto fora de 1..8192")
    if deslocamento_imagem != TAMANHO_CABECALHO + alinhar16(tamanho_manifesto):
        raise ErroSadrivers("LAYOUT", "deslocamento da imagem não segue o layout")
    if not 1 <= tamanho_imagem <= MAX_IMAGEM:
        raise ErroSadrivers("TAMANHO", "tamanho da imagem fora de 1..131072")
    if not 0 <= tamanho_bss <= MAX_BSS:
        raise ErroSadrivers("TAMANHO", "tamanho do BSS fora de 0..65536")
    if deslocamento_realocacoes != deslocamento_imagem + alinhar16(tamanho_imagem):
        raise ErroSadrivers("LAYOUT", "deslocamento das realocações não segue o layout")
    if not 0 <= quantidade_realocacoes <= MAX_REALOCACOES:
        raise ErroSadrivers("TAMANHO", "quantidade de realocações fora de 0..4096")
    total_esperado = deslocamento_realocacoes + \
        alinhar16(quantidade_realocacoes * 8) + TAMANHO_ASSINATURA
    if total_esperado != total:
        raise ErroSadrivers("LAYOUT", "tamanho total não segue o layout")
    if alinhar16(tamanho_imagem) + tamanho_bss > MAX_CARREGADO:
        raise ErroSadrivers("TAMANHO", "imagem + BSS passam de 192 KiB")

    fim_manifesto = TAMANHO_CABECALHO + tamanho_manifesto
    fim_imagem = deslocamento_imagem + tamanho_imagem
    fim_relocacoes = deslocamento_realocacoes + quantidade_realocacoes * 8
    fim_corpo = total - TAMANHO_ASSINATURA
    if not _zeros(dados, fim_manifesto, deslocamento_imagem):
        raise ErroSadrivers("LAYOUT", "preenchimento do manifesto não é zero")
    if not _zeros(dados, fim_imagem, deslocamento_realocacoes):
        raise ErroSadrivers("LAYOUT", "preenchimento da imagem não é zero")
    if not _zeros(dados, fim_relocacoes, fim_corpo):
        raise ErroSadrivers("LAYOUT", "preenchimento das realocações não é zero")
    if versao_abi != ABI_VERSAO or arquitetura != ARQUITETURA_X86 or bandeiras != 0:
        raise ErroSadrivers("VERSAO", "ABI, arquitetura ou bandeiras não suportadas")

    resumo_gravado = dados[48:80]
    resumo_calculado = hashlib.sha256(dados[:48] + dados[80:fim_corpo]).digest()
    if not hmac.compare_digest(resumo_gravado, resumo_calculado):
        raise ErroSadrivers("RESUMO", "SHA-256 do pacote não confere")
    assinatura = dados[fim_corpo:total]
    if chave_publica is not None:
        if not isinstance(chave_publica, (bytes, bytearray)):
            raise ErroUso("a chave pública Ed25519 deve ser bytes")
        chave_publica = bytes(chave_publica)
        if len(chave_publica) != 32:
            raise ErroUso("a chave pública Ed25519 deve ter 32 bytes")
        if not ed25519_verificar(chave_publica, resumo_gravado, assinatura):
            raise ErroSadrivers("ASSINATURA_CRIPTO", "assinatura Ed25519 não confere")

    manifesto_tlv = dados[TAMANHO_CABECALHO:fim_manifesto]
    manifesto = ler_manifesto(manifesto_tlv)
    if chave_publica is not None:
        if manifesto.id_chave != _id_da_chave(chave_publica):
            raise ErroSadrivers("CHAVE", "ID_DA_CHAVE não é o da chave que assinou")
    if manifesto.entrada >= tamanho_imagem:
        raise ErroSadrivers("CAMPO", "ENTRADA fora da imagem")

    imagem = dados[deslocamento_imagem:fim_imagem]
    carregado = alinhar16(tamanho_imagem) + tamanho_bss
    realocacoes: List[Realocacao] = []
    vistos = set()
    ocupados = set()
    for i in range(quantidade_realocacoes):
        deslocamento, alvo = struct.unpack_from("<II", dados,
                                                deslocamento_realocacoes + i * 8)
        tipo = alvo >> 30
        valor = alvo & 0x3FFFFFFF
        if deslocamento + 4 > tamanho_imagem:
            raise ErroSadrivers("REALOCACAO", "deslocamento de realocação inválido")
        if deslocamento in vistos:
            raise ErroSadrivers("REALOCACAO", "deslocamento de realocação repetido")
        vistos.add(deslocamento)
        _registrar_intervalo(ocupados, deslocamento)
        if tipo not in (0, 1, 2):
            raise ErroSadrivers("REALOCACAO", "tipo de realocação reservado ou desconhecido")
        if tipo == 0:
            if valor >= carregado:
                raise ErroSadrivers("REALOCACAO", "alvo interno fora da área carregada")
            valor_efetivo = struct.unpack_from("<I", imagem, deslocamento)[0]
            if valor_efetivo >= carregado:
                raise ErroSadrivers(
                    "REALOCACAO", "ponteiro interno efetivo fora da área carregada")
        elif not 1 <= valor <= 3:
            raise ErroSadrivers("REALOCACAO", "símbolo externo fora de 1..3")
        realocacoes.append(Realocacao(deslocamento, tipo, valor))

    for dep in manifesto.dependencias:
        if dep == manifesto.id:
            raise ErroSadrivers("DEPENDENCIA", "um driver não pode depender de si mesmo")

    return Pacote(dados=dados, manifesto=manifesto,
                  manifesto_tlv=manifesto_tlv, imagem=imagem,
                  tamanho_bss=tamanho_bss, realocacoes=realocacoes,
                  resumo=resumo_gravado, assinatura=assinatura,
                  deslocamento_manifesto=deslocamento_manifesto,
                  deslocamento_imagem=deslocamento_imagem,
                  deslocamento_realocacoes=deslocamento_realocacoes,
                  tamanho_total=total)


# ------------------------------------------------------------------ chaves

def ler_chave_privada(caminho: os.PathLike) -> bytes:
    return _ler_chave(caminho, "privada")


def ler_chave_publica(caminho: os.PathLike) -> bytes:
    return _ler_chave(caminho, "pública")


def _ler_chave(caminho: os.PathLike, tipo: str) -> bytes:
    try:
        bruto = _ler_bytes_ate(caminho, MAX_CHAVE, f"chave {tipo}")
        texto = bruto.decode("ascii")
    except UnicodeDecodeError:
        raise ErroUso(f"a chave {tipo} deve ser ASCII")
    linhas = []
    for linha in texto.splitlines():
        linha = linha.split("#", 1)[0].strip()
        if not linha:
            continue
        linhas.append(linha)
    if len(linhas) != 1:
        raise ErroUso(f"o arquivo da chave {tipo} deve ter uma linha de 64 dígitos hex")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", linhas[0]):
        raise ErroUso(f"a chave {tipo} deve ter 64 dígitos hexadecimais")
    bruto = bytes.fromhex(linhas[0])
    if len(bruto) != 32:
        raise ErroUso(f"a chave {tipo} deve ter 32 bytes")
    return bruto


def gerar_chave_privada(saida: os.PathLike, forcar: bool = False) -> bytes:
    destino = Path(saida)
    destino.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(destino) and not forcar:
        raise ErroUso(f"o arquivo {destino} já existe; use --forcar para substituir")
    if os.path.lexists(destino) and destino.is_symlink():
        # Mesmo com --forcar, não seguimos link simbólico.  O os.replace de um
        # link até substituiria o link, mas recusar é mais simples de auditar.
        raise ErroUso(f"o destino {destino} é um link simbólico; recusado")
    if os.path.lexists(destino) and destino.is_dir():
        raise ErroUso(f"o destino {destino} é uma pasta")
    semente = secrets.token_bytes(32)
    texto = ("# Chave privada Ed25519 do SaguiOS (semente de 32 bytes).\n"
             "# NAO COMMITAR. Gerada por tools/sadrivers.py.\n"
             + semente.hex() + "\n").encode("ascii")
    if not os.path.lexists(destino):
        _gravar_novo(destino, texto)
    else:
        # Sobrescrita só com --forcar.  O temporário é criado de forma
        # exclusiva e com 0600; os.replace troca o nome de uma vez e não
        # escreve dentro do arquivo antigo.
        temporario = destino.with_name(
            destino.name + ".tmp." + secrets.token_hex(8))
        try:
            _gravar_novo(temporario, texto)
            os.replace(temporario, destino)
        finally:
            try:
                if os.path.lexists(temporario):
                    os.unlink(temporario)
            except OSError:
                pass
    try:
        # O arquivo já foi criado com 0600 e fchmod no descritor; este chmod é
        # só uma segunda tentativa em sistemas que ignoram o modo do open.
        # follow_symlinks=False impede que uma troca por link, entre a criação
        # e esta linha, mude as permissões de um arquivo fora da pasta.
        os.chmod(destino, 0o600, follow_symlinks=False)
    except (OSError, NotImplementedError):
        pass
    return semente


def escrever_chave_publica_c(publica: bytes, destino: os.PathLike) -> None:
    if len(publica) != 32:
        raise ErroUso("a chave pública Ed25519 deve ter 32 bytes")
    id_chave = _id_da_chave(publica).hex()
    linhas = [
        "/* chave-publica.c - chave publica Ed25519 reconhecida pelo SaguiOS.",
        " * Gerada por tools/sadrivers.py; nao edite a mao.",
        f" * ID_DA_CHAVE: {id_chave}",
        " * A semente privada nao e distribuida; a chave reconhecida e esta. */",
        "const unsigned char sadrv_chave_publica[32] = {",
    ]
    for i in range(0, 32, 8):
        pedaco = ", ".join(f"0x{b:02x}" for b in publica[i:i + 8])
        linhas.append("    " + pedaco + ("," if i + 8 < 32 else ""))
    linhas.append("};")
    linhas.append("")
    destino = Path(destino)
    try:
        existente = os.lstat(destino)
    except FileNotFoundError:
        existente = None
    except OSError as erro:
        raise ErroUso(f"não foi possível examinar o destino {destino}: {erro}")
    if existente is not None:
        if stat.S_ISLNK(existente.st_mode):
            raise ErroUso(f"o destino {destino} é um link simbólico; recusado")
        if not stat.S_ISREG(existente.st_mode):
            raise ErroUso(f"o destino {destino} não é um arquivo regular")
    # O arquivo regular, se já existia, é substituído só no os.replace final.
    # Um link plantado depois deste lstat também não é seguido: os.replace
    # troca o próprio nome do link, não o alvo.
    try:
        _gravar_atomico(destino, ("\n".join(linhas)).encode("ascii"))
    except ErroUso:
        raise
    except OSError as erro:
        raise ErroUso(f"não foi possível gravar {destino}: {erro}")


# ------------------------------------------------------------------ descrição

def descrever_manifesto(m: Manifesto) -> str:
    linhas = [
        f"ID: {m.id}",
        f"NOME: {m.nome}",
        f"DESCRICAO: {m.descricao}",
        f"AUTOR: {m.autor}",
        f"VERSAO: {m.versao}",
        f"LICENCA: {m.licenca}",
        f"ID_DA_CHAVE: {m.id_chave.hex()}",
        f"ENTRADA: 0x{m.entrada:08x}",
        "DISPOSITIVOS:",
    ]
    for d in m.dispositivos:
        linhas.append("  " + (f"tipo=pci bandeiras=0x{d.bandeiras:02x} "
                              f"classe=0x{d.classe:02x} subclasse=0x{d.subclasse:02x} "
                              f"interface=0x{d.interface:02x} "
                              f"fabricante=0x{d.fabricante:04x} modelo=0x{d.modelo:04x}"))
    if m.dependencias:
        linhas.append("DEPENDENCIAS:")
        for dep in m.dependencias:
            linhas.append(f"  {dep}")
    else:
        linhas.append("DEPENDENCIAS: nenhuma")
    return "\n".join(linhas)


def descrever_pacote(p: Pacote, chave_conferida: bool) -> str:
    linhas = [
        f"Tamanho: {p.tamanho_total} bytes",
        "Formato: 1 (experimental)",
        f"ABI: {ABI_VERSAO}",
        "Arquitetura: x86 (1)",
        "Bandeiras: 0",
        f"Resumo SHA-256: {p.resumo.hex()}",
        f"Assinatura Ed25519: {len(p.assinatura)} bytes "
        + ("(conferida)" if chave_conferida else "(não conferida: sem chave)"),
        f"Manifesto: {p.deslocamento_manifesto}.."
        f"{p.deslocamento_manifesto + len(p.manifesto_tlv)}",
        f"Imagem: {len(p.imagem)} bytes em 0x{p.deslocamento_imagem:x}",
        f"BSS: {p.tamanho_bss} bytes",
        f"Realocações: {len(p.realocacoes)}",
        "",
        descrever_manifesto(p.manifesto),
    ]
    if p.realocacoes:
        linhas.append("")
        linhas.append("REALOCACOES:")
        for r in p.realocacoes:
            linhas.append(f"  0x{r.deslocamento:08x} tipo={r.tipo} alvo=0x{r.alvo:08x}")
    return "\n".join(linhas)


# ------------------------------------------------------------------ comandos

def _abrir_arquivo_regular(caminho: Path, descricao: str) -> int:
    """Abre um arquivo regular para leitura sem aceitar link simbólico.

    O ``lstat`` recusa o link antes do ``open``.  No POSIX, ``O_NOFOLLOW``
    fecha a janela entre os dois passos; no Windows essa flag não existe, então
    a conferência anterior é o que a plataforma permite.  Depois do ``open``,
    ``fstat`` confere o descritor e compara o inode com o do ``lstat`` quando
    os dois estão disponíveis.  Isso reduz a troca do arquivo no meio do
    caminho, mas não vira uma garantia que o Windows não oferece.

    Um caminho inexistente continua levantando ``FileNotFoundError``; quem
    chama decide se isso é "ausente" ou erro.
    """
    try:
        antes = os.lstat(caminho)
    except FileNotFoundError:
        raise
    except OSError as erro:
        raise ErroUso(f"não foi possível examinar {descricao} {caminho}: {erro}")
    if stat.S_ISLNK(antes.st_mode):
        raise ErroUso(f"o {descricao} {caminho} é um link simbólico; recusado")
    if not stat.S_ISREG(antes.st_mode):
        raise ErroUso(f"o {descricao} {caminho} não é um arquivo regular")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descritor = os.open(caminho, flags)
    except FileNotFoundError:
        # Sumiu entre o lstat e o open; quem chama trata como "ausente".
        raise
    except OSError as erro:
        raise ErroUso(f"não foi possível abrir {descricao} {caminho}: {erro}")
    try:
        depois = os.fstat(descritor)
        if not stat.S_ISREG(depois.st_mode):
            raise ErroUso(f"o {descricao} {caminho} não é um arquivo regular")
        if (antes.st_ino and depois.st_ino and
                (antes.st_dev, antes.st_ino) != (depois.st_dev, depois.st_ino)):
            raise ErroUso(
                f"o {descricao} {caminho} mudou durante a abertura; recusado")
    except BaseException:
        os.close(descritor)
        raise
    return descritor


def _ler_arquivo_pacote(caminho: os.PathLike) -> bytes:
    caminho = Path(caminho)
    descritor = _abrir_arquivo_regular(caminho, "arquivo de pacote")
    try:
        arquivo = os.fdopen(descritor, "rb")
    except BaseException:
        os.close(descritor)
        raise
    try:
        with arquivo:
            dados = arquivo.read(MAX_PACOTE + 1)
    except OSError as erro:
        raise ErroUso(f"não foi possível ler {caminho}: {erro}")
    if len(dados) > MAX_PACOTE:
        raise ErroSadrivers("TAMANHO", f"arquivo de pacote maior que {MAX_PACOTE} bytes")
    return dados


def _flags_de_criacao_exclusiva() -> int:
    """Flags para criar um arquivo novo sem seguir link simbólico.

    O_EXCL já recusa um caminho existente, inclusive um link simbólico; o
    O_NOFOLLOW, quando existe, fecha a janela entre a conferência e o open.
    O_BINARY é do Windows; nos outros sistemas não existe.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _abrir_novo(caminho: Path) -> int:
    if os.path.lexists(caminho):
        raise ErroUso(f"o arquivo {caminho} já existe; não sobrescrevo")
    try:
        descritor = os.open(caminho, _flags_de_criacao_exclusiva(), 0o600)
    except FileExistsError:
        raise ErroUso(f"o arquivo {caminho} já existe; não sobrescrevo")
    except OSError as erro:
        raise ErroUso(f"não foi possível criar {caminho}: {erro}")
    # A máscara do processo pode ter tirado permissões; fchmod garante 0600
    # no POSIX.  No Windows não há esse controle fino (ver docs).
    if hasattr(os, "fchmod"):
        try:
            os.fchmod(descritor, 0o600)
        except OSError:
            pass
    return descritor


def _gravar_novo(caminho: Path, dados: bytes) -> None:
    """Cria um arquivo exclusivo e grava ``dados``.

    Se a escrita falhar, o arquivo corrente é apagado antes de o erro subir;
    a extração mantém a lista dos arquivos que já ficaram completos para
    desfazer a operação inteira.
    """
    descritor = _abrir_novo(caminho)
    try:
        arquivo = os.fdopen(descritor, "wb")
    except BaseException:
        try:
            os.close(descritor)
        except OSError:
            pass
        try:
            os.unlink(caminho)
        except OSError:
            pass
        raise
    try:
        with arquivo:
            arquivo.write(dados)
    except BaseException:
        try:
            os.unlink(caminho)
        except OSError:
            pass
        raise


def _gravar_atomico(destino: Path, dados: bytes) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    temporario = destino.with_name(
        destino.name + ".tmp." + secrets.token_hex(8))
    try:
        _gravar_novo(temporario, dados)
        os.replace(temporario, destino)
    finally:
        try:
            if os.path.lexists(temporario):
                os.unlink(temporario)
        except OSError:
            pass


def comando_embalar(args: argparse.Namespace) -> int:
    objeto = Path(args.objeto)
    manifesto_path = Path(args.manifesto)
    chave_path = Path(args.chave)
    saida = Path(args.saida)
    try:
        texto = _ler_bytes_ate(manifesto_path, MAX_TOML, "manifesto TOML").decode("utf-8")
        manifesto = ler_manifesto_toml(texto)
        objeto_lido = ler_objeto_elf(objeto, manifesto.simbolo_entrada)
        manifesto = replace(manifesto, entrada=objeto_lido.entrada)
        semente = ler_chave_privada(chave_path)
        publica = ed25519_chave_publica(semente)
    except ErroSadrivers as erro:
        # Ainda não existe pacote: um manifesto/objeto que a ferramenta não
        # entende é erro de entrada (código 2), não pacote inválido (código 1).
        raise ErroUso(f"entrada inválida: {erro}")
    if saida.name != manifesto.id + ".sadrivers":
        raise ErroUso(f"o nome do arquivo deve ser {manifesto.id}.sadrivers")
    pacote, manifesto = empacotar(manifesto, objeto_lido.imagem,
                                  objeto_lido.tamanho_bss,
                                  objeto_lido.realocacoes, semente)
    _gravar_atomico(saida, pacote)
    print(f"pacote: {saida}")
    print(f"ID: {manifesto.id}")
    print(f"ID_DA_CHAVE: {manifesto.id_chave.hex()} "
          f"(chave pública {publica.hex()})")
    print(f"tamanho: {len(pacote)} bytes; imagem: {len(objeto_lido.imagem)} bytes; "
          f"BSS: {objeto_lido.tamanho_bss}; realocações: {len(objeto_lido.realocacoes)}")
    return 0


def comando_inspecionar(args: argparse.Namespace) -> int:
    pacote = analisar_pacote(_ler_arquivo_pacote(args.pacote))
    print(f"Arquivo: {args.pacote}")
    print(descrever_pacote(pacote, False))
    return 0


def comando_verificar(args: argparse.Namespace) -> int:
    dados = _ler_arquivo_pacote(args.pacote)
    if args.chave_publica:
        publica = ler_chave_publica(args.chave_publica)
        pacote = analisar_pacote(dados, publica)
        print(f"pacote válido: {pacote.manifesto.id} {pacote.manifesto.versao}")
        print(f"assinatura Ed25519 conferida com a chave {pacote.manifesto.id_chave.hex()}")
    else:
        pacote = analisar_pacote(dados)
        print(f"pacote válido: {pacote.manifesto.id} {pacote.manifesto.versao}")
        print("estrutura e SHA-256 conferidos; assinatura NÃO conferida "
              "(nenhuma --chave-publica informada)")
    return 0


def _preparar_pasta_de_extracao(pasta: Path) -> None:
    if os.path.lexists(pasta):
        if pasta.is_symlink():
            raise ErroUso(f"a pasta de extração {pasta} é um link simbólico")
        if not pasta.is_dir():
            raise ErroUso(f"o destino {pasta} não é uma pasta")
        return
    try:
        pasta.mkdir(parents=True)
    except OSError as erro:
        raise ErroUso(f"não foi possível criar a pasta {pasta}: {erro}")
    if pasta.is_symlink():
        raise ErroUso(f"a pasta de extração {pasta} é um link simbólico")


def comando_extrair(args: argparse.Namespace) -> int:
    pacote = analisar_pacote(_ler_arquivo_pacote(args.pacote))
    pasta = Path(args.pasta)
    _preparar_pasta_de_extracao(pasta)
    conteudos = {
        "manifesto.tlv": pacote.manifesto_tlv,
        "manifesto.txt": (descrever_manifesto(pacote.manifesto) + "\n").encode("utf-8"),
        "imagem.bin": pacote.imagem,
        "bss.bin": b"\x00" * pacote.tamanho_bss,
        "resumo.bin": pacote.resumo,
        "assinatura.bin": pacote.assinatura,
    }
    linhas = [f"0x{r.deslocamento:08x} {r.tipo} 0x{r.alvo:08x}"
              for r in pacote.realocacoes]
    conteudos["realocacoes.txt"] = (
        "\n".join(linhas) + ("\n" if linhas else "")).encode("ascii")
    # Confere todos antes de criar o primeiro: se algum nome já existia, nada
    # é escrito.  A criação em si também é exclusiva (O_EXCL), para o caso de
    # alguém trocar um nome por link simbólico entre as duas etapas.
    for nome in conteudos:
        if os.path.lexists(pasta / nome):
            raise ErroUso(f"o arquivo {pasta / nome} já existe; não sobrescrevo")
    criados: List[Path] = []
    try:
        for nome, dados in conteudos.items():
            caminho = pasta / nome
            _gravar_novo(caminho, dados)
            criados.append(caminho)
    except BaseException:
        # _gravar_novo já apaga o arquivo corrente quando a escrita dele
        # falha; aqui desfazemos os que ficaram completos antes do erro.
        for caminho in reversed(criados):
            try:
                os.unlink(caminho)
            except OSError:
                pass
        raise
    print(f"extraído em: {pasta}")
    return 0


def comando_gerar_chave(args: argparse.Namespace) -> int:
    semente = gerar_chave_privada(args.saida, args.forcar)
    publica = ed25519_chave_publica(semente)
    print(f"chave privada: {args.saida}")
    print(f"chave pública: {publica.hex()}")
    print(f"ID_DA_CHAVE: {_id_da_chave(publica).hex()}")
    return 0


def comando_chave_publica(args: argparse.Namespace) -> int:
    semente = ler_chave_privada(args.chave)
    publica = ed25519_chave_publica(semente)
    if args.c:
        escrever_chave_publica_c(publica, args.c)
        print(f"chave pública C: {args.c}")
        print(f"ID_DA_CHAVE: {_id_da_chave(publica).hex()}")
    else:
        print(publica.hex())
    return 0


def comando_fingerprint(args: argparse.Namespace) -> int:
    publica = ler_chave_publica(args.chave)
    print(f"ID_DA_CHAVE: {_id_da_chave(publica).hex()}")
    print(f"SHA-256: {hashlib.sha256(publica).hexdigest()}")
    return 0


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sadrivers.py",
        description="Monta, lê e confere pacotes .sadrivers (formato 0.1).")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("embalar", help="monta um pacote a partir de ELF + TOML")
    p.add_argument("--objeto", required=True, help="objeto ELF32 i386 relocável")
    p.add_argument("--manifesto", required=True, help="manifesto TOML")
    p.add_argument("--chave", required=True, help="chave privada Ed25519")
    p.add_argument("--saida", required=True, help="arquivo <ID>.sadrivers")
    p.set_defaults(funcao=comando_embalar)

    p = sub.add_parser("inspecionar", help="mostra o manifesto e as realocações")
    p.add_argument("pacote")
    p.set_defaults(funcao=comando_inspecionar)

    p = sub.add_parser("verificar", help="confere estrutura, resumo e assinatura")
    p.add_argument("pacote")
    p.add_argument("--chave-publica", help="chave pública Ed25519 (64 hex)")
    p.set_defaults(funcao=comando_verificar)

    p = sub.add_parser("extrair", help="separa manifesto, imagem e assinatura")
    p.add_argument("pacote")
    p.add_argument("--pasta", required=True)
    p.set_defaults(funcao=comando_extrair)

    p = sub.add_parser("gerar-chave", help="gera uma semente Ed25519")
    p.add_argument("--saida", required=True)
    p.add_argument("--forcar", action="store_true",
                   help="substitui um arquivo que já exista")
    p.set_defaults(funcao=comando_gerar_chave)

    p = sub.add_parser("chave-publica", help="deriva a chave pública da semente")
    p.add_argument("chave")
    p.add_argument("--c", help="grava um arquivo C com o vetor de 32 bytes")
    p.set_defaults(funcao=comando_chave_publica)

    p = sub.add_parser("fingerprint", help="mostra o ID_DA_CHAVE de uma chave pública")
    p.add_argument("chave")
    p.set_defaults(funcao=comando_fingerprint)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    try:
        return args.funcao(args)
    except ErroSadrivers as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except ErroUso as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2
    except FileNotFoundError as erro:
        print(f"erro: arquivo não encontrado: {erro.filename}", file=sys.stderr)
        return 2
    except (UnicodeError, struct.error) as erro:
        print(f"erro: entrada ilegível: {erro}", file=sys.stderr)
        return 2
    except OSError as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
