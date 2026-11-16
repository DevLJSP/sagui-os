# Formato `.sadrivers` e ABI de driver — especificação preliminar

**Versão do documento:** 0.1 (experimental, para revisão).
**Versão do formato:** 1 (byte 5 do `magic`, depois de `SADRV`).
**Versão do ABI:** 1.
**Estado:** a ferramenta da H91 (`tools/sadrivers.py`) está implementada e
passou nos testes de host com objetos ELF sintéticos e com um módulo C real
compilado por GCC e ligado com `ld -r`; o carregador do kernel, a verificação no
boot e o módulo real ainda **não** existem. O formato continua experimental
0.1: a versão 1.0 só existe depois que a ferramenta e o carregador passarem nos
testes de conformidade e no QEMU.
**Documento irmão:** `docs/rfc-drivers.md` (o porquê, o problema e os riscos).

As palavras **deve**, **não deve**, **pode** e **obrigatório** têm o sentido da
RFC 2119. Tudo é little-endian, como o x86. Os inteiros sem sinal são `u8`,
`u16` e `u32`; não há campo de 64 bits no formato.

## 1. Visão geral

Um pacote `.sadrivers` é um contêiner fechado, com tamanho e conteúdo
conferidos antes de qualquer código rodar:

```
┌──────────────┬───────────────────┬──────────────────┬───────────────┬────────────┐
│ cabeçalho    │ manifesto (TLV)   │ imagem           │ realocações   │ assinatura │
│ 80 bytes     │ até 8 KiB         │ até 128 KiB      │ 8 bytes cada  │ 64 bytes   │
└──────────────┴───────────────────┴──────────────────┴───────────────┴────────────┘
       │                │                  │                 │              │
       │  SHA-256 cobre os campos do cabeçalho (menos o próprio resumo)     │
       │                └──────────────────┴─────────────────┴──────────────┘
       │                          e todo o corpo até a assinatura
       └──────────────────────────── Ed25519 assina os 32 bytes do resumo ───┘
```

O kernel **não** interpreta ELF, ZIP nem TAR. Quem lê o ELF é a ferramenta de
build, que roda no computador; ela emite a imagem já posicionada e uma tabela
de realocações minúscula. O kernel lê só o formato descrito aqui.

## 2. Cabeçalho (80 bytes)

| Deslocamento | Tamanho | Campo | Regra |
| --- | --- | --- | --- |
| 0 | 8 | `assinatura` | `53 41 44 52 56 01 0D 0A` (`SADRV`, formato 1, CRLF) |
| 8 | 4 | `tamanho_total` | tamanho do arquivo, múltiplo de 16, ≤ 262144 |
| 12 | 4 | `deslocamento_manifesto` | obrigatoriamente 80 |
| 16 | 4 | `tamanho_manifesto` | 1..8192, sem o preenchimento |
| 20 | 4 | `deslocamento_imagem` | 80 + alinhar16(`tamanho_manifesto`) |
| 24 | 4 | `tamanho_imagem` | 1..131072, sem o preenchimento |
| 28 | 4 | `tamanho_bss` | 0..65536 |
| 32 | 4 | `deslocamento_realocacoes` | `deslocamento_imagem` + alinhar16(`tamanho_imagem`) |
| 36 | 4 | `quantidade_realocacoes` | 0..4096 |
| 40 | 2 | `versao_abi` | 1 nesta versão |
| 42 | 2 | `arquitetura` | 1 = x86, 32 bits |
| 44 | 4 | `bandeiras` | reservado; deve ser 0 nesta versão |
| 48 | 32 | `resumo` | SHA-256, calculado como na seção 8 |
| 80 | — | manifesto | começa aqui |

O `magic` tem o byte de versão do formato e um `CR` `LF` no fim: se o arquivo
passar por um editor de texto ou por um transporte que troque fim de linha, a
assinatura deixa de bater e o pacote é recusado, em vez de ser lido torto.

`alinhar16(n)` = `(n + 15) & ~15`.

### 2.1 Layout obrigatório na versão 1

O layout é canônico; os deslocamentos do cabeçalho existem para conferência e
para as ferramentas, não para permitir outra arrumação:

```
0                     80
├─ cabeçalho ─────────┤
80                    manifesto ... preenchimento até 16
                      imagem ... preenchimento até 16
                      realocações (n × 8) ... preenchimento até 16
                      assinatura (64 bytes, no fim)
```

- `deslocamento_manifesto` **deve** ser 80.
- `deslocamento_imagem` **deve** ser `80 + alinhar16(tamanho_manifesto)`.
- `deslocamento_realocacoes` **deve** ser
  `deslocamento_imagem + alinhar16(tamanho_imagem)`.
- A assinatura **deve** ocupar os últimos 64 bytes:
  `tamanho_total - 64`.
- `tamanho_total` **deve** ser
  `deslocamento_realocacoes + alinhar16(quantidade_realocacoes × 8) + 64`.
- Os bytes de preenchimento **devem** ser zero.

Um formato futuro pode permitir outra ordem; para isso muda o byte de versão no
`magic`, e o kernel recusa versão que não conhece.

## 3. Manifesto (TLV)

O manifesto é uma sequência de entradas:

```
tag     u16
tamanho u16
valor   tamanho bytes
```

Regras:

- as tags **devem** estar em ordem estritamente crescente;
- as tags 9 (`DISPOSITIVO`) e 10 (`DEPENDENCIA`) podem repetir, sempre em
  entradas contíguas;
- nenhuma outra tag pode repetir;
- a soma das entradas **deve** ser exatamente `tamanho_manifesto`;
- o manifesto **não deve** ter nulo no fim nem texto terminado em `\0`.

### 3.1 Tags

| Tag | Nome | Conteúdo | Obrigatória |
| --- | --- | --- | --- |
| 1 | `ID` | ASCII, 1..31, `[a-z0-9][a-z0-9._-]*`, com pelo menos um ponto | sim |
| 2 | `NOME` | Latin-1 imprimível, 1..64 | sim |
| 3 | `DESCRICAO` | Latin-1 imprimível, 1..256 | sim |
| 4 | `AUTOR` | Latin-1 imprimível, 1..64 | sim |
| 5 | `VERSAO` | ASCII `X.Y.Z`, cada parte 0..9999, ≤ 16 bytes | sim |
| 6 | `LICENCA` | identificador SPDX da lista permitida, ≤ 32 | sim |
| 7 | `ID_DA_CHAVE` | 8 bytes | sim |
| 8 | `ENTRADA` | u32, deslocamento dentro da imagem | sim |
| 9 | `DISPOSITIVO` | 10 bytes por entrada, 1..16 entradas | sim |
| 10 | `DEPENDENCIA` | ID ASCII, 1..31, 0..8 entradas | não |

Texto "imprimível" em Latin-1: bytes `0x20`..`0x7E` e `0xA0`..`0xFF`. Nada de
controle, nada de `0x7F`, nada de `0x80`..`0x9F` (que no Latin-1 não têm
desenho). O sistema é Latin-1 por dentro (D027); a ferramenta converte o TOML
(UTF-8) na hora de embalar.

Licenças aceitas na v1 (todas compatíveis com a GPL 3, D041):
`GPL-3.0-only`, `GPL-3.0-or-later`, `GPL-2.0-or-later`, `LGPL-3.0-or-later`,
`LGPL-2.1-or-later`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`,
`ISC`, `Zlib`, `0BSD`, `CC0-1.0`.

O `ID` é a identidade do driver: aparece no `drivers`, no `ativo.txt` e nos
registros de log. Ele **deve** ser único entre embutidos e pacotes; um pacote
com o mesmo `ID` de um driver embutido é recusado (nada de se passar por
outro). O `ID` não pode ter ponto duplo, nem terminar em ponto, hífen ou
sublinhado.

### 3.2 Versão

A versão é `maior.menor.correção`, cada parte de 0 a 9999, sem zero à
esquerda. Ela aparece na tela e no log, e serve para o usuário saber o que
está rodando. A v1 **não** compara versões para dependências; só mostra.

## 4. Dispositivos (tag 9)

Cada entrada tem 10 bytes:

| Deslocamento | Tamanho | Campo | Regra |
| --- | --- | --- | --- |
| 0 | 1 | `tipo` | 1 = PCI; 2 = USB (reservado na v1) |
| 1 | 1 | `bandeiras` | bit 0 = casar por classe; bit 1 = casar por fabricante/modelo; bit 2 = exigir interface |
| 2 | 1 | `classe` | byte de classe PCI |
| 3 | 1 | `subclasse` | byte de subclasse |
| 4 | 1 | `interface` | byte de interface (só usado com o bit 2) |
| 5 | 1 | `reservado` | deve ser 0 |
| 6 | 2 | `fabricante` | u16; número exato do PCI-SIG (sem curinga) |
| 8 | 2 | `modelo` | u16; `0xFFFF` = qualquer modelo do fabricante |

Regras de casamento, em ordem:

1. A entrada **deve** ter pelo menos o bit 0 ou o bit 1 ligado.
2. O bit 2 só pode estar ligado junto com o bit 0.
3. Com o bit 0: `classe` e `subclasse` **devem** ser iguais; se o bit 2
   estiver ligado, `interface` também.
4. Com o bit 1: `fabricante` **deve** ser igual; `modelo` igual ou `0xFFFF`.
5. Com os dois bits: as duas condições precisam valer (E, não OU).
6. Uma entrada **não deve** ter `fabricante` igual a `0xFFFF` (não existe
   fabricante com esse número; curinga só vale para `modelo`).

Precedência entre entradas e drivers, do casamento mais específico para o menos
específico:

1. fabricante e modelo exatos combinados com classe, subclasse e interface
   exatas;
2. fabricante e modelo exatos combinados com classe e subclasse exatas, sem
   exigir interface;
3. fabricante e modelo exatos, sem exigência de classe;
4. fabricante exato com modelo curinga (`0xFFFF`) combinado com classe,
   subclasse e interface exatas;
5. fabricante exato com modelo curinga (`0xFFFF`) combinado com classe e
   subclasse exatas, sem exigir interface;
6. classe, subclasse e interface exatas, sem critério de fabricante/modelo;
7. classe e subclasse exatas, sem exigir interface nem fabricante/modelo;
8. fabricante exato com modelo curinga (`0xFFFF`), sem exigência de classe.

O bit 2 aparece duas vezes nas categorias combinadas (itens 1 e 4) porque,
quando a classe já casa, exigir também a interface é um critério mais restrito
do que aceitar qualquer interface; por isso a variante com interface vem antes
da variante sem ela.

Quando os bits 0 e 1 estiverem ligados, os dois critérios precisam ser
verdadeiros: a combinação é E, nunca OU. Dentro da mesma categoria, vence o
driver registrado primeiro; não há desempate por nome nem por ordem alfabética.
Se um mesmo driver declarar várias entradas que casem com o dispositivo, elas
não viram candidatos independentes: conta só a melhor categoria entre elas.
Como os embutidos são registrados antes dos pacotes, em empate os embutidos
conservam a prioridade. O resultado **deve** ser determinístico e aparecer no
`drivers`.

Esta ordenação é uma proposta da RFC e ainda depende de aprovação; a
implementação do kernel não existe nesta etapa.

A proteção da v1 é mais forte que a precedência entre pacotes e embutidos: um
pacote só pode tentar assumir um dispositivo que nenhum embutido assumiu nem
declarou como candidato. Isso vale mesmo quando o embutido declarou suporte e
não chegou a assumir: o dispositivo fica com ele (`compativel` e depois
`falhou`), e o pacote não o substitui na v1. Quando `drivers_carregar()` roda,
esses dispositivos ainda estão em `detectado`; `sem_driver` não é um estado de
entrada do carregador, e sim o estado final que `drivers_finalizar()` atribui
aos que continuarem sem associação. O carregador trata `detectado` como
disponível e não disputa `compativel` nem `falhou`, que pertencem a um
embutido. Não existe "substituir o driver embutido" na v1: é uma proteção, não
uma limitação esquecida.

Na v1 o kernel só casa `tipo = 1`. Uma entrada `tipo = 2` é recusada com
`SADRV_ERRO_CAMPO` (o campo existe para o formato não mudar de tamanho quando
o USB entrar).

## 5. Dependências (tag 10)

Cada entrada é o `ID` de outro driver que **deve** estar carregado antes. O
carregador:

- confere que o `ID` existe entre os pacotes da lista `ativo.txt` ou entre os
  embutidos;
- ordena a carga para que a dependência venha antes;
- recusa ciclo (`A` depende de `B`, `B` depende de `A`) com
  `SADRV_ERRO_DEPENDENCIA`;
- não compara versões na v1.

Dependência de driver embutido é permitida e não muda a ordem do boot: o
embutido já estará registrado quando o pacote carregar.

## 6. Imagem, BSS e entrada

A imagem é o código e os dados já posicionados pela ferramenta:

- a ferramenta concatena, nesta ordem, as seções `.text*`, `.rodata*` e
  `.data*` do objeto, cada uma alinhada ao seu `sh_addralign` (mínimo 16);
- seções `SHT_NOTE` chamadas `.note*` (por exemplo `.note.gnu.property`, que o
  GCC/ld moderno cria) são metadados e **não** entram na imagem; elas não podem
  ser executáveis. Outra seção alocada desconhecida é recusada;
- `.bss*` não ocupa espaço no arquivo: o carregador zera `tamanho_bss` bytes
  logo depois de `alinhar16(tamanho_imagem)`. O alinhamento de cada seção
  `.bss*` vale para o endereço absoluto
  `alinhar16(tamanho_imagem) + deslocamento_bss`; o preenchimento necessário
  entra em `tamanho_bss` e é zerado junto;
- o carregador aloca `alinhar16(tamanho_imagem) + tamanho_bss` bytes contíguos
  e **zera a área inteira** antes de copiar a imagem, para que nenhum resto de
  memória do kernel chegue ao módulo por engano;
- a cópia começa numa base alinhada a 4096 bytes (as páginas alocadas); assim o
  alinhamento de uma seção vale em `base + deslocamento`, e não só no
  deslocamento relativo. O BSS de 4096 bytes do teste depende disso;
- seções desconhecidas que ocupam memória (`.init_array`, `.fini_array`,
  `.eh_frame`, `.gcc_except_table`...) fazem a ferramenta recusar o módulo;
- a ferramenta **não deve** emitir tabela de símbolos no pacote.

A **entrada** (tag 8) é o deslocamento, dentro da imagem, de uma função com
esta assinatura. O símbolo de entrada precisa começar **estritamente dentro**
de uma seção `.text` executável e da imagem: o endereço igual ao fim da seção
é recusado, porque ali já começa a próxima seção (ou o fim da imagem), não uma
função.

```c
int32_t sadrv_entrada(const sadrv_api_t *api, const sadrv_dispositivo_t *disp);
```

O carregador chama a entrada **uma vez por dispositivo casado**, com a tabela
de funções e os dados daquele dispositivo. A função devolve:

| Retorno | Significado |
| --- | --- |
| `0` | Assumiu o dispositivo. |
| `-1` | Não é meu / recusei. |
| `-2` | Tentei e o hardware falhou. |
| outro negativo | Reservado; o número vai para o motivo na tela. |

O retorno vira o estado do **dispositivo**, não o destino do pacote: `-1` não
associa o dispositivo, que continua `detectado` até `drivers_finalizar()`; `-2`
o deixa `falhou` com o motivo. O módulo continua carregado e pode assumir outros
dispositivos dele. O carregador escolhe **um** driver por dispositivo, o
primeiro na ordem de precedência da seção 4; se ele recusar, nenhum outro é
tentado na v1.

A entrada roda na pilha do kernel, em contexto de boot, com interrupções
ligadas. Ela **não deve** bloquear para sempre nem desligar interrupções por
muito tempo.

## 7. Realocações

Uma realocação é um par de 8 bytes:

| Deslocamento | Tamanho | Campo |
| --- | --- | --- |
| 0 | 4 | `deslocamento` na imagem (`deslocamento + 4 ≤ tamanho_imagem`) |
| 4 | 4 | `alvo` (tipo nos bits 31..30, valor nos bits 29..0) |

Tipos:

| Tipo | Nome | O que o carregador faz (com `ler_u32`/`gravar_u32` seguros) |
| --- | --- | --- |
| 0 | absoluta interna | `gravar_u32(p, ler_u32(p) + base)` |
| 1 | absoluta externa | `gravar_u32(p, ler_u32(p) + endereço_do_símbolo)` |
| 2 | relativa externa | `gravar_u32(p, ler_u32(p) + endereço_do_símbolo - (base + deslocamento))` |
| 3 | reservada | recusa |

Cada realocação ocupa o intervalo `[deslocamento, deslocamento + 4)`. Dois
intervalos **não podem** se cruzar: 0 e 2, por exemplo, são recusados; 0 e 4
são permitidos. A regra vale para qualquer par, inclusive quando as entradas
vêm de tabelas de relocação diferentes e caem próximas depois da concatenação
das seções. O parser ELF, `montar_pacote()` e `analisar_pacote()` aplicam a
mesma regra.

Na leitura do ELF, `SHT_SYMTAB` precisa ter `sh_entsize = 16` e `SHT_REL`
precisa ter `sh_entsize = 8`. Zero não é aceito como alternativa: são
estruturas de tamanho fixo.

`ler_u32` e `gravar_u32` copiam quatro bytes com `memcpy` (ou laço de bytes)
para uma variável `uint32_t` local; **não** fazem `*(uint32_t *)p`. O
`memcpy` do compilador pode virar um acesso desalinhado no x86, que o hardware
aceita, mas o C continua definido porque o ponteiro da variável local está
alinhado. O valor de `p` é `base + deslocamento`, e o deslocamento pode ser
qualquer byte dentro da imagem.

Valor:

- tipo 0: tanto o alvo da tabela (`S`) quanto a palavra de 32 bits gravada na
  imagem (`S + A`) devem ser deslocamentos menores que a área carregada
  (`alinhar16(tamanho_imagem) + tamanho_bss`), para permitir ponteiro para
  variável em `.bss`. Um campo `0xFFFFFFFF` ou igual ao tamanho da área é
  recusado, mesmo que o alvo da tabela seja zero;
- tipos 1 e 2: identificador do símbolo externo — 1 = `memcpy`,
  2 = `memset`, 3 = `memmove`. Nada mais.

Por que só isso basta: o linker guarda o "adendo" no próprio lugar apontado
pela realocação (ELF de 32 bits usa `REL`, sem campo de adendo separado). Para
duas referências que ficam na mesma imagem, a diferença entre elas não muda
quando a imagem inteira é copiada para outro endereço — então a ferramenta
resolve as relativas internas (`R_386_PC32`) na hora de embalar e não precisa
emitir nada. Sobra só o que depende do endereço de carga (absolutas internas)
ou de um endereço do kernel (as três funções externas).

O GCC real emite `R_386_32` e `R_386_PC32` em posições que **não** são
múltiplas de quatro (por exemplo, dentro de uma estrutura `packed` ou de um
buffer de bytes). O deslocamento, portanto, só precisa caber na imagem; a
ferramenta e o carregador não podem exigir alinhamento. Ao aplicar o valor, o
carregador **não deve** escrever `*(uint32_t *)p` em C: isso é comportamento
indefinido com ponteiro desalinhado. Use cópia byte a byte ou `memcpy` para
ler e gravar os quatro bytes; em x86 o acesso desalinhado é aceito pelo
hardware, mas o C precisa da forma segura.

O carregador **deve** recusar:

- deslocamento fora da imagem;
- deslocamento repetido;
- dois intervalos de quatro bytes que se cruzem;
- tipo 3 ou desconhecido;
- alvo interno fora da área carregada;
- palavra interna efetiva (`S + A`) fora da área carregada;
- identificador externo fora de 1..3;
- qualquer tipo de realocação que a ferramenta não saiba converter (ela
  recusa antes: `R_386_GOT32`, `R_386_PLT32`, `R_386_16`, `R_386_8`...).

## 8. Resumo e assinatura

1. O resumo é SHA-256 (FIPS 180-4) sobre os bytes `[0, 48)` do cabeçalho
   seguidos dos bytes `[80, tamanho_total - 64)`. O campo `resumo` (48..79) e
   a assinatura não entram.
2. A assinatura é Ed25519 (RFC 8032, variante pura) sobre os **32 bytes do
   resumo**, não sobre o arquivo inteiro. Economiza uma segunda passada de
   hash no boot e não muda a garantia: o resumo já amarra o arquivo todo.
3. A assinatura ocupa os últimos 64 bytes.
4. `ID_DA_CHAVE` é os primeiros 8 bytes do SHA-256 da chave pública de 32
   bytes. Ele não é usado para escolher a chave (o kernel tem poucas chaves e
   tenta todas); serve para conferência depois que uma assinatura válida foi
   encontrada e para o usuário saber qual chave assinou.
5. A verificação Ed25519 usa **SHA-512** por dentro (RFC 8032). O kernel
   precisa das duas rotinas de resumo: SHA-256 para o pacote e SHA-512 para a
   assinatura. Nada de geração de assinatura, X25519 ou RSA no kernel.
6. Antes da equação, a chave pública e o ponto `R` da assinatura precisam ser
   pontos canônicos do subgrupo de ordem prima `L` da curva. O verificador
   **deve** recusar a identidade, qualquer ponto com `[8]P = O` (ordens 1, 2,
   4 ou 8) e qualquer ponto com `[L]P != O` (torção misturada). O kernel deve
   aplicar exatamente essa política, não só a equação: com a chave identidade,
   `R = O` e `S = 0` satisfazem a equação para qualquer mensagem. Os testes da
   H91 cobrem identidade, ordens 2, 4 e 8, ponto misturado e os cinco vetores
   positivos da seção 7.1 do RFC 8032.
7. A parte `S` da assinatura precisa ser canônica: `0 <= S < L`. Um `S` maior
   ou igual a `L` é recusado antes da equação, mesmo que a conta módulo `L`
   fosse aceitar o mesmo valor.

O kernel **deve** verificar a assinatura **antes** de interpretar o manifesto.
Como o `ID_DA_CHAVE` está dentro do manifesto (que ainda não foi lido), a
verificação tenta cada chave embutida, uma de cada vez; a primeira que validar
é a dona do pacote. Depois de validar, o `ID_DA_CHAVE` do manifesto **deve**
ser igual ao da chave que validou, senão o pacote é recusado
(`SADRV_ERRO_CHAVE`). Na v1 há uma chave; o teto é 4.

## 9. Ordem de validação e códigos de erro

O carregador valida nesta ordem e para no primeiro erro:

| Passo | O que confere | Erro |
| --- | --- | --- |
| 1 | tamanho do arquivo ≥ 176, ≤ 262144, múltiplo de 16 | `TAMANHO` |
| 2 | `assinatura` | `ASSINATURA` |
| 3 | `tamanho_total` = tamanho do arquivo | `TAMANHO` |
| 4 | deslocamentos, alinhamentos, preenchimento zero, layout canônico | `LAYOUT` |
| 5 | `versao_abi` = 1, `arquitetura` = 1, `bandeiras` = 0 | `VERSAO` |
| 6 | SHA-256 do cabeçalho e do corpo | `RESUMO` |
| 7 | Ed25519 sobre o resumo, com cada chave embutida | `ASSINATURA_CRIPTO` |
| 8 | TLV: ordem, repetição, tamanho, texto, campos obrigatórios, licença | `MANIFESTO` / `CAMPO` |
| 9 | `ID_DA_CHAVE` do manifesto = chave que validou | `CHAVE` |
| 10 | dispositivos: tipo, bandeiras, limites, coerência | `CAMPO` |
| 11 | entrada estritamente dentro da seção `.text` executável e da imagem | `CAMPO` |
| 12 | realocações: contagem, faixa, alvo, valor efetivo, intervalos sem sobreposição | `REALOCACAO` |
| 13 | dependências: existem, sem ciclo | `DEPENDENCIA` |
| 14 | `ID` não colide com embutido nem com pacote já carregado | `JA_CARREGADO` |
| 15 | alocação das páginas e cópia | `MEMORIA` |
| 16 | aplicação das realocações e chamada da entrada | `ENTRADA` (só falha de hardware; ver seção 6) |

Códigos (usados no kernel, na ferramenta e nos testes):

| Código | Nome | Quando |
| --- | --- | --- |
| 0 | `SADRV_OK` | tudo certo |
| 1 | `SADRV_ERRO_ASSINATURA` | `magic` errado |
| 2 | `SADRV_ERRO_TAMANHO` | tamanho fora dos limites ou não bate |
| 3 | `SADRV_ERRO_LAYOUT` | deslocamento/ordem/preenchimento |
| 4 | `SADRV_ERRO_VERSAO` | formato, ABI ou arquitetura não suportados |
| 5 | `SADRV_ERRO_RESUMO` | SHA-256 não bate |
| 6 | `SADRV_ERRO_CHAVE` | chave desconhecida ou `ID_DA_CHAVE` diferente |
| 7 | `SADRV_ERRO_ASSINATURA_CRIPTO` | Ed25519 não validou |
| 8 | `SADRV_ERRO_MANIFESTO` | TLV malformado |
| 9 | `SADRV_ERRO_CAMPO` | campo inválido ou faltando |
| 10 | `SADRV_ERRO_REALOCACAO` | realocação inválida |
| 11 | `SADRV_ERRO_DEPENDENCIA` | dependência ausente ou ciclo |
| 12 | `SADRV_ERRO_MEMORIA` | não conseguiu alocar as páginas |
| 13 | `SADRV_ERRO_ENTRADA` | a entrada devolveu -2 (falha de hardware); o dispositivo fica `falhou`, mas o pacote continua carregado |
| 14 | `SADRV_ERRO_JA_CARREGADO` | `ID` repetido |
| 15 | `SADRV_ERRO_NAO_LISTADO` | pacote na pasta, mas fora do `ativo.txt` |

## 10. Limites

| Limite | Valor | Por quê |
| --- | --- | --- |
| pacote | 262144 bytes (256 KiB) | cabe num `kmalloc` grande sem apertar a memória baixa |
| manifesto | 8192 bytes | 16 dispositivos + 8 dependências + texto cabem com folga |
| imagem | 131072 bytes (128 KiB) | um driver de rede cabe em dezenas de KiB |
| BSS | 65536 bytes (64 KiB) | estado do driver, não buffer de dados |
| área carregada | 196608 bytes (192 KiB) | imagem alinhada + BSS |
| pacotes na tabela | 32 | inclui `nao_listado` e `ausente`; 72 bytes cada |
| dispositivos | 16 | um driver, uma família |
| dependências | 8 | o grafo é raso de propósito |
| realocações | 4096 | 32 KiB de tabela |
| `ID` | 31 bytes | cabe inteiro no registro (`id[32]`) e no `ativo.txt` |
| `NOME` | 64 bytes | cabe em `nome[65]` (64 + NUL) nos registros da ABI |
| `DESCRICAO` | 256 bytes | uma frase |
| `AUTOR` | 64 bytes | idem |
| `VERSAO` | 16 bytes | `9999.9999.9999` |
| `LICENCA` | 32 bytes | o maior identificador da lista |
| chaves embutidas | 4 | uma do projeto e três de reserva |

## 11. ABI do driver (v1)

### 11.1 A tabela de funções

```c
#define SADRV_ABI 1

typedef struct {
    uint32_t tamanho;          /* bytes desta tabela */
    uint16_t versao;           /* SADRV_ABI */
    uint16_t reservado;
    void *(*alocar)(uint32_t bytes);
    void  (*liberar)(void *p);
    void  (*copiar)(void *destino, const void *origem, uint32_t bytes);
    void  (*preencher)(void *destino, uint8_t valor, uint32_t bytes);
    void  (*registrar)(const char *texto);
    uint32_t (*milissegundos)(void);
    uint32_t (*pci_ler32)(uint8_t b, uint8_t d, uint8_t f, uint8_t reg);
    void  (*pci_escreve32)(uint8_t b, uint8_t d, uint8_t f, uint8_t reg, uint32_t v);
    uint32_t (*mapear_memoria)(uint32_t fisico, uint32_t bytes);
} sadrv_api_t;
```

Regras:

- A tabela é uma estrutura **estática** do kernel, não vive na pilha; o módulo
  pode guardar o ponteiro e usá-lo enquanto estiver carregado.
- `alocar` devolve memória do heap do kernel, identidade-mapeada (o ponteiro é
  também o endereço físico, abaixo de 4 GB), executável e de leitura/escrita.
  Um driver que precisa de DMA pode usar esse endereço diretamente — e é por
  isso que a assinatura importa.
- `liberar` devolve um bloco de `alocar`. Memória alocada e não liberada fica
  com o driver até o fim do boot (não há descarregamento).
- `copiar`, `preencher`: substituem `memcpy`/`memset` sem depender de símbolo
  externo.
- `registrar`: escreve no diário do kernel, prefixado com o `ID` do driver.
  Texto acima de 160 bytes é cortado.
- `milissegundos`: relógio desde o boot (o mesmo de `SIS_TEMPO`).
- `pci_ler32`/`pci_escreve32`: acesso ao espaço de configuração do dispositivo
  (mecanismo 1). Não há conferência de faixa: o driver já é ring 0.
- `mapear_memoria`: mapeia uma faixa física (um BAR, por exemplo) na janela do
  kernel e devolve o ponteiro, ou 0 se não couber. Cada chamada é limitada pela
  janela disponível; faixas grandes devem ser mapeadas aos pedaços.
- A tabela **só cresce no fim**. Um campo novo entra depois de
  `mapear_memoria`, e o módulo confere `tamanho` se quiser usar o campo novo.
  O carregador recusa módulo com `versao_abi` maior que a do kernel.
- Nada de IRQ, nada de classe, nada de dormir, nada de descarregar na v1.

### 11.2 O dispositivo

```c
typedef struct {
    uint16_t id;               /* estável durante o boot */
    uint8_t  barramento;       /* 1 = PCI */
    uint8_t  b, d, f;
    uint16_t fabricante, modelo;
    uint8_t  classe, subclasse, interface;
    uint8_t  reservado;
} sadrv_dispositivo_t;
```

Os dados do dispositivo valem só durante a chamada; se o módulo precisar deles
depois, copia para a memória dele.

## 12. Ferramenta (`tools/sadrivers.py`)

Tudo em Python 3, só com a biblioteca padrão. A H91 foi implementada na opção
(b): o Ed25519 está escrito em Python puro e foi conferido contra os cinco
vetores da seção 7.1 do RFC 8032; o SHA-256 do pacote e o SHA-512 interno do
Ed25519 usam `hashlib` (que é da biblioteca padrão, não é dependência externa
do build). A verificação do kernel continua sendo a de
`userland/cripto/curva25519.c`; a ferramenta e o kernel serão comparados pelos
mesmos vetores quando a H92 integrar a verificação no boot. O `openssl` do
sistema, se existir, é só uma conferência opcional; não é chamado pela
ferramenta.

A ferramenta não executa o código do pacote, não instala nada no pendrive e não
copia pacote para o disco interno. Ela lê ELF, confere o manifesto, resolve as
realocações internas, monta o contêiner e assina. `extrair` nunca sobrescreve:
recusa pasta de destino que seja link simbólico, arquivo existente (inclusive
link) e cria cada saída com `O_EXCL` e, quando existe, `O_NOFOLLOW`; assim um
link plantado entre a conferência e a gravação não desvia a escrita. A pasta
de destino precisa estar livre nos nomes que a ferramenta grava, ou a operação
falha sem tocar no que já existe. Se uma gravação falhar depois que outras
começaram, a ferramenta remove os arquivos que ela própria criou nesta
operação; arquivos preexistentes e a pasta não são apagados. `gerar-chave`
também cria a chave privada com `O_EXCL` e modo 0600 desde o `open`; `--forcar`
grava num temporário exclusivo e troca o nome com `os.replace`, mas recusa
destino que seja link simbólico. `chave-publica --c` usa o mesmo temporário
exclusivo e `os.replace`: recusa destino que seja link simbólico ou que não
seja arquivo regular e nunca escreve no alvo de um link. No Windows o modo
POSIX não controla a ACL: 0600 é só uma tentativa; a proteção real depende da
pasta do usuário e das permissões do Windows. Quem carrega é o kernel, em
outra história.

```
python3 tools/sadrivers.py embalar      --objeto x.o --manifesto x.toml \
                                        --chave chave.txt \
                                        --saida build/modulos/saguios.diagnostico.sadrivers
python3 tools/sadrivers.py inspecionar  x.sadrivers
python3 tools/sadrivers.py verificar    x.sadrivers [--chave-publica k.pub]
python3 tools/sadrivers.py extrair      x.sadrivers --pasta saida/
python3 tools/sadrivers.py gerar-chave  --saida chave.txt
python3 tools/sadrivers.py chave-publica chave.txt --c chave.c
python3 tools/sadrivers.py fingerprint  chave.pub
```

Códigos de saída: 0 = certo, 1 = pacote inválido (com o motivo na saída de
erro), 2 = uso errado.

Os testes de host da H91 rodam sem QEMU e sem a imagem do sistema:

```
python3 tests/h91_sadrivers.py
```

Eles montam objetos ELF32 byte a byte, conferem os cinco vetores da seção 7.1
do RFC 8032, embalam e abrem pacotes, adulteram cada campo e verificam os
limites e as regras de caminho. Também cobrem entrada no fim da seção,
`sh_info` inválido, `sh_entsize` zero em SYMTAB/REL, realocação desalinhada,
sobreposição de intervalos (inclusive em tabelas de relocação diferentes),
ponteiro interno efetivo 0, último byte, limite e `0xFFFFFFFF`, BSS com
alinhamentos de até 4096 bytes, chave identidade, pontos de ordem pequena,
assinatura falsa com chave identidade, link simbólico no pacote autorizado
(dentro e fora da pasta), na extração, na chave privada e na chave pública C,
e o desfazimento dos arquivos criados quando uma gravação da extração falha.
Um teste adicional compila um módulo C mínimo com **GCC** e o passa por
`ld -m elf_i386 -r`; outro compila `tests/h91_abi.c`, que tem as verificações
estáticas de tamanho e alinhamento das estruturas da H89. Se não houver GCC
i386 utilizável (ou se ele tiver sido compilado sem iconv, necessário ao flag
`-fexec-charset`), esses testes são pulados com a razão escrita (o CI do
projeto tem o compilador). Como o nome começa com `h91`, o
`tests/rodar_todos.py` também os encontra depois de `make` no CI.

O nome do arquivo gerado **deve** ser `<ID>.sadrivers` (o mesmo `ID` do
manifesto); a ferramenta recusa outro nome, porque é assim que o carregador
acha o pacote a partir da linha do `ativo.txt`.

### 12.1 O manifesto em TOML

```toml
id       = "saguios.diagnostico"
nome     = "Diagnóstico de exemplo"
descricao = "Lê os primeiros registradores do dispositivo e anota no diário."
autor    = "Eli Rigobeli"
versao   = "0.1.0"
licenca  = "GPL-3.0-or-later"
entrada  = "sadrv_entrada"          # símbolo no objeto

[[dispositivo]]
tipo = "pci"
classe = 0x02
subclasse = 0x00

[[dispositivo]]
tipo = "pci"
fabricante = 0x8086
modelo = 0x100E

# [[dependencia]]
# id = "saguios.e1000"      # exemplo; só existe se a dependência for real
```

O leitor de TOML é o mínimo para este manifesto: `chave = valor`, strings
entre aspas duplas (com os escapes básicos), inteiros decimais e hexadecimais,
`[[dispositivo]]`, `[[dependencia]]` e comentários; o resto é erro. Assim a
ferramenta não depende da versão do Python nem de biblioteca externa.

A ferramenta confere os campos, converte para Latin-1, ordena as tags e calcula
os deslocamentos. Nada de "modo solto": campo desconhecido é erro. A presença
de `classe`/`subclasse` liga o bit 0 da entrada; `fabricante`/`modelo` liga o
bit 1; `interface` liga o bit 2.

### 12.2 Chaves

- **Privada:** arquivo de texto, uma linha `# comentário` e uma linha com 64
  dígitos hexadecimais (a semente de 32 bytes do RFC 8032). Nunca entra no
  repositório; o caminho sugerido é `~/.saguios/chave-de-assinatura.txt`.
- **Pública:** 64 dígitos hexadecimais. A opção `--c` gera um arquivo C com o
  vetor de 32 bytes e o `ID_DA_CHAVE` no comentário, para ser revisado e
  commitado em `kernel/confianca/` na H92. A H91 só gera o arquivo; não embute
  chave no kernel.
- A chave de teste do carregador é gerada em `build/teste/` na hora do teste;
  a imagem de teste é a única que a compila (seção 8 da RFC). Os testes de host
  da H91 usam a semente fixa do primeiro vetor do RFC 8032, que é pública.

A chave pública oficial embutida permite que a **comunidade** produza pacotes:
a ferramenta é pública e qualquer pessoa pode assinar com a própria chave. O
que o projeto aceita, porém, é só o pacote assinado por uma chave que ele
reconheça. Na primeira versão não há chave de usuário: um `chave.pub` no
pendrive não é confiável só por estar lá. A assinatura **não** é uma caixa de
areia nem uma promessa de segurança; ela diz de quem é o código, e o código
roda em ring 0 (seção 15).

A H91 não entrega o carregador, a verificação no boot, o módulo de diagnóstico,
a chave embutida no kernel, IRQ, classes de dispositivo, W^X, descarregamento
nem driver USB externo. Essas coisas continuam nas histórias seguintes e em
issues próprias.

## 13. Como escrever um módulo

### 13.1 Flags

```make
MCFLAGS := -m32 -march=i686 -std=gnu11 -O2 \
           -ffreestanding -fno-builtin -nostdlib -fno-pic -fno-pie \
           -fno-stack-protector -fno-asynchronous-unwind-tables \
           -fno-common -fcf-protection=none -fno-omit-frame-pointer \
           -mgeneral-regs-only \
           -Wall -Wextra -Werror=implicit-function-declaration \
           -finput-charset=UTF-8 -fexec-charset=ISO-8859-1 \
           -Imodulos/inc -Ikernel/inc
```

As mesmas restrições do kernel: sem biblioteca C, sem posição independente,
sem ponto flutuante nem SSE, sem pilha desalinhada. Vários `.c` são unidos com
`ld -m elf_i386 -r` antes de embalar.

O código-fonte fica em `modulos/<nome>/`, **fora de `kernel/`**: o Makefile
compila todo `kernel/**/*.c` para dentro do kernel. As regras de módulo são
separadas e gravam objetos e pacotes em `build/modulos/`, que o build normal não
põe na imagem; só a imagem de teste copia o módulo de diagnóstico.

### 13.2 Esqueleto

```c
/* modulos/exemplo/ola.c - módulo de exemplo do formato .sadrivers.
 * Inclui kernel/inc/sadrv.h, que só depende de tipos.h. */
#include "sadrv.h"

static const sadrv_api_t *api;

int32_t sadrv_entrada(const sadrv_api_t *a, const sadrv_dispositivo_t *d)
{
    api = a;
    /* Sem printf: o texto vai pelo diário do kernel. */
    api->registrar("exemplo: dispositivo assumido");
    /* Lê o registrador de identificação (0x00) só para provar o acesso. */
    uint32_t id = api->pci_ler32(d->b, d->d, d->f, 0x00);
    if ((id & 0xFFFF) != d->fabricante) return -2;
    return 0;
}
```

O módulo **não deve** definir `main`, nem usar `printf`, `malloc`, `memcpy`
diretamente (use `api->copiar`), nem assumir que roda uma vez só.

## 14. Instalação e diagnóstico

```
/usb/.saguios/drivers/ativo.txt
    # um ID por linha; o que não está aqui não carrega
    saguios.diagnostico
```

Cada linha do `ativo.txt` é um `ID` (sem a extensão `.sadrivers`), e o arquivo
correspondente é `<ID>.sadrivers`. O `ID` do manifesto **deve** ser igual ao nome
do arquivo sem a extensão; senão o pacote é recusado (`CAMPO`). O carregador
monta o caminho a partir do ID já validado, então a lista não consegue apontar
para fora da pasta. A ferramenta da H91 já aplica a mesma regra em
`ler_pacote_autorizado`: se o ID não está no `ativo.txt`, ela recusa com
`NAO_LISTADO` antes de abrir o arquivo; se está e o arquivo não existe, devolve
`None` (o chamador mostra `ausente`) sem inventar conteúdo. O nome final não é
resolvido com `Path.resolve()`: um link simbólico em `<ID>.sadrivers` é
recusado, e só arquivo regular é aberto. No POSIX, a abertura usa
`O_NOFOLLOW`; no Windows, onde essa flag não existe, a conferência anterior e
o `fstat` do descritor são o que a plataforma permite, e a janela de troca do
arquivo não vira uma garantia que o Windows não oferece.

O `ativo.txt` é ASCII, uma linha por ID, com `#` iniciando comentário e espaços
em volta ignorados; linha vazia é ignorada, duplicata vale uma vez e o teto é 32
IDs (2 KiB de arquivo). ID fora da regra da seção 3.1 é reportado e ignorado
pelo carregador; a ferramenta de host apenas ignora a linha. O registro tem 32
vagas no total, embutidos incluídos; pacote que não couber é recusado e contado
como recusado.

A tabela de pacotes é preenchida primeiro com os IDs listados (na ordem do
arquivo) e depois com os arquivos não listados, até 32; assim um arquivo solto
não esconde um pacote que o usuário mandou carregar.

- **Instalar:** copiar o pacote como `<ID>.sadrivers`, acrescentar a linha,
  reiniciar; a conferência de assinatura acontece no boot.
- **Desativar:** tirar a linha, reiniciar.
- **Remover:** tirar a linha e apagar o arquivo, reiniciar.
- O carregador lista a pasta `drivers/` para mostrar o nome dos arquivos
  `.sadrivers` que não estão no `ativo.txt` como `nao_listado`, mas **não abre**
  esses arquivos: sem linha na lista, não há verificação nem carga.
- Um `ID` listado sem o arquivo `<ID>.sadrivers` aparece como `ausente`; o boot
  continua com os outros pacotes.
- Na listagem do host, um caminho listado que existe mas não é arquivo regular
  (link simbólico, pasta ou arquivo especial) aparece como `recusado` com o
  motivo, e não como `ausente`; a listagem não abre o caminho nem o destino do
  link.
- Falha de verificação ou de carga não impede o boot: o sistema segue com os
  embutidos e o motivo aparece no `drivers`. Já um módulo assinado que trava
  durante a entrada trava a máquina (seção 15).
- O `INFO_PACOTES` (tipo 11) e o `drivers` mostram, para cada pacote:
  `nao_listado`, `ausente`, `verificado`, `recusado: <motivo>`, `carregado` ou
  `ativo`. O motivo vem do código de erro da seção 9.
- O `pci` continua existindo para o relatório cru; a aba "Drivers" é a visão
  organizada.

## 15. Limitações e modelo de ameaça

- **Ring 0 sem caixa de areia.** Um módulo assinado pode tudo: ler e escrever
  qualquer memória, programar DMA para qualquer endereço, travar a máquina.
  A assinatura diz que o projeto responde pelo código, não que ele é seguro.
- **A chave oficial é uma porta, não uma garantia.** Ela permite que a
  comunidade produza e assine pacotes com as próprias chaves, mas só os
  assinados por uma chave reconhecida pelo projeto são aceitos. A chave do
  usuário no pendrive é recusada na v1; a recuperação é tirar o pendrive. Não
  há sandbox, antivírus nem isolamento: assinatura não é segurança.
- **Sem Secure Boot.** O carregador não verifica o kernel; a cadeia começa no
  kernel.
- **Pendrive não é âncora.** Quem pode gravar o pendrive pode trocar a imagem
  do sistema inteira. A assinatura protege o pacote contra troca acidental ou
  maliciosa **com a imagem intacta** — nada além disso.
- **Sem W^X.** A imagem é carregada legível, escrita e executável. Sem NX, não
  há como separar.
- **Sem descarregar.** Um driver carregado fica até desligar; a remoção vale no
  próximo boot. É também a rede de segurança: sem o pendrive, o sistema volta
  aos embutidos.
- **Sem IRQ e sem classes.** A v1 é de inicialização e consulta. Um driver de
  rede de verdade precisa de IRQ e de um gancho de classe (ABI v2).
- **Sem chave de usuário e sem USB externo.** A primeira versão não tem
  keyring do usuário e não carrega driver USB de pacote; o USB de boot embutido
  continua como está.
- **Um pendrive por vez**, como o resto do sistema (PRD 4.3).

## 16. O que muda antes da versão 1.0

- O formato e o ABI continuam rascunho: a ferramenta da H91 passou nos testes
  de host, mas o carregador e a verificação no boot ainda não existem. Qualquer
  campo pode mudar antes do congelamento; não há 1.0.
- Decidir se `sadrv_dispositivo_t` ganha um campo de instância por dispositivo
  (hoje o estado do módulo é compartilhado).
- Decidir a origem do `ID_DA_CHAVE` (hoje: 8 primeiros bytes do SHA-256 da
  chave pública).
- Adiar, com issue própria: IRQ e classes (ABI 2), W^X (tag de texto somente
  leitura), descarregamento, USB, catálogo assinado.
- Medir o custo do SHA-256 + SHA-512 + Ed25519 no boot do G470 e o tamanho que
  isso acrescenta à imagem.

## 17. Referências

- **RFC 2119** — palavras-chave para exigências.
- **RFC 8032** — Ed25519 (assinatura e verificação).
- **FIPS 180-4** — SHA-256 (pacote) e SHA-512 (dentro do Ed25519).
- **Tool Interface Standard (TIS) ELF Specification 1.2** — ELF32, seções,
  símbolos e realocações `R_386_32`/`R_386_PC32` (lido pela ferramenta).
- **PCI Local Bus Specification 3.0** — espaço de configuração, identificação.
- **Código do SaguiOS** — `userland/cripto/curva25519.c` (implementação do
  Ed25519 do projeto), `userland/cripto/resumos.c` (SHA-256 e SHA-512),
  `kernel/inc/abi.h`, `kernel/dispositivos/pci.c`, `Makefile`.
