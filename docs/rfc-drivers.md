# RFC: um gerente de drivers e pacotes `.sadrivers` para o SaguiOS

**Estado:** proposta geral, ainda em revisão. A ferramenta `tools/sadrivers.py`
e o formato experimental `.sadrivers` 0.1 da H91/H91b foram implementados e
testados em host; a revisão independente ainda não os aprovou. O carregador, a
verificação no kernel e a execução de módulos não foram implementados, e a H92
ainda não começou.
**Para:** Eli Rigobeli.
**De:** conversa com o agente de IA (OpenCode), a partir do pedido do Eli.
**Data:** 15 de novembro de 2026.
**Documento irmão:** `docs/sadrivers.md` — o formato do pacote e o ABI do driver,
em detalhe (versão preliminar 0.1).

Este documento descreve a proposta geral e continua aberto à discussão. Ele
mostra o que está ruim hoje (com o arquivo e a função), o que se propõe, o que
fica de fora e em que pedaços isso entra sem quebrar o que já funciona. As
decisões que precisam de um "sim" estão na seção 11. A regra do projeto vale
inteira: **nada de código de outro sistema operacional**; o que está aqui foi
pensado a partir das especificações públicas listadas na seção 15 e das
necessidades do SaguiOS.

## 1. O problema, com o código na mão

O SaguiOS já fala com bastante hardware, mas cada driver é uma ilha: ele
procura o seu dispositivo, decide sozinho se dá conta e não conta a ninguém o
que aconteceu. Isso já aparece em pontos concretos do código.

| O que se vê hoje | Onde | Por que atrapalha |
| --- | --- | --- |
| Cada driver varre o PCI inteiro por conta própria | `pci_listar()` em `kernel/dispositivos/pci.c`, chamada por `hda_iniciar()`, `ehci_iniciar_todos()`, `e1000_iniciar()` e `video_nativo_tentar()` | São quatro varreduras de 256 barramentos × 32 dispositivos no boot. Nenhuma sabe o que a outra já assumiu. |
| "Tem driver" é uma tabela fixa dentro do relatório | `suporte()` em `kernel/dispositivos/pci.c` | O relatório diz "driver EHCI do SaguiOS" só pela classe do dispositivo, mesmo quando o EHCI não iniciou; diz "driver Intel PRO/1000" para qualquer Intel de rede, com um "se for 8254x" que ninguém confere. A informação envelhece calada. |
| A tela lê o relatório por deslocamento fixo | `userland/programas/configuracoes.c`, na aba "Sobre o computador" (`l + 20`) | Qualquer mudança no texto do `pci` quebra a lista da aba sem aviso. |
| Falha de driver não fica registrada | `e1000_iniciar()` devolve `NULL` | O `pci` mostra o dispositivo, mas ninguém diz "o e1000 tentou e parou no reset". |
| Um driver novo não tem por onde entrar | `Makefile`, linha 33: `KERNEL_C := $(shell find kernel -name '*.c')` | Tudo que está em `kernel/` entra no kernel; um driver de fora não tem pasta, formato nem ABI. |
| O USB avisa os drivers pelo nome | `remover()` em `kernel/usb/usb.c` | Cada driver é chamado na mão (`armaz_desconectar`, `rede_usb_desconectar`); um driver novo não tem como ser avisado. |
| O ABI de `int 0x80` é de ring 3 | `kernel/inc/abi.h` | Ele existe para programas de usuário. Não serve para código que roda em ring 0 e chama funções do kernel. |

O resultado prático: quando um dispositivo não funciona no G470, o caminho é
ler o `pci`, adivinhar qual driver deveria pegá-lo e procurar no diário do
kernel. A informação existe, mas está espalhada e às vezes está errada.

## 2. O que se propõe

Três coisas separadas, que hoje vivem misturadas:

1. **Dispositivo** — o que foi encontrado no barramento (um endereço PCI, por
   exemplo). Tem identidade estável durante o boot e um estado.
2. **Driver** — o código que sabe falar com uma família de dispositivos. Tem
   nome, versão, origem (embutido ou pacote) e estado.
3. **Associação** — o laço entre os dois: "o driver `saguios.e1000` assumiu o
   dispositivo PCI 00:19.0". É ela que hoje não existe.

Em cima disso:

- um **registro** no kernel, com tabelas de tamanho fixo (sem `kmalloc` no
  caminho do boot), que qualquer driver procura e atualiza;
- uma **API de consulta** para o userland, com registros de tamanho fixo (não
  texto para ser lido por deslocamento);
- um **comando `drivers`** e uma **aba "Drivers"** nas Configurações, primeiro
  só para consultar;
- um **formato de pacote** próprio (`.sadrivers`), versionado, validado e
  assinado, para que um driver de folha possa ser acrescentado sem recompilar o
  kernel (driver de rede ou de disco precisa de um gancho de classe, que é
  outro assunto — ver 6.1);
- um **carregador** que só executa o que foi assinado por uma chave que está
  dentro da imagem do sistema.

O desenho é conservador de propósito: o registro e a consulta funcionam
sozinhos, sem carregar nada de fora. É a parte que resolve o problema de
diagnóstico hoje e que pode entrar primeiro, com risco pequeno. O carregamento
de módulos vem depois, com o formato e a assinatura já testados.

## 3. O que fica de fora (e por quê)

- **Sandbox.** Um módulo roda em ring 0, com os mesmos privilégios do kernel:
  ele pode escrever em qualquer memória, desligar interrupções e travar a
  máquina. Não existe "meio ring 0". Separar drivers de verdade exigiria um
  microkernel, que não é o desenho do SaguiOS. A assinatura diz "o
  projeto responde por este código", não "este código é seguro".
- **Descarregar módulo.** Sem suporte a interrupções e sem um jeito seguro de
  parar DMA, tirar um driver do ar é pior do que deixá-lo carregado. Na v1,
  desinstalar vale a partir do próximo boot. Descarregar fica para depois de
  IRQ e de um ciclo de parada bem definido.
- **Interrupções para módulos.** A v1 é só de inicialização e consulta (polling
  e leitura de registradores). IRQ é uma extensão de ABI separada, com issue
  própria, porque mexe no tratador de interrupções e no caminho crítico.
- **Chaves de usuário.** Ver a seção 8: uma chave guardada no mesmo pendrive
  que o atacante controla não protege nada. Na v1, só as chaves que estão
  dentro da imagem assinam.
- **W^X (código que não se escreve, dados que não se executam).** A máquina é
  i386 sem NX. Marcar páginas como somente leitura protege contra bug, não
  contra ataque, e um módulo assinado é confiável por definição. Fica para
  quando houver NX/PAE.
- **Classes de driver (rede, disco, vídeo).** A v1 não tem registro de classe:
  um módulo não consegue entregar um `ler`/`escrever` para o kernel chamar
  depois. Ele inicializa o aparelho e relata; integrar com a pilha de rede ou
  com o sistema de arquivos é a extensão descrita na seção 6.1.
- **Drivers USB na v1.** O formato já tem espaço para USB, mas o registro e o
  carregador começam só com PCI. USB entra quando o registro já estiver de pé.
- **Instalar sozinho.** Pacote no pendrive não é pacote ativo. A lista
  `ativo.txt` é o consentimento explícito; sem ela, o pacote nem é verificado.

## 4. O modelo: dispositivo, driver e associação

```
  barramento PCI            registro do kernel              driver
  ┌──────────────┐         ┌────────────────────┐        ┌──────────────────┐
  │ 00:1b.0      │────────▶│ dispositivo #3     │◀──────▶│ saguios.hda      │
  │ 8086:1c20    │  enumera│ estado: ativo      │ assume │ origem: embutido │
  └──────────────┘         │ driver: #0         │        │ estado: ativo    │
                           └────────────────────┘        └──────────────────┘
```

Estados do **dispositivo**:

| Estado | Significado |
| --- | --- |
| `detectado` | Enumerado e sem associação; ainda pode ser disputado pelo casamento. |
| `sem_driver` | Nenhum driver assumiu; o dispositivo permaneceu sem associação. |
| `compativel` | Algum driver declarou suporte, mas ainda não assumiu. |
| `ativo` | Um driver assumiu e a inicialização terminou bem. |
| `falhou` | Um driver tentou, falhou, e o motivo está guardado. |
| `removido` | O dispositivo saiu do barramento (USB, no futuro). |

Estados do **driver**:

| Estado | Significado |
| --- | --- |
| `registrado` | Declarou-se e declarou o que suporta; ainda não rodou. |
| `carregado` | O código está na memória (pacote), mas não assumiu nada. |
| `ativo` | Assume pelo menos um dispositivo. |
| `desativado` | O usuário desligou na lista; não é carregado no próximo boot. |
| `erro` | Tentou assumir e falhou (motivo guardado). |
| `remocao_pendente` | A remoção foi pedida; vale no próximo boot. |

`desativado` e `remocao_pendente` são estados de intenção: a aba os mostra
comparando o `ativo.txt` com os drivers carregados; o registro do kernel só
muda no próximo boot. Nada é descarregado.

Por que três conceitos e não um: um dispositivo pode existir sem driver (é o
caso do SATA AHCI do G470 hoje), um driver pode existir sem dispositivo (um
pacote instalado num computador sem a placa) e a associação pode falhar sem que
nenhum dos dois esteja errado. A tela precisa mostrar essas três coisas
separadas para o diagnóstico fazer sentido.

### 4.1 Estruturas (rascunho)

```c
/* kernel/inc/drivers.h (rascunho) */
#include <stddef.h>
#include <stdint.h>

#define DRIVERS_MAX_DISP 64      /* o mesmo teto do PCI_MAX */
#define DRIVERS_MAX_DRV  32

typedef struct {
    uint8_t  barramento;         /* 0: 1 = PCI (2 = USB, no futuro) */
    uint8_t  estado;             /* 1: DISP_* */
    uint8_t  b, d, f;            /* 2..4: endereço PCI */
    uint8_t  classe, subclasse, interface; /* 5..7 */
    uint16_t fabricante, modelo; /* 8..11 */
    int8_t   driver;             /* 12: índice em drivers[], -1 = nenhum */
    uint8_t  _res[3];            /* 13..15: deve ser 0 */
    char     motivo[32];         /* 16..47: por que falhou, em Latin-1 */
} drivers_disp_t;                /* 48 bytes */

typedef struct {
    char     id[32];             /* 0..31: "saguios.e1000" + NUL */
    char     nome[65];           /* 32..96: "Intel PRO/1000" + NUL */
    uint8_t  origem;             /* 97: 0 = embutido, 1 = pacote */
    uint8_t  estado;             /* 98: DRV_* */
    uint8_t  dispositivos;       /* 99: quantos assumiu */
    uint8_t  reservado;          /* 100: deve ser 0 */
    uint8_t  _pad0;              /* 101: alinhamento explícito; 0 */
    uint16_t versao[3];          /* 102..107: maior, menor, correção */
    char     motivo[32];         /* 108..139: motivo curto em Latin-1 */
} drivers_drv_t;                 /* 140 bytes */
```

O `NOME` do manifesto tem no máximo 64 bytes, então o registro precisa de 65
para o NUL. A versão é `uint16_t versao[3]`: cada parte vai de 0 a 9999 e não
cabe num `uint8_t` (que pararia em 255). O `_pad0` é explícito para que o
compilador não insira preenchimento invisível antes de `versao`.

Tudo em tabelas fixas: 64 dispositivos × 48 bytes + 32 drivers × 140 bytes +
32 pacotes × 72 bytes dão 9.856 bytes (9,6 KiB) de BSS. Não há alocação no
caminho do boot e não há como o registro falhar por falta de memória.

Estas verificações **devem** acompanhar o cabeçalho (a H89 as compila com
`gcc -m32 -std=gnu11 -c`):

```c
_Static_assert(sizeof(drivers_disp_t) == 48, "drivers_disp_t mudou");
_Static_assert(offsetof(drivers_disp_t, motivo) == 16, "motivo desalinhado");
_Static_assert(sizeof(drivers_drv_t) == 140, "drivers_drv_t mudou");
_Static_assert(offsetof(drivers_drv_t, versao) == 102, "versao desalinhada");
_Static_assert(offsetof(drivers_drv_t, motivo) == 108, "motivo desalinhado");
```

O arquivo `tests/h91_abi.c` repete estas declarações e verificações; o teste da
H91 o compila com GCC `-m32` quando o compilador está disponível.

### 4.2 Quem declara o suporte

O conhecimento de "quais dispositivos eu atendo" fica **com o driver**, não numa
tabela central:

```c
void drivers_registrar_embutido(const char *id, const char *nome);
void drivers_suporta_pci(const char *id, uint16_t fabricante, uint16_t modelo);
void drivers_suporta_classe(const char *id, uint8_t classe, uint8_t subclasse,
                            uint8_t interface);
int  drivers_assumir_pci(const char *id, const pci_disp_t *d);
void drivers_falhou_pci(const char *id, const pci_disp_t *d, const char *motivo);
```

Cada driver, no começo do seu `iniciar()`, chama `drivers_registrar_embutido()` e
as declarações de suporte; quando decide assumir, chama `drivers_assumir_pci()`;
quando um passo falha, chama `drivers_falhou_pci()` com um motivo curto. O
`pci_relatorio()` deixa de ter a tabela `suporte()` e passa a perguntar ao
registro — uma fonte de verdade só, e o `pci` deixa de mentir.

A ordem de casamento proposta, do mais específico para o menos específico, é:

1. fabricante e modelo exatos combinados com classe e subclasse exatas;
2. fabricante e modelo exatos, sem exigência de classe;
3. fabricante com modelo curinga (`0xFFFF`) combinado com classe e subclasse
   exatas;
4. classe, subclasse e interface exatas;
5. classe e subclasse exatas, sem exigência de interface;
6. fabricante exato com modelo curinga (`0xFFFF`), sem exigência de classe.

Quando os bits 0 e 1 estiverem ligados, os dois critérios precisam ser
verdadeiros: a combinação é E, nunca OU. Dentro da mesma categoria, vence quem
declarou primeiro; o desempate não depende do nome nem da ordem alfabética do
driver. Como os embutidos são registrados antes dos pacotes, em empate os
embutidos conservam a prioridade. O resultado deve ser determinístico e
aparecer no registro de drivers.

Esta ordenação é uma proposta da RFC e ainda depende de aprovação (seção 11).
A regra de proteção da v1 continua valendo: como os embutidos rodam antes, um
pacote só pode assumir um dispositivo que nenhum embutido assumiu nem declarou
como candidato — não dá para sequestrar o driver de vídeo ou o de rede
instalando um pacote. Se um embutido declarou suporte e não assumiu, o
dispositivo fica com ele (`compativel` e depois `falhou`); o pacote não o
substitui na v1.

## 5. Onde isso entra no boot

A ordem do boot é delicada (D010, D020). A proposta mexe o mínimo:

| Momento | O que acontece |
| --- | --- |
| depois de `vfs_iniciar()` | `drivers_iniciar()`: zera as tabelas e enumera o PCI **uma vez**. |
| `usb_iniciar()` | Como hoje. O EHCI pode se registrar e assumir o controlador. |
| `hda_iniciar()` | Registra-se, declara suporte, assume ou falha. |
| `rede_iniciar()` | Idem para o `e1000`. |
| `video_nativo_tentar()` | Idem para o vídeo nativo. |
| depois dos embutidos | `drivers_carregar()`: lê `/usb/.saguios/drivers/ativo.txt`, verifica e carrega os pacotes. Sem pendrive, não faz nada. Roda antes de `drivers_finalizar()`; os dispositivos sem candidato embutido ainda estão `detectado`. O pacote só pode assumir dispositivo que nenhum embutido assumiu nem declarou como candidato. |
| fim do boot | `drivers_finalizar()`: o que ficou `compativel` vira `falhou` com o motivo "o driver não assumiu"; o que ficou `detectado` vira `sem_driver`; o resumo é congelado para a consulta. |

Detalhe de ordem: `drivers_carregar()` roda antes de `drivers_finalizar()`.
Nesse momento, os dispositivos sem candidato ainda estão `detectado`; o
`sem_driver` só é atribuído por `drivers_finalizar()` aos que permanecerem sem
associação. O carregador trata `detectado` como disponível; `compativel` e
`falhou` pertencem a um embutido e não são disputados.

O ganho colateral é medível: hoje o PCI é varrido quatro vezes; passa a ser
varrido uma. A estimativa é de algumas dezenas de milissegundos a menos no
boot, a confirmar com o relógio do próprio kernel (não é medida ainda).

## 6. O ABI do driver (v1)

O ABI de driver **não** é o `int 0x80`. Ele é uma tabela de funções que o
kernel passa ao módulo, e o módulo só chama o que está nela:

```c
typedef struct {
    uint32_t tamanho;        /* bytes desta tabela; o módulo confere antes de usar */
    uint16_t versao;         /* SADRV_ABI (1) */
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

Regras da v1:

- **Sem símbolos externos**, com três exceções: `memcpy`, `memset` e `memmove`
  (o compilador pode gerar chamadas a eles numa cópia de estrutura). Qualquer
  outro símbolo indefinido faz o pacote ser recusado antes de rodar.
- **Sem ponto flutuante e sem SSE** (`-mgeneral-regs-only`, como o kernel). O
  kernel não salva FPU no meio de uma interrupção; um módulo com SSE abriria
  essa porta.
- **Sem IRQ** na v1 (seção 3).
- **Uma chamada por dispositivo**: o carregador escolhe **um** driver por
  dispositivo, o primeiro na ordem de precedência, e chama a entrada uma vez,
  com a tabela e o dispositivo. Devolver 0 = assumiu; negativo = recusou ou
  falhou, e nenhum outro driver é tentado na v1. O estado estático do módulo é
  compartilhado entre os dispositivos dele — documentado e aceito na v1.
- **Cresce só no fim**: uma versão nova da tabela só acrescenta funções no
  final. O campo `tamanho` diz ao módulo o que existe; um módulo antigo
  continua funcionando num kernel novo.
- **Chamada em contexto de boot**, com interrupções ligadas, na pilha do
  kernel. Nada de bloquear para sempre: a v1 não oferece `dormir()`.

### 6.1 O que um módulo da v1 consegue fazer

A tabela dá a um módulo: alocar e liberar memória, copiar e preencher, escrever
no registro do kernel, ler o relógio, ler e escrever o espaço de configuração
do PCI e mapear um BAR. Com isso ele **inicializa hardware**: identifica o
dispositivo, liga o barramento, escreve registradores e lê o resultado.

O que ele **não** consegue é se registrar como driver de uma classe. Não existe
na v1 um `registrar_rede(ler, escrever)` nem um `registrar_disco(ler,
escrever)`: o kernel não tem como chamar o módulo de volta depois do boot. A
única chamada é a entrada, uma vez por dispositivo. Um módulo da v1 é, portanto,
uma **folha**: faz o que faz durante a chamada e pronto. Isso basta para
diagnóstico (ler e relatar o que o aparelho responde, testar um BAR, conferir o
estado em que o firmware o deixou) e para aparelhos que só precisam de
inicialização, sem integrar com o resto do sistema.

Por que não já: registrar uma classe obriga a definir quem chama o módulo,
quando, em que contexto, com que bloqueio, e como ele pede IRQ. É a mesma
extensão de ABI que o primeiro driver de rede ou de disco vai precisar; escrever
essa extensão antes de existir um driver que a use seria desenhar no escuro. Por
isso a H95 (o primeiro driver externo de verdade) depende de uma issue separada
de **IRQ e classes**; o que a v1 entrega sozinha é o caminho completo — formato,
assinatura, carregador e ABI — provado por um módulo de diagnóstico.

## 7. O pacote `.sadrivers`

O formato completo está em `docs/sadrivers.md`. Em resumo:

```
┌────────────┬──────────────────┬──────────────┬───────────────┬────────────┐
│ cabeçalho  │ manifesto (TLV)  │ imagem       │ realocações   │ assinatura │
│ 80 bytes   │ até 8 KiB        │ até 128 KiB  │ 8 bytes cada  │ 64 bytes   │
└────────────┴──────────────────┴──────────────┴───────────────┴────────────┘
```

- **Assinatura de arquivo:** `SADRV`, o byte `0x01` (versão do formato) e
  `0D 0A` (para pegar arquivo que passou por editor de texto e virou CRLF).
- **Manifesto TLV:** tags de 1 a 10, em ordem crescente, com identificador,
  nome, descrição, autor, versão, licença, id da chave, entrada, dispositivos e
  dependências. Texto em Latin-1 (o sistema é Latin-1 por dentro, D027);
  identificadores em ASCII.
- **Imagem:** código e dados já posicionados, com uma tabela de realocações
  minúscula (só o que muda com o endereço de carga). O GCC real pode emitir
  realocações em posições não alinhadas; o carregador aplica os quatro bytes
  com cópia byte a byte/`memcpy`, nunca com `*(uint32_t *)p` desalinhado.
- **Resumo e assinatura:** SHA-256 (FIPS 180-4) do cabeçalho e do corpo;
  Ed25519 (RFC 8032) sobre os 32 bytes do resumo. A verificação Ed25519 usa
  SHA-512 por dentro, então o kernel precisa das duas rotinas de resumo.
  A chave pública e o ponto `R` precisam ser canônicos e estar no subgrupo de
  ordem prima `L`: recusar a identidade, `[8]P = O` (ordens 1, 2, 4 e 8) e
  `[L]P != O` (torção misturada); o escalar `S` também precisa ser canônico
  (`S < L`). Sem isso, a chave identidade aceita `R = O, S = 0` como assinatura
  válida de qualquer mensagem. O verificador do kernel deve repetir exatamente
  essa política, além da equação.

Por que um formato próprio, e não ZIP/TAR/ELF renomeado:

- **ZIP/TAR** são formatos genéricos, com muitos campos e caminhos. O kernel
  teria que validar um formato que não foi feito para isso, e um ZIP traria a
  tentação de comprimir (mais um decodificador no kernel). Recusado.
- **ELF direto** obrigaria o kernel a interpretar cabeçalhos de seção, tabela
  de símbolos e realocações de um arquivo **não confiável, antes de saber se
  ele é confiável**. São muitos cantos (program headers, notas, várias tabelas)
  e cada canto é uma chance de bug em ring 0. Em vez disso, a ferramenta de
  build (que roda no computador, não no boot) lê o ELF, resolve o que dá para
  resolver e emite uma imagem plana com uma tabela de realocações de 8 bytes.
  O kernel lê só o formato dono dele.
- O `.sadrivers` tem lugar para ABI, arquitetura, entrada e limites — coisas
  que um ZIP não tem e que o kernel precisa conferir antes de qualquer coisa.

## 8. Confiança: o que a assinatura garante e o que não garante

**Garante:** que o pacote foi montado por quem tem a chave privada
correspondente a uma chave pública que está dentro da imagem do SaguiOS, e que
nada no arquivo mudou depois disso.

**Não garante:** que o código é seguro, que não tem bug, que não vai travar a
máquina. Um driver assinado roda em ring 0 e pode tudo. A assinatura é uma
declaração de responsabilidade do projeto, não uma caixa de areia.

Decisões:

- **Só chaves embutidas na imagem.** A v1 tem uma chave (a do projeto). A chave
  pública vira um vetor C gerado uma vez e revisado no pull request; a privada
  nunca entra no repositório. Acrescentar uma chave é uma versão nova do
  sistema.
- **Nada de chave de usuário no pendrive.** O raciocínio inicial era ter um
  chaveiro do usuário em `/usb/.saguios/chaves`. Isso não protege: quem consegue
  gravar o pendrive grava a chave e o pacote juntos; "confiar na primeira vez"
  não ajuda porque o atacante planta a chave antes do primeiro boot. O pendrive
  também não é âncora de confiança: quem pode trocar o pacote pode trocar a
  imagem inteira. A assinatura protege contra a troca **do pacote** com a
  imagem intacta, e é só isso que ela promete.
- **Sem Secure Boot.** O carregador não verifica o kernel; a cadeia de
  confiança começa no kernel e termina no pacote. Está documentado no README
  quando o recurso entrar.
- **Reconferência a cada boot**, do arquivo, sem cache de "já verifiquei".
- **Revogação = versão nova sem a chave.** O pacote antigo deixa de carregar;
  nada é apagado do pendrive.
- **Imagem de teste separada.** O caminho positivo (carregar um módulo) precisa
  de uma chave de teste. Ela só existe numa imagem construída para os testes
  (`SADRV_TESTE`), com a chave gerada na hora em `build/teste/`. A imagem que
  sai para o pendrive não tem essa chave, e um teste confere isso pelo resumo
  de drivers (uma bandeira diz "chave de teste presente"). Nada de "modo
  desenvolvedor" por opção de boot em máquina de verdade: seria um bypass.
- **Recuperação:** os pacotes vivem no pendrive e nunca são copiados para o
  disco interno. Se um pacote travar o boot, tirar o pendrive volta o sistema
  aos drivers embutidos. É por isso que a v1 não copia pacote para lugar
  nenhum.

## 9. Onde os pacotes ficam e como entram

```
/usb/.saguios/drivers/
    ativo.txt                      uma linha por driver, "#" comenta
    saguios.e1000.sadrivers
    saguios.diagnostico.sadrivers
```

O nome do arquivo é o `ID` do manifesto mais `.sadrivers`. O carregador monta o
caminho a partir do `ID` já validado (nunca de um caminho escrito no
`ativo.txt`), então não há como a lista apontar para fora da pasta.

- **Presença não é consentimento.** O carregador lê `ativo.txt`; um pacote que
  está na pasta e não está na lista não é verificado nem carregado (o `drivers`
  mostra só o nome do arquivo, como `nao_listado`).
- **Instalar** = copiar o pacote como `<ID>.sadrivers` e acrescentar a linha em
  `ativo.txt`; a assinatura é conferida no próximo boot (a ferramenta do
  computador pode conferir antes). **Desativar** = tirar a linha (vale no
  próximo boot). **Remover** = tirar a linha e apagar o arquivo, se nenhuma
  linha o usar.
- Um pendrive por vez, como hoje (PRD 4.3). Sem pendrive montado, não há
  pacote: o sistema liga só com os embutidos.
- O `ativo.txt` é um arquivo de texto comum, escrito pelo VFS que já existe.
  Não precisa de chamada de sistema nova para instalar.

## 10. Consulta e interface

### 10.1 API para o userland

Quatro tipos novos no `SIS_INFO_SISTEMA` (43), **aditivos**, sem mexer nos
existentes:

| Tipo | Valor | Conteúdo |
| --- | --- | --- |
| `INFO_RESUMO_DRIVERS` | 8 | contagens e bandeiras (16 bytes) |
| `INFO_DISPOSITIVOS` | 9 | até 64 registros de tamanho fixo |
| `INFO_DRIVERS` | 10 | até 32 registros de tamanho fixo |
| `INFO_PACOTES` | 11 | até 32 registros de tamanho fixo |

A convenção é a do `INFO_PROCESSOS`: `n` é o número máximo de registros e o
retorno é quantos vieram. Nada de texto para ser cortado por deslocamento.

```c
typedef struct {
    uint16_t dispositivos, ativos, sem_driver, falharam;
    uint16_t drivers;            /* registros em INFO_DRIVERS */
    uint16_t pacotes;            /* registros em INFO_PACOTES */
    uint16_t pacotes_recusados, bandeiras;
} info_resumo_drivers_t;         /* 16 bytes; bandeiras bit 0 = chave de teste */

typedef struct {
    uint16_t id;
    uint8_t  barramento, estado;
    uint8_t  classe, subclasse, interface, reservado;
    uint16_t fabricante, modelo;
    uint16_t driver;             /* índice em drivers, 0xFFFF = nenhum */
    uint16_t _res;               /* alinhamento; deve ser 0 */
    char     nome[65];           /* "Intel 82579V" + NUL */
    char     motivo[32];         /* "sem resposta", "não assumiu"... */
    uint8_t  _pad0;              /* alinhamento explícito; 0 */
} info_dispositivo_t;            /* 114 bytes */

typedef struct {
    uint16_t indice;
    uint8_t  origem, estado;
    uint16_t dispositivos;       /* quantos assumiu */
    uint16_t versao[3];          /* maior, menor, correção (0..9999) */
    uint8_t  reservado;
    uint8_t  _pad0;              /* alinhamento explícito; 0 */
    char     id[32];             /* "saguios.e1000" + NUL */
    char     nome[65];           /* "Intel PRO/1000" + NUL */
    char     motivo[32];
    uint8_t  _pad1;              /* alinhamento explícito; 0 */
} info_driver_t;                 /* 144 bytes */

typedef struct {
    uint16_t indice;
    uint8_t  estado, reservado;
    uint16_t driver;             /* índice em drivers, 0xFFFF = nenhum */
    uint16_t _res;               /* alinhamento; deve ser 0 */
    char     id[32];             /* ID ou nome do arquivo, sem .sadrivers */
    char     motivo[32];         /* "fora do ativo.txt", "assinatura"... */
} info_pacote_t;                 /* 72 bytes */

_Static_assert(sizeof(info_resumo_drivers_t) == 16, "resumo mudou");
_Static_assert(sizeof(info_dispositivo_t) == 114, "dispositivo mudou");
_Static_assert(offsetof(info_dispositivo_t, nome) == 16, "nome desalinhado");
_Static_assert(sizeof(info_driver_t) == 144, "driver mudou");
_Static_assert(offsetof(info_driver_t, versao) == 6, "versao desalinhada");
_Static_assert(offsetof(info_driver_t, nome) == 46, "nome desalinhado");
_Static_assert(sizeof(info_pacote_t) == 72, "pacote mudou");
```

Os três vetores de consulta somam 14.208 bytes (13,9 KiB) se o kernel preencher
os buffers inteiros: 64 × 114 + 32 × 144 + 32 × 72; o resumo acrescenta 16
bytes. Esses buffers são do chamador, não BSS do registro.

Estados do **pacote**: `nao_listado` (arquivo na pasta, fora do `ativo.txt`),
`ausente` (listado, arquivo não encontrado), `verificado` (assinatura e manifesto
certos, ainda sem executar), `recusado` (motivo guardado), `carregado` (código na
memória, sem dispositivo) e `ativo` (assumiu pelo menos um dispositivo). O pacote
carregado também aparece em `INFO_DRIVERS`, com `origem = 1`; as duas visões são
de propósito: o arquivo e o driver que saiu dele.

O impacto no ABI é só de acréscimo: nenhuma chamada muda de número, nenhuma
estrutura existente muda de tamanho. Mesmo assim, é ABI, e por isso está na
lista de aprovação (seção 11).

### 10.2 O comando `drivers`

```
Drivers: 4 embutidos (3 ativos, 1 falhou), 0 pacotes
Dispositivos: 6 (3 ativos, 2 sem driver, 1 falhou)

 ID  BARRAMENTO  DISPOSITIVO                  DRIVER          ESTADO
  0  PCI         8086:1c20 HD Audio (série 6) saguios.hda     ativo
  1  PCI         8086:1c26 EHCI (série 6)     saguios.ehci    ativo
  2  PCI         8086:100e PRO/1000 (82540EM) saguios.e1000   ativo
  3  PCI         1af4:1000 virtio-net         -               sem driver
  4  PCI         8086:1c03 SATA AHCI          -               sem driver
  5  PCI         8086:0106 HD Graphics         saguios.video   falhou: sem modo
```

O comando usa as mesmas tabelas de nome do `pci.c` (`nome_fabricante`,
`nome_modelo`), sem duplicar texto. Quando o registro estiver de pé, o próprio
`pci` passa a perguntar a ele quem suporta o quê.

### 10.3 A aba "Drivers" nas Configurações

Primeiro **só consulta**, com o mesmo desenho das outras abas (título, lista,
rodapé). Depois que instalar/desativar/remover existirem na API, os botões
entram. A ordem na lateral: depois de "Rede", antes de "Programas" — é onde
alguém procura quando o Wi-Fi ou o som não funciona.

O que a aba mostra:

- o resumo em uma linha (no exemplo acima: "6 dispositivos, 3 ativos, 2 sem
  driver, 1 falhou");
- a lista de drivers (nome, versão, origem, estado, quantos dispositivos);
- a lista de dispositivos, com o motivo da falha quando houver;
- a lista de pacotes (nome, estado e motivo), inclusive os que não carregaram;
- um aviso honesto: "Drivers de pacote rodam com os mesmos poderes do sistema.
  Instale só o que veio assinado pelo projeto."

## 11. O que precisa de aprovação

- [ ] A direção geral desta RFC (registro, formato, assinatura, carregador).
- [ ] A precedência PCI detalhada da seção 4.2: (1) fabricante/modelo exatos
      com classe/subclasse; (2) fabricante/modelo exatos; (3) fabricante com
      modelo curinga e classe/subclasse; (4) classe/subclasse/interface;
      (5) classe/subclasse; (6) fabricante com modelo curinga. Em empate,
      declaração primeiro; embutidos antes dos pacotes.
- [ ] Os quatro tipos novos de `INFO_*` (8, 9, 10 e 11), que são ABI mesmo sendo
      aditivos.
- [ ] O escopo da v1: sem IRQ, sem classes, sem chave de usuário, sem W^X, sem
      descarregar, sem USB.
- [ ] O formato `.sadrivers` 0.1 pode virar 1.0 depois dos testes da ferramenta
      e do carregador (antes disso, ele é rascunho).
- [ ] Os números H89 a H95 no `status.json` (o painel lista até H85, mas H86,
      H87 e H88 já aparecem em decisões e testes; H89 é o próximo livre).
- [ ] A aba "Sobre o computador" deixa de ler o `INFO_PCI` por deslocamento:
      passa a usar os registros novos (ou perde a lista, que migra para
      "Drivers").
- [ ] Como seguir sem o toolchain do kernel nesta máquina (seção 16).

## 12. Riscos

| Risco | Impacto | Mitigação |
| --- | --- | --- |
| Bug num módulo ring 0 derruba a máquina | Alto | Só código assinado; chave de teste só na imagem de teste; nada de pacote automático; recuperação tirando o pendrive. |
| Ed25519 no kernel puxar rotinas de 64 bits da libgcc | Alto (falha de link) | Compilar com as mesmas flags do kernel e conferir com `nm`; o CI quebra se aparecer `__muldi3`, `__udivdi3` ou `__umoddi3`. Se aparecer, a conta é reescrita em 32 bits ou a rotina de multiplicação é escrita aqui — libgcc não entra. |
| Criptografia no kernel aumentar demais a imagem | Médio | Medir com `make`; se passar do teto, extrair só a verificação (sem geração de assinatura e sem X25519). |
| Formato mudar depois de publicado | Médio | O byte de versão no `magic`; o kernel recusa versão que não conhece; 1.0 só depois dos testes. |
| A aba virar promessa de "instalar" antes da hora | Médio | Primeiro só consulta; os botões entram com a API pronta e teste. |
| Varredura do PCI ficar mais lenta | Baixo | Enumeração única; medir no teste com `SIS_TEMPO`. |
| Pacote assinado mas com ABI errada | Baixo | Campo de ABI no cabeçalho; o carregador recusa antes de carregar. |
| Driver embutido e pacote disputarem o mesmo dispositivo | Baixo | Embutido tem prioridade (roda antes); o pacote só pode tentar o que nenhum embutido assumiu nem declarou, e isso aparece no `drivers`. |

## 13. Divisão em pull requests

Cada linha é um assunto, para caber na regra de ~500 linhas.

| # | História | O que entra | Depende de |
| --- | --- | --- | --- |
| 1 | — | Esta RFC e o `docs/sadrivers.md` (só documentação) | — |
| 2 | H89 | Registro no kernel, declarações de suporte dos embutidos, os quatro `INFO_*` de consulta, comando `drivers`, teste no QEMU | 1 |
| 3 | H90 | Aba "Drivers" nas Configurações (só consulta), teste de tela | 2 |
| 4 | H91 | Formato `.sadrivers` + ferramenta `tools/sadrivers.py` (embalar, inspecionar, verificar, extrair) + testes em Python | 1 |
| 5 | H92 | Verificação no kernel (SHA-256, SHA-512 e Ed25519), chave embutida, status dos pacotes na UI, sem executar nada | 4 |
| 6 | H93 | Carregador + ABI + módulo de diagnóstico, só na imagem de teste | 5 |
| 7 | H94 | Instalar/desativar/remover na aba, com teste de ponta a ponta | 6 |
| 8 | H95 | Primeiro driver externo de verdade (issue separada; candidato: RTL8139, que o QEMU emula e tem datasheet público) | 6 + IRQ e classes (issue própria) |

Os testes acompanham cada pull request; nenhum deles enfraquece teste existente.

Três linhas podem passar do teto de ~500 linhas quando o código aparecer: a H89
(registro + consulta + comando), a H91 (ferramenta do formato) e a H92 (SHA-256,
SHA-512 e Ed25519). Se acontecer, cada uma se divide em duas
(`H89`/`H89b`, `H91`/`H91b`, `H92`/`H92b`), sem renumerar as seguintes. O desenho
não muda; só o tamanho do pull request.

## 14. Questões abertas

1. **Descarregar módulo**: só depois de IRQ e de um ciclo de parada (parar DMA,
   liberar IRQ, esperar). Vale a pena? A recuperação por pendrive já resolve o
   caso de emergência.
2. **IRQ e classes para módulos**: uma extensão de ABI com
   `pedir_irq`/`liberar_irq`, uma pilha própria e os ganchos
   `registrar_rede`/`registrar_disco`. Precisa de issue e de teste com
   interrupção de verdade.
3. **Um módulo, vários dispositivos**: hoje a entrada é chamada por dispositivo,
   com estado compartilhado. Um driver de duas portas precisa de instância por
   dispositivo? Se sim, o ABI muda antes de 1.0.
4. **Chaves**: uma só, do projeto. Quando (e se) houver TPM ou keyring assinado
   por versão, volta a conversa sobre chaves de terceiros.
5. **W^X**: depende de NX/PAE. Sem isso, não há o que proteger de verdade.
6. **Primeiro driver externo**: RTL8139 (fácil de testar no QEMU) ou o da placa
   do G470? São issues diferentes, com datasheet diferente.
7. **A aba substitui a lista de PCI da aba "Sobre o computador"?** Proposta:
   sim, com o `pci` continuando para quem quiser o relatório cru.
8. **Distribuição**: por enquanto, copiar o pacote para o pendrive. Um catálogo
   assinado (uma lista de pacotes assinada pela mesma chave) é o passo natural,
   mas é outro assunto.

## 15. De onde veio o conhecimento

Tudo foi pensado a partir de documentos públicos e do código que já existe no
SaguiOS. **Nenhum código de sistema operacional foi copiado, adaptado ou
reproduzido de memória** (AGENTS.md, D041):

- **PCI Local Bus Specification 3.0** (PCI-SIG): espaço de configuração pelo
  mecanismo 1, portas `0xCF8`/`0xCFC`, formato de identificação — é o que o
  `pci.c` já usa.
- **IDs de fabricante e modelo**: os números são atribuídos pelo PCI-SIG e
  constam dos datasheets dos fabricantes; as tabelas do `pci.c` são uma
  seleção dos aparelhos que aparecem nas máquinas do projeto.
- **Tool Interface Standard (TIS) ELF Specification, versão 1.2**: formato
  ELF32, seções, símbolos e realocações `R_386_32`/`R_386_PC32` — lido pela
  ferramenta de build, não pelo kernel.
- **FIPS 180-4** (SHA-256 e SHA-512) e **RFC 8032** (Ed25519): os algoritmos.
- **RFC 2119**: o sentido de "deve" e "não deve" em `docs/sadrivers.md`.
- **Especificação USB 2.0** (USB-IF): só para o desenho futuro do casamento USB;
  a v1 não implementa.
- **Código do SaguiOS**: `kernel/dispositivos/pci.c`, `kernel/inc/abi.h`,
  `kernel/nucleo/chamadas_processos.c`, `kernel/nucleo/principal.c`,
  `kernel/fs/discos.c`, `kernel/usb/usb.c`, `userland/programas/configuracoes.c`,
  `userland/cripto/curva25519.c`, `userland/cripto/resumos.c`, `Makefile` e os
  testes em `tests/`.

## 16. Como seguir (e o que esta máquina não faz)

A sessão de revisão da H91 usa o Windows como máquina principal, mas os testes
completos rodaram numa instância WSL1 Alpine, com Python 3.12, GCC 13.2 e GNU
ld 2.42. Foi esse ambiente que compilou o módulo C real, passou por `ld -r` e
executou os testes de link simbólico e permissão POSIX; no Windows nativo, o
GCC i386 temporário não tem iconv, então o módulo C real e os links simbólicos
foram pulados, e o teste de layout estático passou. Nenhum arquivo do kernel
foi compilado e não há `qemu-system-i386` em nenhum dos dois. Então:

- **não dá para compilar o kernel nem rodar os testes de QEMU aqui.** Qualquer
  passo de kernel (H89 em diante) precisa de uma máquina Linux com as
  ferramentas do `README`/CI, ou do CI do GitHub;
- **dá para escrever e testar a ferramenta do formato** (H91): ela é Python 3
  e os testes montam o `.o` byte a byte; quando há GCC utilizável, também
  compilam um módulo C real com os flags da especificação e um `ld -r`;
- o caminho mais seguro é: aprovar esta RFC, revisar a H91 (ferramenta +
  testes) e deixar H89/H92/H93 para um ambiente com toolchain, com o CI
  confirmando cada passo.

## 17. Texto pronto para a issue

```markdown
## Gerente de drivers e pacotes `.sadrivers`

Hoje cada driver do SaguiOS procura o seu dispositivo sozinho e não conta o
que aconteceu. O relatório `pci` diz "tem driver" por uma tabela fixa
(`suporte()`), que às vezes mente; a aba "Sobre o computador" lê esse texto por
deslocamento fixo; e não existe jeito de acrescentar um driver sem recompilar
o kernel (`Makefile`: `KERNEL_C := $(shell find kernel -name '*.c')`).

### Proposta

1. Um registro no kernel com três conceitos separados: dispositivo, driver e
   associação. Tabelas fixas, sem alocação no boot. Cada driver declara o que
   suporta e assume (ou falha com motivo) explicitamente.
2. Uma API de consulta aditiva (`INFO_RESUMO_DRIVERS` 8, `INFO_DISPOSITIVOS` 9,
   `INFO_DRIVERS` 10, `INFO_PACOTES` 11), um comando `drivers` e uma aba
   "Drivers" nas Configurações — primeiro só para consultar.
3. Um formato de pacote próprio, `.sadrivers`: cabeçalho de 80 bytes, manifesto
   TLV, imagem plana com tabela de realocações, SHA-256 e assinatura Ed25519.
   O kernel não interpreta ELF nem ZIP: a ferramenta de build lê o ELF e emite
   o formato dono do projeto.
4. Um carregador que só executa pacote assinado por uma chave embutida na
   imagem. Sem chave de usuário no pendrive (não protegeria nada), sem Secure
   Boot, sem sandbox: um driver roda em ring 0 e a assinatura é uma declaração
   de responsabilidade, não uma caixa de areia.

### Escopo da v1

Sem IRQ para módulos, sem classes de driver (rede/disco), sem descarregar, sem
W^X, sem USB, sem instalar automaticamente. Desinstalar vale no próximo boot.
Pacotes vivem no pendrive e nunca são copiados para o disco interno: tirar o
pendrive volta aos embutidos.

### Pedaços

- H89: registro + `INFO_*` de consulta + comando `drivers` + teste.
- H90: aba "Drivers" (só consulta) + teste de tela.
- H91: formato + `tools/sadrivers.py` + testes em Python.
- H92: verificação (SHA-256, SHA-512 e Ed25519) no kernel, sem executar.
- H93: carregador + ABI + módulo de diagnóstico, só na imagem de teste.
- H94: instalar/desativar/remover na aba.
- H95: primeiro driver externo de verdade, depois da API de IRQ e de classes
  (issue separada). A v1 sozinha vai até o módulo de diagnóstico.

### Documentos

- `docs/rfc-drivers.md` (esta proposta, com o problema e os riscos)
- `docs/sadrivers.md` (formato e ABI, v0.1)

### Fora de escopo

Sandbox, Secure Boot, chaves de terceiros, IRQ, classes de driver, descarregar
módulo, drivers USB, cópia de pacotes para o disco interno.
```
