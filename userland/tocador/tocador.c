/* tocador.c - o Tocador de músicas do SaguiOS (pedido do Eli).
 *
 * Uma janela com a música que está tocando, o tempo, uma barra de progresso
 * (clicar nela pula para aquele ponto), os botões anterior / tocar-pausar /
 * parar / próxima, o volume e a lista das músicas da pasta. Abre sozinho
 * quando se dá dois cliques numa música no Arquivos ("tocador arquivo.wav").
 *
 * Como o som funciona: a placa toca 16 bits, estéreo, 48 kHz (H40). O Tocador
 * decodifica a música em blocos, converte a taxa por interpolação linear (como
 * o tocar, H42) e entrega à placa com som_enviar, que aceita só o que cabe na
 * fila: o resto fica para a próxima volta do laço. Pausar é só parar de
 * entregar. O tempo mostrado conta os quadros entregues.
 *
 * Formatos: WAV (PCM de 8 ou 16 bits, mono ou estéreo, qualquer taxa, pelo
 * formato RIFF da Microsoft/IBM) e, quando o decodificador do MP3 estiver no
 * sistema, MP3 (userland/tocador/mp3.c, pela norma ISO/IEC 11172-3). */
#include "sagui.h"
#include "gui.h"

#define LARG 560
#define ALT  400
#define MAX_MUSICAS 64
#define TAXA_PLACA 48000

/* ------------------------------------------------------------ a música aberta */

typedef struct {
    unsigned char *dados;      /* o arquivo inteiro */
    unsigned tam;
    unsigned taxa, canais, bits;
    unsigned ini, bytes;       /* as amostras (pedaço "data" do WAV) */
    unsigned quadros;          /* quadros da música, na taxa dela */
    unsigned long long pos;    /* próximo quadro, em 16.16 (fração para a interpolação); 64 bits: em
                                * 32 a conta dava a volta depois de 65536 amostras (1,5 s a 44,1 kHz) */
} musica_t;

static musica_t mus;
static bool aberta, tocando;
static int fonte = -1;
static char erro[96];

static unsigned le16(const unsigned char *p) { return (unsigned)p[0] | ((unsigned)p[1] << 8); }
static unsigned le32(const unsigned char *p) { return le16(p) | (le16(p + 2) << 16); }

static bool termina_com(const char *s, const char *fim)
{
    unsigned a = tam_texto(s), b = tam_texto(fim);
    if (a < b) return false;
    for (unsigned i = 0; i < b; i++) {
        char c = s[a - b + i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != fim[i]) return false;
    }
    return true;
}

static bool eh_musica(const char *nome) { return termina_com(nome, ".wav") || termina_com(nome, ".mp3"); }

static void fechar_musica(void)
{
    if (mus.dados) libera(mus.dados);
    memset(&mus, 0, sizeof mus);
    aberta = tocando = false;
}

/* Lê o arquivo inteiro (em laço: um ler() pode trazer menos que o pedido). */
static bool ler_tudo(const char *caminho)
{
    info_arquivo_t inf;
    if (info_arquivo(caminho, &inf) < 0) { copia_texto(erro, "Arquivo não encontrado.", sizeof erro); return false; }
    int fd = abrir(caminho, ABRIR_LER);
    if (fd < 0) { formatar_texto(erro, sizeof erro, "Não abriu: %s", nome_erro(fd)); return false; }
    mus.dados = aloca(inf.tamanho + 1);
    if (!mus.dados) { fechar(fd); copia_texto(erro, "Música grande demais para a memória.", sizeof erro); return false; }
    unsigned n = 0;
    while (n < inf.tamanho) {
        int r = ler(fd, mus.dados + n, inf.tamanho - n);
        if (r <= 0) break;
        n += (unsigned)r;
    }
    fechar(fd);
    mus.tam = n;
    if (n < inf.tamanho) registrar("tocador: li %u de %u bytes de %s", n, inf.tamanho, caminho);
    return true;
}

/* WAV: percorre os pedaços ("chunks") RIFF: "fmt " diz o formato, "data" tem as amostras. */
static bool abrir_wav(void)
{
    unsigned char *d = mus.dados;
    if (mus.tam < 44 || compara_texto_n((char *)d, "RIFF", 4) != 0 || compara_texto_n((char *)d + 8, "WAVE", 4) != 0) {
        copia_texto(erro, "Não é um arquivo WAV.", sizeof erro);
        return false;
    }
    unsigned formato = 0;
    for (unsigned p = 12; p + 8 <= mus.tam;) {
        unsigned t = le32(d + p + 4);
        if (compara_texto_n((char *)d + p, "fmt ", 4) == 0 && t >= 16) {
            formato = le16(d + p + 8); mus.canais = le16(d + p + 10);
            mus.taxa = le32(d + p + 12); mus.bits = le16(d + p + 22);
        } else if (compara_texto_n((char *)d + p, "data", 4) == 0) {
            mus.ini = p + 8;
            mus.bytes = t > mus.tam - mus.ini ? mus.tam - mus.ini : t;
            break;
        }
        p += 8 + t + (t & 1);
    }
    if (formato != 1 || (mus.bits != 8 && mus.bits != 16) || mus.canais < 1 || mus.canais > 2 ||
        mus.taxa < 4000 || mus.taxa > 96000 || !mus.ini) {
        copia_texto(erro, "WAV num formato que o Tocador não conhece (só PCM 8/16 bits).", sizeof erro);
        return false;
    }
    mus.quadros = mus.bytes / (mus.bits / 8 * mus.canais);
    return true;
}

static bool abrir_musica(const char *caminho)
{
    fechar_musica();
    erro[0] = 0;
    if (termina_com(caminho, ".mp3")) {
        copia_texto(erro, "MP3 ainda não: o decodificador está sendo escrito.", sizeof erro);
        return false;
    }
    if (!ler_tudo(caminho) || !abrir_wav()) { fechar_musica(); return false; }
    aberta = true;
    registrar("tocador: %s (%u Hz, %u bits, %u canais, %u s)", caminho, mus.taxa, mus.bits, mus.canais, mus.quadros / mus.taxa);
    return true;
}

/* Amostra k do canal c, em 16 bits com sinal. */
static int amostra(unsigned k, unsigned c)
{
    unsigned bq = mus.bits / 8 * mus.canais, ch = mus.canais == 2 ? c : 0;
    const unsigned char *p = mus.dados + mus.ini + k * bq;
    return mus.bits == 16 ? (short)le16(p + ch * 2) : ((int)p[ch] - 128) << 8;
}

/* Preenche até max quadros de 48 kHz estéreo; devolve quantos (0 = acabou). */
static int gerar(short *saida, int max)
{
    /* passo = taxa / 48000 em 16.16; 65536 / 48000 = 1024 / 750. */
    unsigned passo = mus.taxa * 1024u / 750u;
    int q = 0;
    while (q < max) {
        unsigned k = (unsigned)(mus.pos >> 16), fr = (unsigned)mus.pos & 0xFFFF;
        if (k + 1 >= mus.quadros) break;
        for (unsigned c = 0; c < 2; c++) {
            int a = amostra(k, c), b = amostra(k + 1, c);
            saida[2 * q + c] = (short)(a + (int)(((long long)(b - a) * fr) >> 16));
        }
        q++;
        mus.pos += passo;
    }
    return q;
}

static unsigned segundos_atual(void) { return mus.taxa ? (unsigned)(mus.pos >> 16) / mus.taxa : 0; }
static unsigned segundos_total(void) { return mus.taxa ? mus.quadros / mus.taxa : 0; }

/* ------------------------------------------------------------ a lista */

static char pasta[160] = "/usb";
static char musicas[MAX_MUSICAS][64];
static int qtd_musicas, atual = -1;
static lista_t lista;

static void carregar_lista(void)
{
    qtd_musicas = 0;
    entrada_pasta_t e;
    for (int i = 0; listar(pasta, i, &e) == 1 && qtd_musicas < MAX_MUSICAS; i++)
        if (e.tipo != TIPO_PASTA && eh_musica(e.nome)) copia_texto(musicas[qtd_musicas++], e.nome, 64);
    lista.qtd = qtd_musicas;
}

static void caminho_de(int i, char *c, unsigned max)
{
    formatar_texto(c, max, "%s%s%s", pasta, pasta[tam_texto(pasta) - 1] == '/' ? "" : "/", musicas[i]);
}

/* ------------------------------------------------------------ a janela */

static jan_t *j;
static botao_t b_ant, b_tocar, b_parar, b_prox, b_menos, b_mais;
#define BARRA_Y 92
#define BARRA_X 20
#define BARRA_L (LARG - 40)

static void desenhar_topo(void)
{
    g_retangulo(j, 0, 0, LARG, 176, 0x14201A);
    const char *nome = aberta && atual >= 0 ? musicas[atual] : "Nenhuma música tocando";
    g_texto(j, 20, 18, "Tocador", 0xFFDF4A);
    g_texto_n(j, 20, 44, nome, (LARG - 40) / LETRA_L, 0xFFFFFF);
    if (erro[0]) g_texto_n(j, 20, 64, erro, (LARG - 40) / LETRA_L, 0xFF8A80);
    /* Barra de progresso. */
    g_retangulo(j, BARRA_X, BARRA_Y, BARRA_L, 8, 0x3A4A40);
    unsigned tot = mus.quadros ? mus.quadros : 1;
    /* Sem divisão de 64 bits (a libgcc não entra no SaguiOS): quadros por pixel. */
    int feito = aberta ? (int)((unsigned)(mus.pos >> 16) / (tot / BARRA_L + 1)) : 0;
    if (feito > BARRA_L) feito = BARRA_L;
    g_retangulo(j, BARRA_X, BARRA_Y, feito, 8, 0x2EB872);
    g_retangulo(j, BARRA_X + feito - 2, BARRA_Y - 3, 5, 14, 0xFFDF4A);
    char t[40];
    formatar_texto(t, sizeof t, "%u:%02u / %u:%02u", segundos_atual() / 60, segundos_atual() % 60, segundos_total() / 60, segundos_total() % 60);
    g_texto(j, BARRA_X, BARRA_Y + 16, t, 0xC8D2CC);
    char v[24];
    formatar_texto(v, sizeof v, "Volume: %d", som_volume(-1));
    g_texto(j, LARG - 20 - 8 * 13 - 70, 140, v, 0xC8D2CC);
    b_tocar.texto = tocando ? "Pausar" : "Tocar";
    botao_desenhar(j, &b_ant); botao_desenhar(j, &b_tocar); botao_desenhar(j, &b_parar); botao_desenhar(j, &b_prox);
    botao_desenhar(j, &b_menos); botao_desenhar(j, &b_mais);
    jan_mostrar_area(j, 0, 0, LARG, 176);
}

static void desenhar_tudo(void)
{
    g_retangulo(j, 0, 0, LARG, ALT, COR_FUNDO);
    desenhar_topo();
    char t[200];
    formatar_texto(t, sizeof t, "Músicas em %s (%d):", pasta, qtd_musicas);
    g_texto_n(j, 12, 186, t, (LARG - 24) / LETRA_L, COR_TEXTO);
    if (!qtd_musicas) g_texto(j, 12, 216, "Nenhum .wav ou .mp3 nesta pasta.", COR_TEXTO_FRACO);
    lista.sel = atual;
    lista_desenhar(j, &lista);
    jan_mostrar(j);
}

static void tocar_item(int i)
{
    if (i < 0 || i >= qtd_musicas) return;
    char c[240];
    caminho_de(i, c, sizeof c);
    atual = i;
    tocando = abrir_musica(c);
    desenhar_tudo();
}

/* Entrega à placa o que couber. Devolve false quando a música acabou. */
static bool alimentar(void)
{
    static short bloco[2 * 960];
    static int pendente, enviado;   /* quadros do bloco ainda não aceitos */
    if (!tocando || fonte < 0) return true;
    for (int voltas = 0; voltas < 8; voltas++) {
        if (enviado >= pendente) {
            pendente = gerar(bloco, 960);
            enviado = 0;
            if (pendente == 0) return false;
        }
        int r = som_enviar(fonte, (char *)bloco + enviado * 4, (unsigned)(pendente - enviado) * 4);
        if (r <= 0) break;
        enviado += r / 4;
    }
    return true;
}

int principal(int argc, char **argv)
{
    j = jan_abrir("Tocador", LARG, ALT);
    if (!j) return 1;
    b_ant   = (botao_t){ 20, 132, 70, 28, "<<", false };
    b_tocar = (botao_t){ 96, 132, 86, 28, "Tocar", false };
    b_parar = (botao_t){ 188, 132, 70, 28, "Parar", false };
    b_prox  = (botao_t){ 264, 132, 70, 28, ">>", false };
    b_menos = (botao_t){ LARG - 20 - 70, 132, 32, 28, "-", false };
    b_mais  = (botao_t){ LARG - 20 - 32, 132, 32, 28, "+", false };
    lista = (lista_t){ 12, 206, LARG - 24, ALT - 206 - 12, musicas, 0, -1, 0, NULL };
    fonte = som_abrir();
    if (fonte < 0) copia_texto(erro, "Sem placa de som HD Audio: não dá para tocar.", sizeof erro);
    /* "tocador arquivo": a pasta dele vira a lista; senão, /usb (ou /sons). */
    if (argc > 1) {
        copia_texto(pasta, argv[1], sizeof pasta);
        char *barra = NULL;
        for (char *p = pasta; *p; p++) if (*p == '/') barra = p;
        if (barra && barra != pasta) *barra = 0; else if (barra) barra[1] = 0; else copia_texto(pasta, ".", sizeof pasta);
    }
    carregar_lista();
    if (!qtd_musicas && argc <= 1) { copia_texto(pasta, "/sons", sizeof pasta); carregar_lista(); }
    if (argc > 1) {
        const char *nome = argv[1];
        for (const char *p = argv[1]; *p; p++) if (*p == '/') nome = p + 1;
        for (int i = 0; i < qtd_musicas; i++) if (compara_texto(musicas[i], nome) == 0) atual = i;
        if (atual >= 0) tocar_item(atual);
        else { tocando = abrir_musica(argv[1]); }
    }
    desenhar_tudo();
    registrar("tocador: pronto (%d músicas em %s)", qtd_musicas, pasta);

    evento_t e;
    unsigned ultimo_desenho = tempo_ms();
    for (;;) {
        bool teve = false;
        while (proximo_evento(j->id, &e, false) == 1) {
            teve = true;
            if (e.tipo == EV_FECHAR) goto fim;
            if (botao_tratar(j, &b_tocar, &e)) {
                if (!aberta && qtd_musicas) tocar_item(atual >= 0 ? atual : 0);
                else if (aberta) tocando = !tocando;
                registrar("tocador: %s", tocando ? "tocando" : "pausado");
                desenhar_topo();
            }
            if (botao_tratar(j, &b_parar, &e)) { tocando = false; mus.pos = 0; registrar("tocador: parado"); desenhar_topo(); }
            if (botao_tratar(j, &b_ant, &e) && qtd_musicas) tocar_item(atual > 0 ? atual - 1 : qtd_musicas - 1);
            if (botao_tratar(j, &b_prox, &e) && qtd_musicas) tocar_item((atual + 1) % qtd_musicas);
            if (botao_tratar(j, &b_menos, &e)) { int v = som_volume(-1) - 10; som_volume(v < 0 ? 0 : v); desenhar_topo(); }
            if (botao_tratar(j, &b_mais, &e)) { int v = som_volume(-1) + 10; som_volume(v > 100 ? 100 : v); desenhar_topo(); }
            /* Clique na barra de progresso: pula para aquele ponto. */
            if (e.tipo == EV_CLIQUE && aberta && e.y >= BARRA_Y - 6 && e.y < BARRA_Y + 14 && e.x >= BARRA_X && e.x < BARRA_X + BARRA_L) {
                unsigned q = (unsigned)(e.x - BARRA_X) * (mus.quadros / BARRA_L + 1);
                if (q >= mus.quadros) q = mus.quadros ? mus.quadros - 1 : 0;
                mus.pos = (unsigned long long)q << 16;
                registrar("tocador: pulou para %u s", segundos_atual());
                desenhar_topo();
            }
            if (e.tipo == EV_TECLA && e.tecla == ' ' && aberta) { tocando = !tocando; desenhar_topo(); }
            int r = lista_tratar(j, &lista, &e);
            if (r == LISTA_ATIVOU) tocar_item(lista.sel);
        }
        if (!alimentar()) {
            registrar("tocador: fim de %s", atual >= 0 ? musicas[atual] : "?");
            tocando = false;
            if (qtd_musicas > 1 && atual >= 0 && atual + 1 < qtd_musicas) tocar_item(atual + 1);   /* a próxima da lista */
            else { mus.pos = 0; desenhar_topo(); }
        }
        if (tempo_ms() - ultimo_desenho > 500) { ultimo_desenho = tempo_ms(); if (aberta) desenhar_topo(); }
        if (!teve) dormir(10);
    }
fim:
    if (fonte >= 0) som_fechar(fonte);
    fechar_musica();
    jan_fechar(j);
    return 0;
}
