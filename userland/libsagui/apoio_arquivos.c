/* apoio_arquivos.c - pequenas ajudas para os programas de arquivos (H93):
 * ler um arquivo inteiro para a memória, converter a data do relógio para
 * os formatos do Unix (tar, gzip) e do MS-DOS (zip), e os nomes dos erros
 * da compactação. Ficam fora de compactar.c para que aquele arquivo dependa
 * só de memória e possa ser testado no computador de desenvolvimento. */
#include "compactar.h"

const char *comp_nome_erro(int erro)
{
    switch (erro) {
    case COMP_ERRO_DADOS:    return "dados compactados corrompidos";
    case COMP_ERRO_CHEIO:    return "o resultado não cabe";
    case COMP_ERRO_CRC:      return "a soma de conferência (CRC) não bate";
    case COMP_ERRO_MEMORIA:  return "sem memória";
    case COMP_ERRO_TRUNCADO: return "o arquivo acaba antes da hora";
    case COMP_ERRO_METODO:   return "método não suportado";
    }
    return nome_erro(erro);
}


/* Segundos desde 1/1/1970 (sem fuso: o relógio da placa-mãe vale como está). */
uint32_t data_para_unix(const data_t *d)
{
    static const uint16_t antes_do_mes[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    if (d->ano < 1970 || d->mes < 1 || d->mes > 12) return 0;
    uint32_t dias = 0;
    for (uint32_t a = 1970; a < d->ano; a++) dias += (a % 4 == 0 && (a % 100 != 0 || a % 400 == 0)) ? 366 : 365;
    dias += antes_do_mes[d->mes - 1] + d->dia - 1u;
    uint32_t a = d->ano;
    if (d->mes > 2 && a % 4 == 0 && (a % 100 != 0 || a % 400 == 0)) dias++;
    return dias * 86400u + d->hora * 3600u + d->minuto * 60u + d->segundo;
}

/* MS-DOS: data = (ano - 1980) << 9 | mês << 5 | dia; hora = h << 11 |
 * min << 5 | seg / 2 (PKWARE APPNOTE, seção 4.4.6). */
uint32_t data_para_dos(const data_t *d)
{
    uint32_t ano = d->ano < 1980 ? 0 : d->ano - 1980u;
    uint32_t data = ano << 9 | (uint32_t)d->mes << 5 | d->dia;
    uint32_t hora = (uint32_t)d->hora << 11 | (uint32_t)d->minuto << 5 | d->segundo / 2u;
    return hora << 16 | data;
}

int ler_arquivo_inteiro(const char *caminho, uint8_t **dados)
{
    info_arquivo_t inf;
    *dados = NULL;
    int r = info_arquivo(caminho, &inf);
    if (r < 0) return r;
    if (inf.tipo == TIPO_PASTA) return ERRO_E_PASTA;
    if (inf.tamanho > COMP_LIMITE) return COMP_ERRO_CHEIO;
    int fd = abrir(caminho, ABRIR_LER);
    if (fd < 0) return fd;
    uint8_t *b = aloca(inf.tamanho + 1);
    if (!b) { fechar(fd); return COMP_ERRO_MEMORIA; }
    uint32_t k = 0;
    while (k < inf.tamanho) {
        int m = ler(fd, b + k, inf.tamanho - k);
        if (m < 0) { fechar(fd); libera(b); return m; }
        if (m == 0) break;
        k += (uint32_t)m;
    }
    fechar(fd);
    *dados = b;
    return (int)k;
}
