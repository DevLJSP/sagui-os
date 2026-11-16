/*
 * Confere, no compilador, o layout das estruturas de driver documentadas em
 * docs/rfc-drivers.md (H89).  Não é código do kernel: é um teste de host,
 * compilado com -m32, que quebra se alguém mudar um campo sem mudar o tamanho
 * ou o alinhamento declarado.
 *
 * O teste Python tests/h91_sadrivers.py compila este arquivo quando há GCC
 * i386.  Usamos tipos próprios, sem <stdint.h>, para o teste também rodar em
 * uma instalação de compilador sem os cabeçalhos de 32 bits da libc.
 */
#include <stddef.h>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef signed char int8_t;

typedef struct {
    uint8_t  barramento;
    uint8_t  estado;
    uint8_t  b, d, f;
    uint8_t  classe, subclasse, interface;
    uint16_t fabricante, modelo;
    int8_t   driver;
    uint8_t  _res[3];
    char     motivo[32];
} drivers_disp_t;

typedef struct {
    char     id[32];
    char     nome[65];
    uint8_t  origem;
    uint8_t  estado;
    uint8_t  dispositivos;
    uint8_t  reservado;
    uint8_t  _pad0;
    uint16_t versao[3];
    char     motivo[32];
} drivers_drv_t;

typedef struct {
    uint16_t dispositivos, ativos, sem_driver, falharam;
    uint16_t drivers;
    uint16_t pacotes;
    uint16_t pacotes_recusados, bandeiras;
} info_resumo_drivers_t;

typedef struct {
    uint16_t id;
    uint8_t  barramento, estado;
    uint8_t  classe, subclasse, interface, reservado;
    uint16_t fabricante, modelo;
    uint16_t driver;
    uint16_t _res;
    char     nome[65];
    char     motivo[32];
    uint8_t  _pad0;
} info_dispositivo_t;

typedef struct {
    uint16_t indice;
    uint8_t  origem, estado;
    uint16_t dispositivos;
    uint16_t versao[3];
    uint8_t  reservado;
    uint8_t  _pad0;
    char     id[32];
    char     nome[65];
    char     motivo[32];
    uint8_t  _pad1;
} info_driver_t;

typedef struct {
    uint16_t indice;
    uint8_t  estado, reservado;
    uint16_t driver;
    uint16_t _res;
    char     id[32];
    char     motivo[32];
} info_pacote_t;

_Static_assert(sizeof(drivers_disp_t) == 48, "drivers_disp_t mudou");
_Static_assert(offsetof(drivers_disp_t, motivo) == 16, "motivo desalinhado");
_Static_assert(sizeof(drivers_drv_t) == 140, "drivers_drv_t mudou");
_Static_assert(offsetof(drivers_drv_t, versao) == 102, "versao desalinhada");
_Static_assert(offsetof(drivers_drv_t, motivo) == 108, "motivo desalinhado");

_Static_assert(sizeof(info_resumo_drivers_t) == 16, "resumo mudou");
_Static_assert(sizeof(info_dispositivo_t) == 114, "dispositivo mudou");
_Static_assert(offsetof(info_dispositivo_t, nome) == 16, "nome desalinhado");
_Static_assert(sizeof(info_driver_t) == 144, "driver mudou");
_Static_assert(offsetof(info_driver_t, versao) == 6, "versao desalinhada");
_Static_assert(offsetof(info_driver_t, nome) == 46, "nome desalinhado");
_Static_assert(sizeof(info_pacote_t) == 72, "pacote mudou");
