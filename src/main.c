#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAM_BLOCO 4
#define RODADAS 3

/*
 * Projeto acadêmico: cifra de blocos simétrica didática de 32 bits.
 *
 * IMPORTANTE:
 * Esta implementação é adequada para fins educacionais e demonstração
 * de conceitos de criptografia (S-Box, subchaves, XOR e rotações).
 * NÃO deve ser usada para proteger dados sensíveis em produção.
 */

static const uint8_t SBOX[16] = {
    0xE, 0x4, 0xD, 0x1,
    0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC,
    0x5, 0x9, 0x0, 0x7
};

/* S-Box inversa: necessária para desfazer corretamente a substituição. */
static const uint8_t SBOX_INV[16] = {
    0xE, 0x3, 0x4, 0x8,
    0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6,
    0xB, 0x2, 0x0, 0x5
};

static uint32_t rotl32(uint32_t valor, unsigned int deslocamento) {
    deslocamento &= 31u;

    if (deslocamento == 0u) {
        return valor;
    }

    return (valor << deslocamento) | (valor >> (32u - deslocamento));
}

static uint32_t rotr32(uint32_t valor, unsigned int deslocamento) {
    deslocamento &= 31u;

    if (deslocamento == 0u) {
        return valor;
    }

    return (valor >> deslocamento) | (valor << (32u - deslocamento));
}

/* Aplica a S-Box em cada um dos 8 nibbles do bloco de 32 bits. */
static uint32_t aplicar_sbox_bloco(uint32_t bloco) {
    uint32_t resultado = 0;

    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (uint8_t)((bloco >> (i * 4)) & 0x0Fu);
        resultado |= ((uint32_t)SBOX[nibble]) << (i * 4);
    }

    return resultado;
}

/* Desfaz a substituição usando a S-Box inversa. */
static uint32_t aplicar_sbox_inversa_bloco(uint32_t bloco) {
    uint32_t resultado = 0;

    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (uint8_t)((bloco >> (i * 4)) & 0x0Fu);
        resultado |= ((uint32_t)SBOX_INV[nibble]) << (i * 4);
    }

    return resultado;
}

/* Gera uma subchave por rotação da chave principal. */
static uint32_t gerar_subchave(uint32_t chave_principal, int rodada) {
    return rotl32(chave_principal, (unsigned int)(rodada * 5));
}

/*
 * Encriptação de um bloco:
 * 1) XOR com subchave
 * 2) substituição não linear em todos os nibbles
 * 3) rotação do bloco
 */
static uint32_t encriptar_bloco(uint32_t bloco, uint32_t chave) {
    uint32_t resultado = bloco;

    for (int rodada = 1; rodada <= RODADAS; rodada++) {
        uint32_t subchave = gerar_subchave(chave, rodada);

        resultado ^= subchave;
        resultado = aplicar_sbox_bloco(resultado);
        resultado = rotl32(resultado, 4);
    }

    return resultado;
}

/*
 * Decriptação:
 * desfaz exatamente as operações da encriptação na ordem inversa.
 */
static uint32_t decriptar_bloco(uint32_t bloco, uint32_t chave) {
    uint32_t resultado = bloco;

    for (int rodada = RODADAS; rodada >= 1; rodada--) {
        uint32_t subchave = gerar_subchave(chave, rodada);

        resultado = rotr32(resultado, 4);
        resultado = aplicar_sbox_inversa_bloco(resultado);
        resultado ^= subchave;
    }

    return resultado;
}

/* Conversão determinística entre 4 bytes e uint32_t (big-endian). */
static uint32_t bytes_para_u32(const uint8_t bytes[TAM_BLOCO]) {
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8)  |
           ((uint32_t)bytes[3]);
}

static void u32_para_bytes(uint32_t valor, uint8_t bytes[TAM_BLOCO]) {
    bytes[0] = (uint8_t)((valor >> 24) & 0xFFu);
    bytes[1] = (uint8_t)((valor >> 16) & 0xFFu);
    bytes[2] = (uint8_t)((valor >> 8) & 0xFFu);
    bytes[3] = (uint8_t)(valor & 0xFFu);
}

/*
 * Padding no estilo PKCS#7, adaptado para blocos de 4 bytes:
 * - se faltam 3 bytes: adiciona 03 03 03
 * - se faltam 2 bytes: adiciona 02 02
 * - se falta 1 byte: adiciona 01
 * - se o arquivo já é múltiplo de 4: adiciona um bloco 04 04 04 04
 */
static int encriptar_arquivo(FILE *entrada, FILE *saida, uint32_t chave) {
    uint8_t buffer[TAM_BLOCO];

    while (1) {
        size_t lidos = fread(buffer, 1, TAM_BLOCO, entrada);

        if (lidos == TAM_BLOCO) {
            uint32_t bloco = bytes_para_u32(buffer);
            uint32_t cifrado = encriptar_bloco(bloco, chave);

            u32_para_bytes(cifrado, buffer);

            if (fwrite(buffer, 1, TAM_BLOCO, saida) != TAM_BLOCO) {
                perror("Erro ao escrever arquivo cifrado");
                return 0;
            }

            continue;
        }

        if (ferror(entrada)) {
            perror("Erro ao ler arquivo de entrada");
            return 0;
        }

        uint8_t padding = (uint8_t)(TAM_BLOCO - lidos);

        for (size_t i = lidos; i < TAM_BLOCO; i++) {
            buffer[i] = padding;
        }

        uint32_t bloco = bytes_para_u32(buffer);
        uint32_t cifrado = encriptar_bloco(bloco, chave);

        u32_para_bytes(cifrado, buffer);

        if (fwrite(buffer, 1, TAM_BLOCO, saida) != TAM_BLOCO) {
            perror("Erro ao escrever bloco final cifrado");
            return 0;
        }

        break;
    }

    return 1;
}

static int decriptar_arquivo(FILE *entrada, FILE *saida, uint32_t chave) {
    if (fseek(entrada, 0, SEEK_END) != 0) {
        perror("Erro ao verificar tamanho do arquivo");
        return 0;
    }

    long tamanho = ftell(entrada);

    if (tamanho <= 0 || tamanho % TAM_BLOCO != 0) {
        fprintf(stderr, "Erro: arquivo cifrado invalido.\n");
        return 0;
    }

    rewind(entrada);

    long total_blocos = tamanho / TAM_BLOCO;
    uint8_t buffer[TAM_BLOCO];

    for (long i = 0; i < total_blocos; i++) {
        if (fread(buffer, 1, TAM_BLOCO, entrada) != TAM_BLOCO) {
            perror("Erro ao ler arquivo cifrado");
            return 0;
        }

        uint32_t bloco = bytes_para_u32(buffer);
        uint32_t decifrado = decriptar_bloco(bloco, chave);

        u32_para_bytes(decifrado, buffer);

        size_t bytes_para_escrever = TAM_BLOCO;

        if (i == total_blocos - 1) {
            uint8_t padding = buffer[TAM_BLOCO - 1];

            if (padding < 1 || padding > TAM_BLOCO) {
                fprintf(stderr,
                        "Erro: padding invalido. A chave pode estar incorreta "
                        "ou o arquivo pode estar corrompido.\n");
                return 0;
            }

            for (uint8_t j = 0; j < padding; j++) {
                if (buffer[TAM_BLOCO - 1 - j] != padding) {
                    fprintf(stderr,
                            "Erro: padding invalido. A chave pode estar incorreta "
                            "ou o arquivo pode estar corrompido.\n");
                    return 0;
                }
            }

            bytes_para_escrever = TAM_BLOCO - padding;
        }

        if (bytes_para_escrever > 0 &&
            fwrite(buffer, 1, bytes_para_escrever, saida) != bytes_para_escrever) {
            perror("Erro ao escrever arquivo decriptado");
            return 0;
        }
    }

    return 1;
}

static int modo_valido(const char *modo) {
    return strcmp(modo, "E") == 0 ||
           strcmp(modo, "e") == 0 ||
           strcmp(modo, "D") == 0 ||
           strcmp(modo, "d") == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr,
                "Uso: %s <entrada> <saida> <chave_hex> <E|D>\n"
                "  E = encriptar\n"
                "  D = decriptar\n"
                "Exemplo: %s arquivo.txt arquivo.cifrado AABBCCDD E\n",
                argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    if (!modo_valido(argv[4])) {
        fprintf(stderr, "Erro: modo invalido. Utilize E para encriptar ou D para decriptar.\n");
        return EXIT_FAILURE;
    }

    char *fim = NULL;
    unsigned long chave_lida = strtoul(argv[3], &fim, 16);

    if (argv[3][0] == '\0' || *fim != '\0' || chave_lida > UINT32_MAX) {
        fprintf(stderr, "Erro: a chave deve ser um valor hexadecimal de ate 32 bits.\n");
        return EXIT_FAILURE;
    }

    uint32_t chave = (uint32_t)chave_lida;
    int decriptar = (argv[4][0] == 'D' || argv[4][0] == 'd');

    FILE *entrada = fopen(argv[1], "rb");

    if (!entrada) {
        perror("Erro ao abrir arquivo de entrada");
        return EXIT_FAILURE;
    }

    FILE *saida = fopen(argv[2], "wb");

    if (!saida) {
        perror("Erro ao abrir arquivo de saida");
        fclose(entrada);
        return EXIT_FAILURE;
    }

    int sucesso;

    if (decriptar) {
        sucesso = decriptar_arquivo(entrada, saida, chave);
    } else {
        sucesso = encriptar_arquivo(entrada, saida, chave);
    }

    fclose(entrada);
    fclose(saida);

    if (!sucesso) {
        remove(argv[2]);
        return EXIT_FAILURE;
    }

    printf("Operacao concluida com sucesso!\n");
    return EXIT_SUCCESS;
}
