# Symmetric Block Cipher in C

Projeto acadêmico desenvolvido no curso de Ciência da Computação com o objetivo de estudar, na prática, conceitos de criptografia simétrica e programação de baixo nível em C.

## Sobre o projeto

A aplicação implementa uma cifra de blocos didática de 32 bits utilizando:

- S-Box de substituição;
- S-Box inversa para decriptação;
- geração de subchaves;
- operações XOR;
- rotações de bits;
- processamento de arquivos binários;
- padding para arquivos cujo tamanho não é múltiplo de 4 bytes.

> **Aviso:** esta cifra foi criada para fins educacionais. Ela não substitui algoritmos criptográficos consolidados, como AES, e não deve ser utilizada para proteger informações sensíveis em produção.

## Tecnologias

- C
- GCC
- Linux / WSL
- Git / GitHub

## Estrutura sugerida

```text
symmetric-block-cipher-c/
├── src/
│   └── main.c
├── examples/
│   └── arquivo.txt
├── docs/
│   └── relatorio-extensao.pdf
├── README.md
├── .gitignore
└── LICENSE
```

## Compilação

```bash
gcc -Wall -Wextra -O2 src/main.c -o cifra
```

## Uso

### Encriptar

```bash
./cifra arquivo.txt arquivo.cifrado AABBCCDD E
```

### Decriptar

```bash
./cifra arquivo.cifrado arquivo_final.txt AABBCCDD D
```

A mesma chave utilizada na encriptação deve ser utilizada na decriptação.

## Como funciona

Cada bloco de 32 bits passa por três rodadas. Em cada rodada de encriptação são realizadas:

1. combinação XOR com uma subchave;
2. substituição de cada nibble por uma S-Box;
3. rotação do bloco.

Na decriptação, essas operações são desfeitas na ordem inversa utilizando a S-Box inversa.

## Padding

Arquivos são processados em blocos de 4 bytes. Para garantir que qualquer tamanho de arquivo possa ser processado, o programa utiliza padding no estilo PKCS#7 adaptado para blocos de 4 bytes.

## Principais aprendizados

- manipulação de bits em C;
- operações XOR e rotações;
- conceitos de substituição e difusão;
- manipulação de arquivos binários;
- implementação de operações reversíveis;
- validação de entrada;
- depuração e testes de software.

## Contexto acadêmico

Projeto de Extensão desenvolvido durante o curso de Ciência da Computação, abordando conceitos de segurança da informação, criptografia simétrica e desenvolvimento em linguagem C.
