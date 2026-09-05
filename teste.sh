#!/usr/bin/env bash
set -e

gcc -Wall -Wextra -O2 src/main.c -o cifra

printf "Teste de criptografia em C!\nArquivo com tamanho nao multiplo de quatro." > arquivo_teste.txt

./cifra arquivo_teste.txt arquivo_teste.cifrado AABBCCDD E
./cifra arquivo_teste.cifrado arquivo_teste_final.txt AABBCCDD D

cmp arquivo_teste.txt arquivo_teste_final.txt

echo "Teste concluido: arquivo original e arquivo decriptado sao identicos."
