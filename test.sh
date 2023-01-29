#!/bin/bash

declare -a BufferArray=(
  "h" "hello" "hello world" "12345678" "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
)
declare -a DigestArray=( "md5" "sha256" "whirlpool" )
declare -a CipherArray=( "des" )
declare -a BlockModeArray=( "ecb" "cbc" "cfb" "ofb" )
KEY="0011223344556677"
IV="1122334455667788"

test_digest() {
  for digest in "${DigestArray[@]}"; do
    echo "$digest" | tr '[:lower:]' '[:upper:]'
    for buf in "${BufferArray[@]}"; do
        diff <(echo -ne $buf | openssl $digest | cut -d ' ' -f 2) <(echo -ne $buf | ./ft_ssl $digest) > /dev/null
        if [ $? -eq 0 ]
        then
          echo -e "\033[0;90m \033[42m OK \033[0m"
        else
            echo -e "\033[0;90m \033[41m KO \033[0m"
            #echo "buf: $buf"
        fi
    done
  done
}

test_cipher_enc() {
  echo "CIPHER ENCRYPTION"
  for cipher in "${CipherArray[@]}"; do
    for mode in "${BlockModeArray[@]}"; do
      echo "$cipher-$mode" | tr '[:lower:]' '[:upper:]'
      for buf in "${BufferArray[@]}"; do
        diff <(echo -ne $buf | openssl $cipher-$mode -K $KEY -iv $IV 2> /dev/null) <(echo -ne $buf | ./ft_ssl $cipher-$mode -k $KEY -v $IV) > /dev/null
        if [ $? -eq 0 ]
        then
          echo -e "\033[0;90m \033[42m OK \033[0m"
        else
            echo -e "\033[0;90m \033[41m KO \033[0m"
            #echo "buf: $buf"
        fi
      done
    done
  done
}

test_cipher_dec() {
  echo "CIPHER DECRYPTION"
  for cipher in "${CipherArray[@]}"; do
    for mode in "${BlockModeArray[@]}"; do
      echo "$cipher-$mode" | tr '[:lower:]' '[:upper:]'
      for buf in "${BufferArray[@]}"; do
        dec=`echo -ne $buf | openssl $cipher-$mode -K $KEY -iv $IV 2> /dev/null | ./ft_ssl $cipher-$mode -k $KEY -v $IV -d`
        diff <(echo -ne $dec) <(echo -ne $buf) > /dev/null
        if [ $? -eq 0 ]
        then
          echo -e "\033[0;90m \033[42m OK \033[0m"
        else
            echo -e "\033[0;90m \033[41m KO \033[0m"
            #echo "buf: $buf"
        fi
      done
    done
  done
}

test_triple_des_enc() {
  echo "TRIPLE-DES ENCRYPTION"
  for mode in "${BlockModeArray[@]}"; do
    echo "des3-$mode" | tr '[:lower:]' '[:upper:]'
    for buf in "${BufferArray[@]}"; do
      diff <(echo -ne $buf | openssl des-ede3-$mode -K $KEY$KEY$KEY -iv $IV 2> /dev/null) <(echo -ne $buf | ./ft_ssl des3-$mode -k $KEY$KEY$KEY -v $IV) > /dev/null
      if [ $? -eq 0 ]
      then
        echo -e "\033[0;90m \033[42m OK \033[0m"
      else
          echo -e "\033[0;90m \033[41m KO \033[0m"
          #echo "buf: $buf"
      fi
    done
  done
}

test_triple_des_dec() {
  echo "TRIPLE-DES DECRYPTION"
  for mode in "${BlockModeArray[@]}"; do
    echo "des3-$mode" | tr '[:lower:]' '[:upper:]'
    for buf in "${BufferArray[@]}"; do
      dec=`echo -ne $buf | openssl des-ede3-$mode -K $KEY$KEY$KEY -iv $IV 2> /dev/null | ./ft_ssl des3-$mode -k $KEY$KEY$KEY -v $IV -d`
      diff <(echo -ne $dec) <(echo -ne $buf) > /dev/null
      if [ $? -eq 0 ]
      then
        echo -e "\033[0;90m \033[42m OK \033[0m"
      else
          echo -e "\033[0;90m \033[41m KO \033[0m"
          #echo "buf: $buf"
      fi
    done
  done
}

echo "-----------------------------------------------"
test_digest
echo "-----------------------------------------------"
paste <(test_cipher_enc) <(test_cipher_dec) | column -s $'\t' -t
echo "-----------------------------------------------"
paste <(test_triple_des_enc) <(test_triple_des_dec) | column -s $'\t' -t
