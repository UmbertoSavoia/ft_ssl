#ifndef ASN1_H
#define ASN1_H

#include "rsa.h"
#include "dsa.h"

#define ANS1_TAG_SEQUENCE   0x30
#define ASN1_TAG_INTEGER    0x02
#define ASN1_TAG_BITSTRING  0x03

#define PEM_HEADER_RSA_PRIVATE "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_FOOTER_RSA_PRIVATE "-----END RSA PRIVATE KEY-----"
#define PEM_HEADER_RSA_PUBLIC "-----BEGIN PUBLIC KEY-----"
#define PEM_FOOTER_RSA_PUBLIC "-----END PUBLIC KEY-----"
#define PEM_HEADER_DSA_PARAM "-----BEGIN DSA PARAMETERS-----"
#define PEM_FOOTER_DSA_PARAM "-----END DSA PARAMETERS-----"
#define PEM_HEADER_DSA_PRIVATE "-----BEGIN DSA PRIVATE KEY-----"
#define PEM_FOOTER_DSA_PRIVATE "-----END DSA PRIVATE KEY-----"

void    asn1_pkcs1_rsa_private_key(t_rsa_key *key, int fd_out);
void    asn1_pkcs1_rsa_public_key(t_rsa_key *key, int fd_out);

int     asn1_parse_pem_rsa_private_key(t_rsa_key *rsa, int fd_in);
int     asn1_parse_pem_rsa_public_key(t_rsa_key *rsa, int fd_in);

void    asn1_pkcs1_dsa_param(t_dsa_param *param, int fd_out);
void    asn1_pkcs1_dsa_private_key(t_dsa_key_priv *key, int fd_out);

#endif