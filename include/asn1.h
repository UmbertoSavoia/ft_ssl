#ifndef ASN1_H
#define ASN1_H

#include "rsa.h"

#define ANS1_TAG_SEQUENCE   0x30
#define ASN1_TAG_INTEGER    0x02
#define ASN1_TAG_BITSTRING  0x03

#define PEM_HEADER_RSA_PRIVATE "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_FOOTER_RSA_PRIVATE "-----END RSA PRIVATE KEY-----"
#define PEM_HEADER_RSA_PUBLIC "-----BEGIN PUBLIC KEY-----"
#define PEM_FOOTER_RSA_PUBLIC "-----END PUBLIC KEY-----"

void    asn1_pkcs1_rsa_private_key(t_rsa_key *key, int fd_out);
void    asn1_pkcs1_rsa_public_key(t_rsa_key *key, int fd_out);

int     asn1_parse_pem_rsa_private_key(t_rsa_key *rsa, int fd_in);
int     asn1_parse_pem_rsa_public_key(t_rsa_key *rsa, int fd_in);

#endif