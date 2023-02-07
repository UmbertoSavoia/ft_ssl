#ifndef ASN1_H
#define ASN1_H

#define ANS1_TAG_SEQUENCE   0x30
#define ASN1_TAG_INTEGER    0x02

void    asn1_pkcs1_rsa_private_key(t_rsa_key *key, int fd_out);

#endif