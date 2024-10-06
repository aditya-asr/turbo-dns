#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <oqs/oqs.h>
#include <constants.h>

unsigned char *gen_hmac(unsigned char *, int, unsigned char *, int);

unsigned char *derive_hkdf_key(unsigned char *, int);
