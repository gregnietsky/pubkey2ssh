/*
 * An implementation of convertion from OpenSSL to OpenSSH public key format
 *
 * Copyright (c) 2008 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * 
 */

#include <memory.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define FORMAT_RAW 100
#define FORMAT_PEM 101
#define FORMAT_DER 102

static unsigned char pSshHeader[11] = { 0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2D, 0x72, 0x73, 0x61};

static int SshEncodeBuffer(unsigned char *pEncoding, int bufferLen, unsigned char* pBuffer)
{
   int adjustedLen = bufferLen, index;
   if (*pBuffer & 0x80)
   {
      adjustedLen++;
      pEncoding[4] = 0;
      index = 5;
   }
   else
   {
      index = 4;
   }
   pEncoding[0] = (unsigned char) (adjustedLen >> 24);
   pEncoding[1] = (unsigned char) (adjustedLen >> 16);
   pEncoding[2] = (unsigned char) (adjustedLen >>  8);
   pEncoding[3] = (unsigned char) (adjustedLen      );
   memcpy(&pEncoding[index], pBuffer, bufferLen);
   return index + bufferLen;
}

static void GetOptions(int argc, char **argv, int *iFileType) {
   int c;
   while ((c = getopt (argc, argv, "dpr")) != -1)
      switch (c)
      {
         case 'd':
            *iFileType = FORMAT_DER;
            break;
         case 'p':
            *iFileType = FORMAT_PEM;
            break;
         case 'r':
            *iFileType = FORMAT_RAW;
            break;
         default:
            abort();
      }
}

int main(int argc, char**  argv) {
   int iRet = 0;
   int nLen = 0, eLen = 0;
   int encodingLength = 0;
   int index = 0;
   int iFileType = FORMAT_RAW;
   unsigned char *nBytes = NULL, *eBytes = NULL;
   unsigned char* pEncoding = NULL;
   FILE* pFile = NULL;
   EVP_PKEY *pPubKey = NULL;
   X509 *pCert = NULL;
   RSA* pRsa = NULL;
   BIO *bio, *b64;

   ERR_load_crypto_strings(); 
   OpenSSL_add_all_algorithms();

   GetOptions(argc, argv, &iFileType);

   if (argc-optind != 2)
   {
      printf("usage: %s [-d|-p|-r] public_key_file_name ssh_key_description\n", argv[0]);
      printf("   -d   x509 DER\n");
      printf("   -p   x509 PEM\n");
      printf("   -r   raw public key\n");
      iRet = 1;
      goto error;
   }

   if (!strcmp(argv[argc-2],"-")) {
     pFile = stdin;
   } else {
     pFile = fopen(argv[argc-2], "rt");
   }
   if (!pFile)
   {
      printf("Failed to open the given file\n");
      iRet = 2;
      goto error;
   }

   switch (iFileType) {
      case FORMAT_RAW:
         pPubKey = PEM_read_PUBKEY(pFile, NULL, NULL, NULL);
         break;
      case FORMAT_PEM:
         pCert = PEM_read_X509_AUX(pFile, NULL, NULL, NULL);
         if (!pCert)
         {
            printf("Unable to read PEM format from the given file: %s\n", ERR_error_string(ERR_get_error(), NULL));
            iRet = 6;
            goto error;
         }
         pPubKey = X509_get_pubkey(pCert);
         break;
      case FORMAT_DER:
         pCert = d2i_X509_fp(pFile, NULL);
         if (!pCert)
         {
            printf("Unable to read DER format from the given file: %s\n", ERR_error_string(ERR_get_error(), NULL));
            iRet = 7;
            goto error;
         }
         pPubKey = X509_get_pubkey(pCert);
   }
   if (!pPubKey)
   {
      printf("Unable to decode public key from the given file: %s\n", ERR_error_string(ERR_get_error(), NULL));
      iRet = 3;
      goto error;
   }

   if (EVP_PKEY_type(pPubKey->type) != EVP_PKEY_RSA)
   {
      printf("Only RSA public keys are currently supported\n");
      iRet = 4;
      goto error;
   }

   pRsa = EVP_PKEY_get1_RSA(pPubKey);
   if (!pRsa)
   {
      printf("Failed to get RSA public key : %s\n", ERR_error_string(ERR_get_error(), NULL));
      iRet = 5;
      goto error;
   }

   // reading the modulus
   nLen = BN_num_bytes(pRsa->n);
   nBytes = (unsigned char*) malloc(nLen);
   BN_bn2bin(pRsa->n, nBytes);

   // reading the public exponent
   eLen = BN_num_bytes(pRsa->e);
   eBytes = (unsigned char*) malloc(eLen);
   BN_bn2bin(pRsa->e, eBytes);

   encodingLength = 11 + 4 + eLen + 4 + nLen;
   // correct depending on the MSB of e and N
   if (eBytes[0] & 0x80)
      encodingLength++;
   if (nBytes[0] & 0x80)
      encodingLength++;

   pEncoding = (unsigned char*) malloc(encodingLength);
   memcpy(pEncoding, pSshHeader, 11);

   index = SshEncodeBuffer(&pEncoding[11], eLen, eBytes);
   index = SshEncodeBuffer(&pEncoding[11 + index], nLen, nBytes);

   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   bio = BIO_new_fp(stdout, BIO_NOCLOSE);
   BIO_printf(bio, "ssh-rsa ");
   bio = BIO_push(b64, bio);
   BIO_write(bio, pEncoding, encodingLength);
   BIO_flush(bio);
   bio = BIO_pop(b64);
   BIO_printf(bio, " %s\n", argv[argc-1]);
   BIO_flush(bio);
   BIO_free_all(bio);
   BIO_free(b64);

error:
   if (pFile)
      fclose(pFile);
   if (pRsa)
      RSA_free(pRsa);
   if (pPubKey)
      EVP_PKEY_free(pPubKey);
   if (nBytes)
      free(nBytes);
   if (eBytes)
      free(eBytes);
   if (pEncoding)
      free(pEncoding);

   EVP_cleanup();
   ERR_free_strings();
   return iRet;
}

/* vim: set tabstop=8 softtabstop=3 shiftwidth=3 expandtab: */
