#ifndef __SSLKERNELITEM_H__
#define __SSLKERNELITEM_H__

#pragma once
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#ifndef _WIN32
#include <stdbool.h>
#endif
#include <string.h>
#include "hashmd5.h"

#ifdef _WIN32
#pragma comment(lib, "libeay32.lib") 
#pragma comment(lib, "ssleay32.lib") 
#endif

#define MAXSIGLEN  128
#define PUBLIC_KEY   0
#define PRIVATE_KEY  1

#define ECDH_SIZE 67
#define log_notice         printf

#ifdef __cplusplus
extern "C"{
#endif
    
bool base16Encode(unsigned char* pBufferIn, int nBufferIn, unsigned char* pBufferOut, int nBufferOut, int* pBufferOutUsed);

void ReadBufferHex(char * pcBufIn, int nLenBufIn, char * pcBufOut, int*pnLenBufOut);

int ReadFileECC(const char *szFilePath,char **pDataBuffer,int *pFilelen);

int CreateECDSAKey(const char *pFilePath);

int ECDSASignToBuffer(const char *szPrivateKeyPath,char *szBufferData,const int nBufferData,const char *szLicenceBuffer,unsigned int *pLicencelen);
	
int ECDSASignFileToLicenceFile(const char *szPrivateKeyPath,const char *szDataFilePath,const char *szLicencePath);
	
int ECDSASignBufferToLicenceFile(const char *szPrivateKeyPath,char *szBufferData,const int nBufferData,const char *szLicencePath);
	
int ECDSASignBufferBase16ToLicenceFile(const char *szPrivateKeyPath,char *szBufferData,const int nBufferData,const char *szLicencePath);

int ECDSAVerifyLicenceBuffer(const char *szPublicKeyPath,char *szBuffer,int nBufflen,char *szLicenceData,int nLicencelen);

int ECDSAVerifyLicenceFile(const char *szPublicKeyPath,const char *szDataFilePath,const char *szLicencePath);

int ECDSAVerifyBase16LicenceFile(const char *szPublicKeyPath,const char *szDataFilePath,const char *szLicencePath);

int GetECDHShareKeyFromSrvPublicKey(const char *szSrvPublicKey,const int nSrvPublicKeylen,const char *szSharekey,const char *szBufClientPubKey,int *pClientPubKeylen);


#ifdef __cplusplus
}
#endif

#endif

