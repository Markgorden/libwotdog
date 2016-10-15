#include "SSLKernelItem.h"

//用于读取指定文件，参数返回数据，内部申请内存外部释放
int ReadFileECC(const char *szFilePath, char **pDataBuffer, int *pFilelen) {
	int ret = 0;
	FILE *file = NULL;
	int nFilelen = 0;
	char *pDataFileBuffer = NULL;
	do {
		file = fopen(szFilePath, "rb");
		if (!file) {
			printf("fopen文件%s打开失败\n", szFilePath);
			ret = -1;
			break;
		}

		fseek(file, 0L, SEEK_END); /* 定位到文件末尾 */
		nFilelen = ftell(file);  // 计算文件长度
		pDataFileBuffer = (char*) malloc(nFilelen);
		if (pDataFileBuffer) {
			memset(pDataFileBuffer, 0, nFilelen);
			fseek(file, 0L, SEEK_SET); /* 定位到文件开头 */
			fread(pDataFileBuffer, nFilelen, 1, file);

			// 过滤回车换行
			int i = 0;
			int j = 0;
			for (; i < nFilelen; ++ i) {
				if (*(pDataFileBuffer + i) == '\n' || *(pDataFileBuffer + i) == '\r') {
					continue;
				}
				*(pDataFileBuffer + j) = *(pDataFileBuffer + i);
				++j;
			}
			if(j < i)
			{
				*(pDataFileBuffer + j) = '\0';
			}

			*pDataBuffer = pDataFileBuffer;
			*pFilelen = j;
			fclose(file);
			file = NULL;
			return 1;
		} else {
			printf("ReadFileECC申请内存失败\n");
			ret = -2;
			break;
		}
	} while (0);

	if (file) {
		fclose(file);
		file = NULL;
	}

	if (pDataFileBuffer) {
		free(pDataFileBuffer);
	}

	*pFilelen = 0;
	*pDataBuffer = NULL;
	return ret;
}

void ReadBufferHex(char * pcBufIn, int nLenBufIn, char * pcBufOut, int*pnLenBufOut)
{
	if (NULL == pcBufIn || NULL == pcBufOut || NULL == pnLenBufOut)
	{
		return;
	}

	int nLenBufOut = 0;
	int i = 0;
	for (i = 0; i < nLenBufIn; i += 2)
	{
		char cByte[4] = {0};
		sscanf(pcBufIn, "%2x", cByte);
#ifdef _SDK_BE_
		memcpy(pcBufOut, cByte+3, 1);
#else
		memcpy(pcBufOut, cByte, 1);
#endif

		pcBufIn  += 2;
		pcBufOut += 1;
		nLenBufOut +=1;
	}

	(*pnLenBufOut) = nLenBufOut;
}

int CreateECDSAKey(const char *pFilePath)
{
	int ret = 0;
	BIO 	*pBioKeyFile = NULL;
	EC_KEY  *ec_key = NULL;;   
	char    *pFileAllPath = NULL;
	do 
	{
		EC_GROUP *ec_group;  
		ec_key = EC_KEY_new();

		if (!ec_key)  
		{ 
			ret = -1;
			printf("Error：EC_KEY_new()\n");   
			break;  
		}   

		ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
		if (!ec_group)
		{   
			ret = -2;
			printf("Error：CreateECDSAKey--EC_GROUP_new_by_curve_name()\n");  
			break;
		}
		
		EC_GROUP_set_asn1_flag(ec_group, OPENSSL_EC_NAMED_CURVE);
		EC_GROUP_set_point_conversion_form(ec_group, POINT_CONVERSION_UNCOMPRESSED);

		if(1 != EC_KEY_set_group(ec_key,ec_group))  
		{   
			ret = -3;
			printf("Error：CreateECDSAKey--EC_KEY_set_group()\n");  
			break;
		}
		
		if (!EC_KEY_generate_key(ec_key))
		{
			ret = -3;
			printf("Error：CreateECDSAKey--EC_KEY_generate_key()\n");
			break;
		}

		char *pPublicKey  = "public.pem";
		char *pPrivateKey = "ec_key.pem";
		//////////////////////////////////////////////////////////////////////////
		//保存公钥
		int nPathLen = strlen(pFilePath) + strlen(pPublicKey)+ strlen(pPrivateKey)+2;
		pFileAllPath = (char*)malloc(nPathLen);
		if (!pFileAllPath)
		{
			ret = -5;
			printf("CreateECDSAKey--申请内存失败\n");
			break;
		}

		//生成保存公钥的文件路径
		memset((void*)pFileAllPath,0,nPathLen);
		strcpy(pFileAllPath,pFilePath);
		strcat(pFileAllPath,"/");
		strcat(pFileAllPath,pPublicKey);

		pBioKeyFile = BIO_new_file(pFileAllPath, "wb");

		if (!pBioKeyFile)
		{
			ret = -6;
			printf("BIO创建文件%s失败\n",pFileAllPath);
			break;
		}
		
		if (1 != PEM_write_bio_EC_PUBKEY(pBioKeyFile, ec_key))
		{
			ret = -7;
			printf("PEM_write_bio_EC_PUBKEY写入key文件%s失败\n",pFileAllPath);
			break;
		}

		//////////////////////////////////////////////////////////////////////////
		//保存私钥
		//生成保存私钥的文件路径
		memset((void*)pFileAllPath,0,nPathLen);
		strcpy(pFileAllPath,pFilePath);
		strcat(pFileAllPath,"/");
		strcat(pFileAllPath,pPrivateKey);

		BIO_free(pBioKeyFile); 
		pBioKeyFile = BIO_new_file(pFileAllPath, "wb");
		if (!pBioKeyFile)
		{
			ret = -8;
			printf("BIO创建文件%s失败\n",pFileAllPath);
			break;
		}

		PEM_write_bio_ECPKParameters(pBioKeyFile, ec_group);
		if (1 != PEM_write_bio_ECPrivateKey(pBioKeyFile, ec_key,NULL,NULL,0,NULL,NULL))
		{
			ret = -9;
			printf("PEM_write_bio_EC_PUBKEY写入key文件%s失败\n",pFileAllPath);
			break;
		}

		ret = 1;
	} while (0);

	if (ec_key)
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}

	if (pFileAllPath)
	{
		free(pFileAllPath);
		pFileAllPath = NULL;
	}

	if (pBioKeyFile)
	{
		BIO_free(pBioKeyFile); 
		pBioKeyFile = NULL;
	}

	return ret;
}

int ECDSASignToBuffer(const char *szPrivateKeyPath,char *szBufferData,const int nBufferData,const char *szLicenceBuffer,unsigned int *pLicencelen)
{
	int ret = 0;
	EC_KEY *ec_key = NULL; 
	BIO    *pBioKeyFile = NULL;

	do 
	{
		if (!szBufferData || !szLicenceBuffer || !pLicencelen)
		{
			ret = 0;
			printf("参数错误\n");
			break;
		}

		pBioKeyFile = BIO_new_file(szPrivateKeyPath,"rb");
		ec_key = PEM_read_bio_ECPrivateKey(pBioKeyFile, NULL, NULL,NULL);

		if (!ec_key)
		{
			ret = -3;
			printf("从文件%s中读取密钥解密失败\n",szPrivateKeyPath);
			break;
		}

		unsigned char *signature = NULL;
		unsigned char digest[32] = {};
		unsigned int dgst_len = 0;

		EVP_MD_CTX md_ctx;
		EVP_MD_CTX_init(&md_ctx);
		EVP_DigestInit(&md_ctx,EVP_sha256());
		EVP_DigestUpdate(&md_ctx, (const void*)szBufferData,nBufferData);
		EVP_DigestFinal(&md_ctx, digest, &dgst_len);

		/* 数据签名 */   
		if (!ECDSA_sign(0,(const unsigned char *)digest, dgst_len,(unsigned char *)szLicenceBuffer,pLicencelen,ec_key)) 
		{
			ret = -4;
			printf("ECDSA_sign error\n");
			break;
		}

		ret = 1;
	} while (0);

	if (pBioKeyFile)
	{
		BIO_free(pBioKeyFile);
		pBioKeyFile = NULL;
	}

	if (ec_key)
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	
	return ret;
}

int ECDSAVerifyLicenceBuffer(const char *szPublicKeyPath,char *szBuffer,int nBufflen,char *szLicenceData,int nLicencelen)
{
	int ret;  
	EC_KEY *ec_key = NULL;  
	EC_GROUP *ec_group = NULL;   
	BIO *pBioKeyFile = NULL;
	do 
	{
		pBioKeyFile = BIO_new_file(szPublicKeyPath,"rb");
		ec_key = PEM_read_bio_EC_PUBKEY(pBioKeyFile, NULL, NULL,NULL);

		if (ec_key == NULL)
		{
			ret = -6;
			printf("Error：ECDSAVerifyLicenceBuffer PEM_read_bio_EC_PUBKEY\n");
			break;
		}

		unsigned char digest[32]={};  
		unsigned int  dgst_len = 0;   
		EVP_MD_CTX md_ctx;  
		EVP_MD_CTX_init(&md_ctx);  
		EVP_DigestInit(&md_ctx, EVP_sha256()); 
		// 散列算法  
		EVP_DigestUpdate(&md_ctx, (const void*)szBuffer,nBufflen);  
		EVP_DigestFinal(&md_ctx, digest, &dgst_len);

		/* 验证签名 */
		//nLicencelen++;
		ret = ECDSA_verify(0,(const unsigned char*)digest, dgst_len, (const unsigned char *)szLicenceData, nLicencelen,ec_key);
	} while (0);

	if (ec_key)
	{
		EC_KEY_free(ec_key); 
		ec_key = NULL;
	}

	if (pBioKeyFile)
	{
		BIO_free(pBioKeyFile);
		pBioKeyFile = NULL;
	}

	return ret; 
}

int ECDSASignBufferToLicenceFile(const char *szPrivateKeyPath,char *szBufferData,const int nBufferData,const char *szLicencePath)
{
	int nRet = 0;
	unsigned int nLicencelen   = 0;
	char szLicenceBuffer[1024] = {};
	nRet = ECDSASignToBuffer(szPrivateKeyPath,szBufferData,nBufferData,szLicenceBuffer,&nLicencelen);
	if (1 == nRet)
	{
		FILE *file = fopen(szLicencePath,"wb");
		if (file)
		{
			fwrite(szLicenceBuffer,nLicencelen,1,file);
			fclose(file);
		}
	}
	return nRet;

}

bool base16Encode(unsigned char* pBufferIn, int nBufferIn, unsigned char* pBufferOut, int nBufferOut, int* pBufferOutUsed)
{
	*pBufferOutUsed = 0;

	if (!pBufferIn || !pBufferOut)
		return false;

	if (nBufferOut < (nBufferIn * 2))
		return false;

	int i = 0;
	for (; i < nBufferIn; i++)
	{
		char szTmp[3] = {0};
		sprintf(szTmp, "%02X", *(pBufferIn + i));
		strcat((char*)pBufferOut, szTmp);
		*pBufferOutUsed += 2;
	}
	return true;
}

int ECDSASignBufferBase16ToLicenceFile(const char *szPrivateKeyPath,char *szBufferData,const int nBufferData,const char *szLicencePath)
{
	int nRet = 0;
	unsigned int nLicencelen   = 0;
	char szLicenceBuffer[512] = {};
	nRet = ECDSASignToBuffer(szPrivateKeyPath,szBufferData,nBufferData,szLicenceBuffer,&nLicencelen);
	if (1 == nRet)
	{
		FILE *file = fopen(szLicencePath,"wb");
		if (file)
		{
			int nLicenceOutlen      = 0;
			int nLicenceBase16len   = 1024;
			char szLicenceBase16Buffer[1024] = {};
			base16Encode((unsigned char *)szLicenceBuffer,nLicencelen,(unsigned char *)szLicenceBase16Buffer,nLicenceBase16len,&nLicenceOutlen);
			fwrite(szLicenceBase16Buffer,nLicenceOutlen,1,file);
			fclose(file);
		}
		else
		{
			nRet = 0;
		}
	}

	return nRet;
}


int ECDSASignFileToLicenceFile(const char *szPrivateKeyPath,const char *szDataFilePath,const char *szLicencePath)
{
	int nRet = 0;
	FILE *file = NULL;
	char *szDataFile = NULL;
	unsigned int nLicencelen   = 0;
	char szLicenceBuffer[1024] = {};

	do 
	{
		int nFileLen;
		if (1 != ReadFileECC(szDataFilePath,&szDataFile,&nFileLen))
		{
			printf("文件%s打开失败\n",szDataFilePath);
			nRet = -1;
			break;
		}

		nRet = ECDSASignToBuffer(szPrivateKeyPath,szDataFile,nFileLen,szLicenceBuffer,&nLicencelen);
		if (1 == nRet)
		{
			file = fopen(szLicencePath,"wb");
			if (file)
			{
				fwrite(szLicenceBuffer,nLicencelen,1,file);
			}
		}
	} while (0);
	
	if (file)
	{
		fclose(file);
		file = NULL;
	}

	if (szDataFile)
	{
		free(szDataFile);
		szDataFile = NULL;
	}
	
	return nRet;
}

int ECDSAVerifyLicenceFile(const char *szPublicKeyPath,const char *szDataFilePath,const char *szLicencePath)
{
	int ret = 0;
	FILE *file = NULL; 
	char *pDataFileBuffer  = NULL;
	char *szLicenceBuffer  = NULL;

	do 
	{
		int nDataFilelen  = 0;
		int nLicencelen   = 0;
		if (1 != ReadFileECC(szDataFilePath,&pDataFileBuffer,&nDataFilelen))
		{
			printf("文件%s打开失败\n",szDataFilePath);
			ret = -1;
			break;
		}
		
		if (1 != ReadFileECC(szLicencePath,&szLicenceBuffer,&nLicencelen))
		{
			printf("文件%s打开失败\n",szLicencePath);
			ret = -1;
			break;
		}
		ret = ECDSAVerifyLicenceBuffer(szPublicKeyPath,pDataFileBuffer,nDataFilelen,szLicenceBuffer,nLicencelen);
	} while (0);

	if (pDataFileBuffer)
	{
		free(pDataFileBuffer);
		pDataFileBuffer = NULL;
	}

	if (szLicenceBuffer)
	{
		free(szLicenceBuffer);
		szLicenceBuffer = NULL;
	}

	if (file)
	{
		fclose(file);
		file = NULL;
	}
	return ret;

}

int ECDSAVerifyBase16LicenceFile(const char *szPublicKeyPath,const char *szDataFilePath,const char *szLicencePath)
{
	int ret = 0;
	FILE *file = NULL; 
	char *pDataFileBuffer  = NULL;
	char *szLicenceBuffer  = NULL;
	char *szDecodeLicenceBuffer = NULL;

	do 
	{
		int nDataFilelen  = 0;
		int nLicencelen   = 0;
		if (1 != ReadFileECC(szDataFilePath,&pDataFileBuffer,&nDataFilelen))
		{
			printf("文件%s打开失败\n",szDataFilePath);
			ret = -1;
			break;
		}

		if (1 != ReadFileECC(szLicencePath,&szLicenceBuffer,&nLicencelen))
		{
			printf("文件%s打开失败\n",szLicencePath);
			ret = -2;
			break;
		}

		
		szDecodeLicenceBuffer = (char*)malloc(nLicencelen*2+5);

		int nOutlen = 0;
		ReadBufferHex(szLicenceBuffer,nLicencelen,szDecodeLicenceBuffer,&nOutlen);
		ret = ECDSAVerifyLicenceBuffer(szPublicKeyPath,pDataFileBuffer,nDataFilelen,szDecodeLicenceBuffer,nOutlen);
	} while (0);

	if (pDataFileBuffer)
	{
		free(pDataFileBuffer);
		pDataFileBuffer = NULL;
	}

	if (szDecodeLicenceBuffer)
	{
		free(szDecodeLicenceBuffer);
		szDecodeLicenceBuffer = NULL;
	}

	if (szLicenceBuffer)
	{
		free(szLicenceBuffer);
		szLicenceBuffer = NULL;
	}

	if (file)
	{
		fclose(file);
		file = NULL;
	}
	return ret;
}

int GetECDHShareKeyFromSrvPublicKey(const char *szSrvPublicKey,const int nSrvPublicKeylen,const char *szSharekey,const char *szBufClientPubKey,int *pClientPubKeylen)
{
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_algorithms();

	int nResult = 0;
	EC_KEY   *ecKeyClient = NULL;
	EC_POINT *pointServer = NULL;
	do
	{
		ecKeyClient = EC_KEY_new_by_curve_name(NID_secp192k1);
		if( ecKeyClient == NULL )
		{
			log_notice("ECDH:EC_KEY_new_by_curve_name failed.");
			nResult = -1;
			break;
		}

		if (!EC_KEY_generate_key(ecKeyClient))
		{
			log_notice("ECDH:EC_KEY_generate_key failed.");
			nResult = -2;
			break;
		}

		// 客户端公钥
		const EC_POINT *pointClient = EC_KEY_get0_public_key(ecKeyClient);
		if( NULL == pointClient )
		{
			log_notice("ECDH:EC_KEY_get0_public_key failed.");
			nResult = -3;
			break;
		}

		char pubkeyClient[512] = {0};
		int  pubkeyLenCli = 0;
		pubkeyLenCli = EC_POINT_point2oct(EC_KEY_get0_group(ecKeyClient), pointClient, POINT_CONVERSION_COMPRESSED, (unsigned char*)pubkeyClient, ECDH_SIZE, NULL);
		if( pubkeyLenCli <= 0 )
		{
			log_notice("ECDH:EC_POINT_point2oct failed, pubkeyLenCli:%d.", pubkeyLenCli);
			nResult = -4;
			break;
		}

		memcpy((void*)szBufClientPubKey,pubkeyClient,pubkeyLenCli);
		if (pClientPubKeylen)
		{
			*pClientPubKeylen = pubkeyLenCli;
		}

		// 通过服务端公钥计算共享私钥 
		// 服务端公钥
		char pubkeyServer[128] = {0};
		int  pubkeyLenSvr = sizeof(pubkeyServer);
		ReadBufferHex((char*)szSrvPublicKey, nSrvPublicKeylen, pubkeyServer, &pubkeyLenSvr);

		const EC_GROUP* group = EC_KEY_get0_group((ecKeyClient));
		if(NULL == group)
		{
			log_notice("ECDH:EC_KEY_get0_group failed, return NULL.");
			nResult = -5;
			break;
		}

		pointServer = EC_POINT_new(group);
		if (NULL == pointServer)
		{
			log_notice("ECDH:EC_POINT_new failed, return NULL.");
			nResult = -6;
			break;
		}

		if(!EC_POINT_oct2point(group, pointServer, (const unsigned char*)pubkeyServer, pubkeyLenSvr, NULL))
		{
			log_notice("ECDH:EC_POINT_oct2point failed, return NULL.");
			nResult = -7;
			break;
		}

		// 计算共享密钥
		char  sharekey[512] = {0};
		int   sharekey_len = 0;
		sharekey_len = ECDH_compute_key(sharekey, sizeof(sharekey), pointServer, ecKeyClient, NULL);
		if( sharekey_len <= 0)
		{
			nResult = -8;
			log_notice("ECDH:ECDH_compute_key failed: %d", sharekey_len);
		}
		else
		{
			// 计算MD5
			Md5HashBuffer((uint8 *)szSharekey, sharekey, sharekey_len);
			nResult = 1;
		}
	}while(0);

	if(NULL != ecKeyClient)
	{
		EC_KEY_free(ecKeyClient);
	}
	if(NULL != pointServer)
	{
		EC_POINT_free(pointServer);
	}

	return nResult;
}
