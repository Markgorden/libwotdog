
#ifndef __HASH_MD5_H__
#define __HASH_MD5_H__

#ifdef __cplusplus
extern "C"{
#endif
    
#pragma once
typedef unsigned char			uint8;
typedef signed char				int8;
typedef signed int				int32;
typedef unsigned int			uint32;

#define MD5_LAST_BLOCK  56
#define l2c(l,c)    (*((c)++)=(uint8)(((l)     )&0xff), *((c)++)=(uint8)(((l)>> 8L)&0xff), *((c)++)=(uint8)(((l)>>16L)&0xff), *((c)++)=(uint8)(((l)>>24L)&0xff))
#define MD5_CBLOCK  64
#define MD5_DIGEST_LENGTH	16
#define MD5_LBLOCK			16

// MD5数据结构
typedef struct MD5state_st
{
	uint32 A,B,C,D;
	uint32 Nl,Nh;
	uint32 data[MD5_LBLOCK];
	int32 num;
} MD5_CTX;

#define INIT_DATA_A (uint32)0x67452301L
#define INIT_DATA_B (uint32)0xefcdab89L
#define INIT_DATA_C (uint32)0x98badcfeL
#define INIT_DATA_D (uint32)0x10325476L

#define MD5_CBLOCK  64

#define c2l(c,l)    (l = ((uint32)(*((c)++))), l|=(((uint32)(*((c)++)))<< 8), l|=(((uint32)(*((c)++)))<<16), l|=(((uint32)(*((c)++)))<<24))

#define p_c2l(c,l,n)    { switch (n) { case 0: l =((uint32)(*((c)++))); case 1: l|=((uint32)(*((c)++)))<< 8; case 2: l|=((uint32)(*((c)++)))<<16; case 3: l|=((uint32)(*((c)++)))<<24; } }

#define p_c2l_p(c,l,sc,len) { switch (sc) { case 0: l =((uint32)(*((c)++))); if (--len == 0) break; case 1: l|=((uint32)(*((c)++)))<< 8; if (--len == 0) break; case 2: l|=((uint32)(*((c)++)))<<16; } }

#define c2l_p(c,l,n)    { l=0; (c)+=n; switch (n) { case 3: l =((uint32)(*(--(c))))<<16; case 2: l|=((uint32)(*(--(c))))<< 8; case 1: l|=((uint32)(*(--(c))))    ; } }

#define F(b,c,d)    ((((c) ^ (d)) & (b)) ^ (d))
#define G(b,c,d)    ((((b) ^ (c)) & (d)) ^ (c))
#define H(b,c,d)    ((b) ^ (c) ^ (d))
#define I(b,c,d)    (((~(d)) | (b)) ^ (c))

#if defined(WIN32)
#define ROTATE(a,n)     (((a)<<(n))|((a)>>(32-(n))))
#else
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffffL)>>(32-(n))))
#endif

#if defined(WIN32)
/* 5 instructions with rotate instruction, else 9 */
#define Endian_Reverse32(a) \
{ \
	unsigned long l=(a); \
	(a)=((ROTATE(l,8)&0x00FF00FF)|(ROTATE(l,24)&0xFF00FF00)); \
}
#else
/* 6 instructions with rotate instruction, else 8 */
#define Endian_Reverse32(a) \
{ \
	unsigned long l=(a); \
	l=(((l&0xFF00FF00)>>8L)|((l&0x00FF00FF)<<8L)); \
	(a)=ROTATE(l,16L); \
}
#endif


#define R0(a,b,c,d,k,s,t) { a+=((k)+(t)+F((b),(c),(d))); a=ROTATE(a,s); a+=b; };
#define R1(a,b,c,d,k,s,t) { a+=((k)+(t)+G((b),(c),(d))); a=ROTATE(a,s); a+=b; };

#define R2(a,b,c,d,k,s,t) { a+=((k)+(t)+H((b),(c),(d))); a=ROTATE(a,s); a+=b; };

#define R3(a,b,c,d,k,s,t) { a+=((k)+(t)+I((b),(c),(d))); a=ROTATE(a,s); a+=b; };

void Md5HashBuffer( uint8 *outBuffer, const void *inBuffer, uint32 length);




#ifdef __cplusplus
}
#endif

#endif
