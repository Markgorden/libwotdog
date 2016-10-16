/*
 Authors: ZhangXuelian
 	


 Changes:
 	
	
*/

#ifndef _G_PROTOCOL_H_
#define _G_PROTOCOL_H_
#ifdef __cplusplus
extern "C"{
#endif

// 需要处理的私有协议，加在这里。
// 1、要支持的私有协议的客户端类型
typedef enum {
	UNKNOWN_CLIENT = 0,
	HTTP_CLIENT,
	COMMAND_CLIENT,
	LOG_CLIENT,
} CLIENT_TYPE;


// 2、要支持的私有协议的头文件。
// protocol public file
#include "cmd_proto.h"
bool parse_command_recved_data(void * __client);

// comm function.

#ifdef __cplusplus
}
#endif
#endif
