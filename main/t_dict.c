/*
 Authors: ZhangXuelian
 	


 Changes:
 	
	
*/
#include "server.h"

//int dictSdsKeyCompare(void *privdata, const void *key1,
//					  const void *key2)
//{
//	int l1,l2;
//	DICT_NOTUSED(privdata);
//	l1 = strlen((char*)key1);
//	l2 = strlen((char*)key2);
//	if (l1 != l2) return 0;
//	return memcmp(key1, key2, l1) == 0;
//}

//static dictType IntPtrDictType = {dictSdsHash, NULL,NULL, dictClientPtrCompare,NULL,NULL};

void * get_element(dict * d, char * key) 
{
    dictEntry * de;
    if (dictSize(d) == 0 || (de = dictFind(d,key)) == NULL) 
	   return 0;
	return dictGetVal(de);
}

int delete_element(dict * d, char *key) 
{
    if (dictSize(d) > 0) dictDelete(d,key);
    if (dictDelete(d,key) == DICT_OK) 
        return 1;
	else 
        return 0;
}

static inline void * _lookupKey(dict * d, void * key) 
{
    dictEntry *de = dictFind(d,key);
    if (de) 
	{
        void * val = dictGetVal(de);
        return val;
    } else {
        return NULL;
    }
}

static inline int _dbAdd(dict * d, void * key, void * val) 
{
	if (!key && !val)
		return NULL;
	return dictAdd(d, key, val);
}

static inline int _dbOverwrite(dict * d, void * key, void * val) 
{
	dictEntry *de = dictFind(d,key);
	return dictReplace(d, key, val);
}

int set_element(dict * d, void * key, void * val)
{
	if (_lookupKey(d,key) == NULL) 
		return _dbAdd(d,key,val);
	else 
		return _dbOverwrite(d,key,val);
}

void update_element(dict * d, void * key, void * value)
{
	dictEntry * kde, * de;
	kde = dictFind(d,key);
	de = dictReplaceRaw(d,dictGetKey(kde));
	dictSetVal(d,de,value);
}

int do_element_exist(dict * d, void * key) 
{
	return dictFind(d,key) != NULL;
}

long long deinit_dict(dict * d, void(callback)(void*)) 
{
	int j;
	long long removed = 0;
	dictEmpty(d,callback);
	return removed;
}

dictEntry * get_random_element(dict * db) 
{
	dictEntry * de;
	de = dictGetRandomKey(db);
	if (de == NULL) 
		return NULL;
	else
		return de;
}


//void main()
//{
//	while(i--)
//	{
//        CLIENT * client = malloc(sizeof(CLIENT));
//		client->id = i;
//		char a[20] = {0};
//		sprintf(a,"%d",i);
//		memcpy(client->resp_buf.buf, a, sizeof(client->resp_buf.buf));
//		char * key = malloc(36+1);
//		memcpy(key, a, strlen(a));
//		key[strlen(a)] = 0;
//		int retval = set_element(my_dict, key, client);
//		if ( j == i % 10000 )
//		{
//			tryResizeHashTables(my_dict,0);
//			incrementallyRehash(my_dict,0);
//		}
//	}
//	
//	dictIterator * di;
//	dictEntry * de;
//	di = dictGetIterator(my_dict);
//	while ((de = dictNext(di)) != NULL) 
//	{
//		CLIENT * a = (CLIENT *)dictGetVal(de);
//		printf("%d-%s\n", a->id,a->resp_buf.buf);
//	}
//	dictReleaseIterator(di);
//    printf("table size:%d\n",dictSize(my_dict));
//	printf("-------------------------------\nBegan to traverse the read\n");
//	i = 100;//00000;
//	j = 0;
//	while(i--)
//	{
//		char a[20] = {0};
//		sprintf(a,"%d",i);
//		CLIENT* value = NULL;
//		value = get_element(my_dict,a);
//		if (value)
//		{
//			printf("The value is %s\n", value->resp_buf.buf);
//		}
//		j++;
//	}
//	printf("There are number of elements: %d \n",j);
//	dictRelease(my_dict);
//	return 0;
//}
