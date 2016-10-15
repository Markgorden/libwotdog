由于包的调用问题。
此处需要用到原始的平台上的包的配置。

对比后，仅发现，只是一个文件有差别。


luaconf.h

/* 详细有说明，此处改Lua执行时，寻找库的路径。默认系统则无所谓。
   如果写好了很多库，则要在这里指定好路径，好让Lua执行时，自动去找到库的位置
   http://www.educity.cn/wenda/308308.html
   http://see.sl088.com/wiki/Lua_%E5%8C%85%E8%B7%AF%E5%BE%84%E6%93%8D%E4%BD%9C
   http://stackoverflow.com/questions/19982915/how-to-include-lua-module-in-build
   http://www.4byte.cn/question/364946/how-to-include-lua-module-in-build.html
   
   Add the dist paths to the environment: LUA_CPATH='dist/usr/local/lib/lua/5.1/?.so;;' and LUA_PATH='dist/usr/local/share/lua/5.1/?.lua;;'
   看到此处有？通配，即想到，是不是Lua执行时，在环境变量里，设置了什么，或者是
   在编译的时候就指定了，寻找库的路径，
   后来在看OPENWRT编译的Makefile文件时，发现要改luaconf.h这个文件，以指定路径。

    即发现在此修改。
    查了Lua 执行的时候，没有带参数可以指定寻找库的路径，lua --?
    也即要不是读环境变量，即通配那个。
    要不然，就是编译进了程序里。即在配置文件里可以找到。
    也就是说，我的程序，要与 系统自带的/usr/bin/lua 这个文件的执行环境是一样的。就可以了。
    因此，要看它的编译过程，是如何产生的这个。
    
    看了启动脚本，没有配置环境变量。因此，肯定就是在编译里。
    
    /etc/init.d/ 下还有几个 用到了 lua -l xxxx 带库名的用法。
       
   
@@ LUA_PATH_DEFAULT is the default path that Lua uses to look for
@* Lua libraries.
@@ LUA_CPATH_DEFAULT is the default path that Lua uses to look for
@* C libraries.
** CHANGE them if your machine has a non-conventional directory
** hierarchy or if you want to install your libraries in
** non-conventional directories.
*/
#if defined(_WIN32)	/* { */
/*
** In Windows, any exclamation mark ('!') in the path is replaced by the
** path of the directory of the executable file of the current process.
*/
#define LUA_LDIR	"!\\lua\\"
#define LUA_CDIR	"!\\"
#define LUA_PATH_DEFAULT  \
		LUA_LDIR"?.lua;"  LUA_LDIR"?\\init.lua;" \
		LUA_CDIR"?.lua;"  LUA_CDIR"?\\init.lua;" ".\\?.lua"
#define LUA_CPATH_DEFAULT \
		LUA_CDIR"?.dll;" LUA_CDIR"loadall.dll;" ".\\?.dll"

#else			/* }{ */

/*
#define LUA_VDIR	LUA_VERSION_MAJOR "." LUA_VERSION_MINOR "/"
#define LUA_ROOT	"/usr/local/"
#define LUA_LDIR	LUA_ROOT "share/lua/" LUA_VDIR
#define LUA_CDIR	LUA_ROOT "lib/lua/" LUA_VDIR
#define LUA_PATH_DEFAULT  \
		LUA_LDIR"?.lua;"  LUA_LDIR"?/init.lua;" \
		LUA_CDIR"?.lua;"  LUA_CDIR"?/init.lua;" "./?.lua"
#define LUA_CPATH_DEFAULT \
		LUA_CDIR"?.so;" LUA_CDIR"loadall.so;" "./?.so" 
*/

// for openwrt environment by zxl 2014.10.24
// 由此配置了Lua执行时，寻找库的路径。
#define LUA_ROOT	"/usr/"
#define LUA_LDIR	LUA_ROOT "share/lua/"
#define LUA_CDIR	LUA_ROOT "lib/lua/"
#define LUA_PATH_DEFAULT  \
		"./?.lua;"  LUA_LDIR"?.lua;"  LUA_LDIR"?/init.lua;" \
		            LUA_CDIR"?.lua;"  LUA_CDIR"?/init.lua"
#define LUA_CPATH_DEFAULT \
	"./?.so;"  LUA_CDIR"?.so;" LUA_CDIR"loadall.so"
#endif			/* } */

// edited end.


以上方法在Lua中调用库时，Lua库的库没有找到，之类的，就会出现断错误。
因此，还是恢复用5.2.5版本的，不会在dofile那里出错。调用了没有的库，会有提示信息出来。

改用环境 变量的方式。
环境变量，还没有写完
export LUA_CPATH='/usr/lib/lua/?.so'
export LUA_PATH='/usr/lib/lua/?.lua'
设置这个环境变量是对的。
在程序里设置与在shell设置一样的。

因此，上面两种方法都可行。

程序仍然出现段错误，是由于 OPENWRT所用的lua，版本，打了很多补丁，不能用其他的版本，必须用这个随机的 库才行。
否则就不兼容了，通过对比发现，打了很多补丁，修改了很多代码，怪不得运行不了。这样的话，LUCI写出来的程序，就不能在标准的LUA上运行了。
会出现段错误。

LUA_CPATH='/usr/local/lib/lua/5.1/?.so;;' 
LUA_PATH='/usr/local/share/lua/5.1/?.lua;;'

怪不得一运行 加载luci的库，就出现段错误。
现在直接COPY了系统里的lua.a文件过来用。其他代码现在没有使用。

2014.10.24

