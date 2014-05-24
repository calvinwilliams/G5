# 此文件由makeobj.sh自动生成
############################################################
# 项目名 : 
# 模块名 : 
# 备  注 : 
############################################################

###### 源文件配置区
#@ c_FILE
c_FILE		=	\
			G5.c \

###### 目标文件、安装目录配置区
BIN		=	G5
BININST		=	$(HOME)/bin

###### 编译选项
CFLAGS		=	-I. \

###### 链接选项
LFLAGS		=	-L. \

###### 额外宏定义区
CLEAN_ADDITION	=

###### 加载mktpl模板库
#@ make_all
#@ make_clean
#@ make_install
#@ make_install_BININST
#@ make_install_HDERINST
#@ make_install_DFTHDERINST

include $(MKTPLDIR)/makeobj_$(MKTPLOS).inc

###### 目标文件依赖关系
G5		:	$(c_FILE_o)
	$(CC) -o $@ $(c_FILE_o) $(LFLAGS)

