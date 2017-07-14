#****************************************************************************
#
# webgate
#
# This is a GNU make (gmake) makefile
#****************************************************************************

# DEBUG can be set to YES to include debugging info, or NO otherwise
DEBUG          := YES

# PROFILE can be set to YES to include profiling info, or NO otherwise
PROFILE        := NO

# USE_STL can be used to turn on STL support. NO, then STL
# will not be used. YES will include the STL files.
USE_STL := YES

# WIN32_ENV
WIN32_ENV := YES
#****************************************************************************

CC     := gcc
CXX    := g++
LD     := g++
AR     := ar rc
RANLIB := ranlib

# ifeq (YES, ${WIN32_ENV})
#   RM     := del
# else
#   RM     := rm -f
# endif

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O2

DEBUG_CXXFLAGS   := ${DEBUG_CFLAGS}
RELEASE_CXXFLAGS := ${RELEASE_CFLAGS}

DEBUG_LDFLAGS    := -g
RELEASE_LDFLAGS  := -O3

ifeq (YES, ${DEBUG})
   CFLAGS       := ${DEBUG_CFLAGS}
   CXXFLAGS     := ${DEBUG_CXXFLAGS}
   LDFLAGS      := ${DEBUG_LDFLAGS}
else
   CFLAGS       := ${RELEASE_CFLAGS}
   CXXFLAGS     := ${RELEASE_CXXFLAGS}
   LDFLAGS      := ${RELEASE_LDFLAGS}
endif

ifeq (YES, ${PROFILE})
   CFLAGS   := ${CFLAGS} -pg -O3
   CXXFLAGS := ${CXXFLAGS} -pg -O3
   LDFLAGS  := ${LDFLAGS} -pg
endif

#****************************************************************************
# Preprocessor directives
#****************************************************************************

ifeq (YES, ${USE_STL})
  DEFS := -DUSE_STL
else
  DEFS :=
endif

#****************************************************************************
# Include paths
#****************************************************************************

#INCS := -I/usr/include/g++-2 -I/usr/local/include
INCS := -I/usr/local/include -I../comm_v1.0.0/lib/SocketLite/src -I../comm_v1.0.0/pcommon -I../comm_v1.0.0/pcommon/log -I../comm_v1.0.0/pcommon/net \
		-I../comm_v1.0.0/lib/libconhash -I/home/boost_1_58_0/sdk/include -I../comm_v1.0.0/lib/jsoncpp-0.10.2/include
LIBS := -L/home/boost_1_58_0/sdk/lib -lboost_system -lboost_thread -lboost_locale -L../comm_v1.0.0/lib/SocketLite/src -lsocketlite \
		-L/usr/lib -lpthread -L../comm_v1.0.0/lib/libconhash -lconhash -ljsoncpp

#****************************************************************************
# Makefile code common to all platforms
#****************************************************************************

CFLAGS   := ${CFLAGS}   ${DEFS}
CXXFLAGS := ${CXXFLAGS} ${DEFS}

#****************************************************************************
# Targets of the build
#****************************************************************************

OUTPUT := webgate

all: ${OUTPUT}

#****************************************************************************
# Source files
#****************************************************************************

SRCS := ../comm_v1.0.0/pcommon/log/CLogThread.cpp \
	../comm_v1.0.0/pcommon/log/syslog-nb.cpp \
	../comm_v1.0.0/pcommon/log/CAlarmNotify.cpp \
	../comm_v1.0.0/pcommon/base64.cpp \
	../comm_v1.0.0/pcommon/sha1.cpp \
	../comm_v1.0.0/pcommon/split.cpp \
	../comm_v1.0.0/pcommon/Config.cpp \
	../comm_v1.0.0/pcommon/net/io_service_pool.cpp \
	CCmdGuideMgr.cpp \
	GlobalSetting.cpp \
	client_session.cpp \
	clientsession_manager.cpp \
	svrsession_manager.cpp \
	WebgateApplication.cpp \
	main.cpp \
	server.cpp \
	tcp_client.cpp \
	roomsvr_client.cpp \
	usermgr_client.cpp \
	CRoomMgr.cpp

# Add on the sources for libraries
SRCS := ${SRCS}

OBJS := $(addsuffix .o,$(basename ${SRCS}))

#****************************************************************************
# Output
#****************************************************************************

${OUTPUT}: ${OBJS}
	${LD} -o $@ ${LDFLAGS} ${OBJS} ${LIBS} ${EXTRA_LIBS}
#	$(CXX) $@ $(OBJS)
#****************************************************************************
# common rules
#****************************************************************************

# Rules for compiling source files to object files
%.o : %.cpp
	${CXX} -c ${CXXFLAGS} ${INCS} $< -o $@

%.o : %.c
	${CC} -c ${CFLAGS} ${INCS} $< -o $@

dist:
	bash makedistlinux

clean:
	${RM} core ${OBJS} ${OUTPUT}

depend:
	#makedepend ${INCS} ${SRCS}

%.o: %.h
