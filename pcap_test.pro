TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    get_network_address.cpp

HEADERS += \
    get_network_address.h
