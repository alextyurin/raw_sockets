#-------------------------------------------------
#
# Project created by QtCreator 2015-10-18T13:02:00
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer
TEMPLATE = app


SOURCES += main.cpp\
        gui.cpp \
    listener.cpp \
    field.cpp

HEADERS  += \
    gui.hpp \
    listener.hpp \
    field.hpp

FORMS    += gui.ui

CONFIG += c++11

LIBS += ../../externals/libtins-master/build/lib/libtins.so

INCLUDEPATH += ../../externals/libtins-master/include
