#-------------------------------------------------
#
# Project created by QtCreator 2015-10-26T21:48:46
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = tcp_generator
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.hpp

FORMS    += mainwindow.ui

CONFIG += c++11

LIBS += ../../externals/libtins-master/build/lib/libtins.so

INCLUDEPATH += ../../externals/libtins-master/include
