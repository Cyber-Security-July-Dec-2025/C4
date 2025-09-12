QT -= core gui
CONFIG += console
CONFIG -= app_bundle

SOURCES += keygen.cpp

INCLUDEPATH += /usr/include
LIBS += -lcryptopp
