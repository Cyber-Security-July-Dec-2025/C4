QT += core gui network widgets
CONFIG += c++17

SOURCES += src/main.cpp \
           src/mainwindow.cpp \
           src/crypto_utils.cpp

HEADERS += src/mainwindow.h \
           src/crypto_utils.h

# adjust include paths if Crypto++ is in a nonstandard location
# Local Crypto++ repo path
CRYPTOPP_DIR = /Users/pritesh/cryptopp

INCLUDEPATH += $$CRYPTOPP_DIR
LIBS += $$CRYPTOPP_DIR/libcryptopp.a
