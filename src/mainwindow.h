#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpServer>
#include <QTcpSocket>
#include <memory>
#include <QString>

#include "crypto_utils.h"
class QTextEdit;
class QLineEdit;
class QPushButton;


class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onConnectClicked();
    void onDisconnectClicked();
    void onSendClicked();
    void onNewConnection();
    void onSocketReadyRead();
    void onSocketDisconnected();

private:
    bool loadKeys(); // load keys from config.ini
    void appendLog(const QString &s);

    QTextEdit *display = nullptr;
    QLineEdit *input = nullptr;
    QPushButton *sendBtn = nullptr;
    QPushButton *connectBtn = nullptr;
    QPushButton *disconnectBtn = nullptr;

    QTcpServer *server = nullptr;
    QTcpSocket *socket = nullptr; // client or accepted socket

    // crypto key holders
    CryptoPP::RSA::PrivateKey myPrivate;
    CryptoPP::RSA::PublicKey myPublic;
    CryptoPP::RSA::PublicKey peerPublic;
    bool haveMyPrivate = false;
    bool havePeerPublic = false;

    // network config read from config.ini
    QString listenIp;
    quint16 listenPort = 0;
    QString peerIp;
    quint16 peerPort = 0;
};

#endif // MAINWINDOW_H
