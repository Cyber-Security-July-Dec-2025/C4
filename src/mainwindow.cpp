#include "mainwindow.h"
#include "crypto_utils.h"

#include <QVBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QWidget>
#include <QSettings>
#include <QLabel>
#include <QHostAddress>
#include <QDataStream>
#include <QByteArray>
#include <QFile>
#include <QHBoxLayout>
#include <QDateTime>

using namespace std;

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);

    QLabel *lbl = new QLabel("Secure Chat", central);
    layout->addWidget(lbl);

    display = new QTextEdit(central);
    display->setReadOnly(true);
    layout->addWidget(display);

    input = new QLineEdit(central);
    layout->addWidget(input);

    auto *hbox = new QWidget(central);
    auto *hlayout = new QHBoxLayout(hbox);

    sendBtn = new QPushButton("Send", hbox);
    connectBtn = new QPushButton("Connect", hbox);
    disconnectBtn = new QPushButton("Disconnect", hbox);

    hlayout->addWidget(connectBtn);
    hlayout->addWidget(disconnectBtn);
    hlayout->addWidget(sendBtn);
    layout->addWidget(hbox);

    setCentralWidget(central);
    setWindowTitle("Cyber");

    // button states
    sendBtn->setEnabled(false);
    disconnectBtn->setEnabled(false);

    connect(connectBtn, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    connect(disconnectBtn, &QPushButton::clicked, this, &MainWindow::onDisconnectClicked);
    connect(sendBtn, &QPushButton::clicked, this, &MainWindow::onSendClicked);

    // read config and load keys
    if(!loadKeys()) {
        appendLog("Keys not fully loaded — check config.ini and keys.");
    }

    // setup server to accept incoming connections
    server = new QTcpServer(this);
    connect(server, &QTcpServer::newConnection, this, &MainWindow::onNewConnection);

    if(!listenIp.isEmpty() && listenPort != 0) {
        QHostAddress addr(listenIp);
        if(!server->listen(addr, listenPort)) {
            appendLog(QString("Server listen failed: %1").arg(server->errorString()));
        } else {
            appendLog(QString("Listening on %1:%2").arg(listenIp).arg(listenPort));
        }
    }
}

MainWindow::~MainWindow() {
    if(socket) socket->disconnectFromHost();
    if(server && server->isListening()) server->close();
}

void MainWindow::appendLog(const QString &s) {
    display->append(s);
}

bool MainWindow::loadKeys() {
    QSettings settings("config.ini", QSettings::IniFormat);
    listenIp = settings.value("network/listen_ip", "0.0.0.0").toString();
    listenPort = settings.value("network/listen_port", 5000).toUInt();
    peerIp = settings.value("network/peer_ip", "127.0.0.1").toString();
    peerPort = settings.value("network/peer_port", 5001).toUInt();

    QString myPrivPath = settings.value("keys/my_private").toString();
    QString myPubPath  = settings.value("keys/my_public").toString();
    QString peerPubPath = settings.value("keys/peer_public").toString();

    if(!myPrivPath.isEmpty()) {
        if(CryptoUtils::LoadPrivateKey(myPrivPath.toStdString(), myPrivate)) {
            haveMyPrivate = true;
            appendLog(QString("Loaded my_private=%1").arg(myPrivPath));
            sendBtn->setEnabled(havePeerPublic); // enabled only if peer key present
        } else appendLog("Failed to load my_private");
    }

    if(!myPubPath.isEmpty()) {
        if(CryptoUtils::LoadPublicKey(myPubPath.toStdString(), myPublic)) {
            appendLog(QString("Loaded my_public=%1").arg(myPubPath));
        } else appendLog("Failed to load my_public");
    }

    if(!peerPubPath.isEmpty()) {
        if(CryptoUtils::LoadPublicKey(peerPubPath.toStdString(), peerPublic)) {
            havePeerPublic = true;
            appendLog(QString("Loaded peer_public=%1").arg(peerPubPath));
            sendBtn->setEnabled(haveMyPrivate); // both keys required to enable send
        } else {
            appendLog("Failed to load peer_public");
        }
    }

    return haveMyPrivate; // at least have private for receiving
}

void MainWindow::onNewConnection() {
    // accept the first incoming connection and replace any existing socket
    if(socket) {
        socket->disconnectFromHost();
        socket->deleteLater();
        socket = nullptr;
    }
    socket = server->nextPendingConnection();
    connect(socket, &QTcpSocket::readyRead, this, &MainWindow::onSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &MainWindow::onSocketDisconnected);
    appendLog(QString("Accepted connection from %1:%2").arg(socket->peerAddress().toString()).arg(socket->peerPort()));
    disconnectBtn->setEnabled(true);
    sendBtn->setEnabled(havePeerPublic && haveMyPrivate);
}

void MainWindow::onConnectClicked() {
    if(socket && socket->state() == QAbstractSocket::ConnectedState) {
        appendLog("Already connected.");
        return;
    }
    if(socket) { socket->deleteLater(); socket = nullptr; }
    socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::readyRead, this, &MainWindow::onSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &MainWindow::onSocketDisconnected);

    appendLog(QString("Connecting to %1:%2 ...").arg(peerIp).arg(peerPort));
    socket->connectToHost(peerIp, peerPort);
    if(!socket->waitForConnected(3000)) {
        appendLog(QString("Connect failed: %1").arg(socket->errorString()));
        socket->deleteLater();
        socket = nullptr;
    } else {
        appendLog("Connected to peer.");
        disconnectBtn->setEnabled(true);
        sendBtn->setEnabled(havePeerPublic && haveMyPrivate);
    }
}

void MainWindow::onDisconnectClicked() {
    if(socket) {
        socket->disconnectFromHost();
        appendLog("Disconnected.");
        disconnectBtn->setEnabled(false);
        sendBtn->setEnabled(false);
    }
}

static void writeLengthPrefixed(QByteArray &out, const QByteArray &data) {
    quint32 len = (quint32)data.size();
    QByteArray header;
    QDataStream ds(&header, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::BigEndian);
    ds << len;
    out.append(header);
    out.append(data);
}

// Packet format: [4]rsa_len [rsa_bytes] [4]iv_len [iv_bytes] [4]cipher_len [cipher_bytes]
void MainWindow::onSendClicked() {
    if(!socket || socket->state() != QAbstractSocket::ConnectedState) {
        appendLog("Not connected to peer.");
        return;
    }
    QString text = input->text().trimmed();
    if(text.isEmpty()) return;

    // 1) Generate session key (AES-256)
    const size_t AES_BYTES = 32;
    std::vector<uint8_t> sessionKey(AES_BYTES);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(sessionKey.data(), sessionKey.size());

    // 2) AES encrypt message
    std::vector<uint8_t> iv, cipher;
    if(!CryptoUtils::AESEncrypt(sessionKey, text.toStdString(), iv, cipher)) {
        appendLog("AES encryption failed.");
        return;
    }

    // 3) RSA-encrypt session key with peer public
    std::vector<uint8_t> rsaCipher;
    if(!CryptoUtils::RSAEncrypt(peerPublic, sessionKey, rsaCipher)) {
        appendLog("RSA encrypt session-key failed.");
        return;
    }

    // 4) Build packet
    QByteArray packet;
    writeLengthPrefixed(packet, QByteArray(reinterpret_cast<const char*>(rsaCipher.data()), rsaCipher.size()));
    writeLengthPrefixed(packet, QByteArray(reinterpret_cast<const char*>(iv.data()), iv.size()));
    writeLengthPrefixed(packet, QByteArray(reinterpret_cast<const char*>(cipher.data()), cipher.size()));

    // 5) send
    qint64 written = socket->write(packet);
    if(written == packet.size()) {
        appendLog("Sent message (encrypted).");
        QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        display->append(QString("[%1] Me: %2").arg(ts).arg(text));
        input->clear();
    } else {
        appendLog(QString("Failed to write to socket: wrote %1 of %2").arg(written).arg(packet.size()));
    }
}

void MainWindow::onSocketReadyRead() {
    if(!socket) return;
    QDataStream ds(socket);
    ds.setByteOrder(QDataStream::BigEndian);

    // We need to read three length-prefixed blocks; safe approach: read entire available bytes into buffer and parse
    QByteArray avail = socket->readAll();
    static QByteArray buffer;
    buffer.append(avail);

    auto readBlock = [](QByteArray &buf, QByteArray &out)->bool {
        if(buf.size() < 4) return false;
        QDataStream hds(buf.left(4));
        hds.setByteOrder(QDataStream::BigEndian);
        quint32 L;
        hds >> L;
        if((quint32)buf.size() < 4 + L) return false;
        out = buf.mid(4, L);
        buf = buf.mid(4 + L);
        return true;
    };

    // attempt parse; require all three present
    QByteArray rsaBlock, ivBlock, cipherBlock;
    if(!readBlock(buffer, rsaBlock)) return;
    if(!readBlock(buffer, ivBlock)) return;
    if(!readBlock(buffer, cipherBlock)) return;

    // Convert to std::vectors
    std::vector<uint8_t> rsaBytes(rsaBlock.size()), ivBytes(ivBlock.size()), cipherBytes(cipherBlock.size());
    memcpy(rsaBytes.data(), rsaBlock.constData(), rsaBlock.size());
    memcpy(ivBytes.data(), ivBlock.constData(), ivBlock.size());
    memcpy(cipherBytes.data(), cipherBlock.constData(), cipherBlock.size());

    // RSA decrypt session key
    std::vector<uint8_t> sessionKey;
    if(!CryptoUtils::RSADecrypt(myPrivate, rsaBytes, sessionKey)) {
        appendLog("RSA decrypt failed.");
        return;
    }

    // AES decrypt message
    std::string plain;
    if(!CryptoUtils::AESDecrypt(sessionKey, ivBytes, cipherBytes, plain)) {
        appendLog("AES decrypt failed.");
        return;
    }

    QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    display->append(QString("[%1] Peer: %2").arg(ts).arg(QString::fromStdString(plain)));
}

void MainWindow::onSocketDisconnected() {
    appendLog("Peer disconnected.");
    disconnectBtn->setEnabled(false);
    sendBtn->setEnabled(false);
    if(socket) {
        socket->deleteLater();
        socket = nullptr;
    }
}
