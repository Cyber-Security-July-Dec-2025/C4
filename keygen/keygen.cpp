// keygen.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]){
    AutoSeededRandomPool rng;
    int keysize = 2048;
    if(argc >= 2) keysize = atoi(argv[1]);

    RSA::PrivateKey priv;
    RSA::PublicKey pub;

    priv.GenerateRandomWithKeySize(rng, keysize);
    pub = RSA::PublicKey(priv);

    // Create keys directory
    system("mkdir -p keys");

    // Save private key (DER)
    FileSink fs1("keys/my_private.der", true);
    priv.DEREncode(fs1);
    fs1.MessageEnd();

    // Save public key (DER)
    FileSink fs2("keys/my_public.der", true);
    pub.DEREncode(fs2);
    fs2.MessageEnd();

    cout << "Generated RSA keypair with size " << keysize << " bits.\n";
    cout << "Private: keys/my_private.der\n";
    cout << "Public : keys/my_public.der\n";
    cout << "Now copy the public file to the peer and set peer_public in config.ini\n";
    return 0;
}
