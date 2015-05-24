/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client;

import static KerberosAPI.Cryptage.signVerify;
import KerberosAPI.DataSenderProtocol;
import static KerberosAPI.KeyManager.getPublicKeyInFile;
import KerberosAPI.KeyStoreManager;
import KerberosAPI.ProtocolClientSC;
import KerberosAPI.readAndWriteObject;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class CertSS_Request {

    String ip;
    ServerSocket server_sock;
    Socket s;
    SocketChannel client;
    KeyStore ks;
    X509Certificate cert;
    PrivateKey privKey;
    PublicKey pubKey;
    public int port;
    String identiteB;
    String login;
    Client c;
    KeyStoreManager storeManager;

    public CertSS_Request(int port, String identiteB) {
        this.port = port;
        this.identiteB = identiteB;
    }

    public CertSS_Request(int port) {
        this.port = port;
    }

    public void connect() {
        try {
            s = new Socket(ip, 1010);
        } catch (Exception e) {
            System.out.println("CertSS_Request => connect : " + e);
        }
    }

    public void run(String identiteA) {

        //try {
        System.out.print("Instanciation pour l'envoi et la réception : ");
        readAndWriteObject readWrite2 = new readAndWriteObject(s);
        System.out.println("OK");

        try {
            storeManager = new KeyStoreManager();
        } catch (Exception e) {
            System.out.println("CertSS_Request => KeyStoreManager : " + e);
        }

        //String identiteA = Client.getIdentite();
        System.out.print("Récupération de notre certificat : ");
        try {
            cert = storeManager.getCertInKeyStore(identiteA, identiteA);
        } catch (Exception e) {
            System.out.println("CertSS_Request => getCertInKeyStore : " + e);
        }

        System.out.println("OK");

        System.out.print("Récupération de notre clé privé : ");
        try {
            privKey = storeManager.getOwnPrivKey(identiteA);
        } catch (Exception e) {
            System.out.println("CertSS_Request => getOwnPrivKey : " + e);
        }
        System.out.println("OK");

        System.out.print("Récupération de la clé publique du Serveur de Certificats : ");

        try {
            pubKey = getPublicKeyInFile();
        } catch (Exception e) {
            System.out.println("CertSS_Request => getPublicKeyInFile : " + e);
        }
        System.out.println("OK");

        System.out.println("A veut contacter SS et demande au SC le certificat du SS.");

        System.out.print("Etape 1 : ");
        byte[] step1 = ProtocolClientSC.AtoSC1(identiteA, identiteB, pubKey);
        try {
            readWrite2.writeObject2(step1);
        } catch (Exception e) {
            System.out.println("CertSS_Request => writeObject2 : " + e);
        }
        System.out.println("OK");

        System.out.print("Etape 2 : ");

        byte[] step2 = null;
        try {
            step2 = readWrite2.readObject2();
        } catch (Exception e) {
            System.out.println("CertSS_Request => readObject2: " + e);
        }

        DataSenderProtocol dsp = DataSenderProtocol.getSCtoA2(step2, privKey);

        String idB = dsp.getIdB();
        X509Certificate certB = dsp.getCert();
        byte[] certSign = dsp.getCertSign();

        try {
            //vérification de la signature
            if (signVerify(pubKey, certB.getEncoded(), certSign)) {
                //A enregistre le certificat de B dans son KeyStore
                storeManager.saveCertOfSS(identiteA, idB, certB);
                
                System.out.println("OK");
            } else {
                System.out.println("Signature incorrecte");
            }

            System.out.println("==========Liste des certificats=========");
            storeManager.listCertAliasses(identiteA);

            close();
            System.out.println("CertSS_Request closed!");

        } catch (Exception e) {
            System.out.println("CertSS_Request => signVerify : " + e);
        }
    }

    public String getIdentiteB() {
        return identiteB;
    }

    public void close() throws IOException {
        this.s.close();
    }

}
