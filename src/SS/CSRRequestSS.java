/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SS;

import static KerberosAPI.BuildKeyPair.generateKeyPair;
import KerberosAPI.CSRManager;
import static KerberosAPI.Certificate.getCertBytes;
import static KerberosAPI.Cryptage.encrypt;
import static KerberosAPI.DigestManager.digest;
import static KerberosAPI.KeyManager.getPublicKeyInFile;
import KerberosAPI.KeyStoreManager;
import KerberosAPI.readAndWriteObject;
import Useful.InfoCSR;
import static Useful.InfoCSR.ObjectToByte;
import java.io.IOException;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author Aliou
 */
public class CSRRequestSS {

    String ip;
    public int port;
    private PrivateKey privKey;
    SocketChannel service;
    Socket s;
    String login;
    String password;
    PublicKey pubKeySC;

    public CSRRequestSS(int port, String login, String password) {
        this.port = port;
        this.login = login;
        this.password = password;
        try {
            pubKeySC = getPublicKeyInFile();
        } catch (Exception e) {
            System.out.println("CSRRequestSS : " + e);
        }
    }

    public void connect() {
        try {
            s = new Socket(ip, 1010);
        } catch (Exception e) {
            System.out.println("connect : " + e);
        }
    }

    public void run() {

        try {
            KeyPair keyPair = generateKeyPair();
            privKey = keyPair.getPrivate();

            //Création du CSR a envoyer au Serveur de Certificat
            PKCS10CertificationRequest csr = CSRManager.generateCSR(login, keyPair);

            System.out.print("Création de l'objet à envoyé :");
            InfoCSR serviceCSR = new InfoCSR(csr.getEncoded(), login, digest(password));
            System.out.println("OK");

            System.out.print("Transformation en tableau de bytes");
            byte[] bytesCSR = ObjectToByte(serviceCSR);
            System.out.println("OK");

            System.out.print("Récupération de la clé publique du Serveur de Certificats :");
            PublicKey pubKey = getPublicKeyInFile();
            System.out.println("OK");

            System.out.print("Chiffrement de l'objet :");
            byte[] encrypted = encrypt(pubKey, bytesCSR);
            System.out.println("OK");

            System.out.print("Instanciation de la classe pour l'envoi et la réception:");
            readAndWriteObject readWrite2 = new readAndWriteObject(s);
            System.out.println("OK");

            System.out.print("Envoi de la demande de certification :");
            readWrite2.writeObject2(encrypted);
            System.out.println("OK");

            System.out.print("Réception de l'objet contenant le certificat :");
            byte[] receive = readWrite2.readObject2();

            System.out.println("OK");

            System.out.print("Réconstruction du certificat :");
            X509Certificate cert = getCertBytes(receive);
            System.out.println("OK");
            
            KeyStoreManager storeManager = null;
            try {
                storeManager = new KeyStoreManager();
            } catch (Exception e) {
                System.out.println("CSRRequestSS => KeyStoreManager: " + e);
            }

            System.out.print("Enregistrement du certificat réçu dans le keystore : ");
            storeManager.saveOwnCert(login, cert);
            System.out.println("OK");

            System.out.print("Enregistrement de la clé privé dans le keystore : ");
            storeManager.saveOwnKey(login, privKey, cert);
            System.out.println("OK");

            System.out.println("==========Liste des certificats=========");
            storeManager.listCertAliasses(login);

            close();
            System.out.println("CSRRequestSS closed!");

        } catch (Exception e) {
            System.out.println("CSRRequestSS => run : " + e);
        }
    }

    public void close() throws IOException {
        this.s.close();
    }

    public PublicKey getPubKeySC() {
        return pubKeySC;
    }

    public PrivateKey getPrivKey() {
        return privKey;
    }
}
