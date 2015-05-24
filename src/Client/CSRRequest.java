/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client;

import Useful.InfoCSR;
import static Useful.InfoCSR.*;
import static KerberosAPI.BuildKeyPair.generateKeyPair;
import KerberosAPI.CSRManager;
import static KerberosAPI.Certificate.getCertBytes;
import static KerberosAPI.Cryptage.encrypt;
import static KerberosAPI.DigestManager.digest;
import static KerberosAPI.KeyManager.getPublicKeyInFile;
import KerberosAPI.KeyStoreManager;
import KerberosAPI.readAndWriteObject;
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
public class CSRRequest {

    String ip;
    public int port;
    private PrivateKey privKey;
    X509Certificate cert;
    SocketChannel client;
    Socket s;
    String login;
    String mdp;
    PublicKey pubKeySC;
    Client c;
    KeyStoreManager storeManager;

    public CSRRequest(int port, String login, String mdp ) {
        this.port = port;
        this.login = login;
        this.mdp = mdp;
    }

    public void connect() throws IOException {
        try {            
            s = new Socket(ip, 1010);
        } 
        catch (Exception e) {
            System.out.println("CSRRequest => connect : "+e);
        }
    }

    public void run() {

        try {
            //Génération de la paire de clés
            KeyPair keyPair = generateKeyPair();
            //Récupération de la clé privé
            privKey = keyPair.getPrivate();

            //Création du CSR a envoyer au Serveur de Certificat
            PKCS10CertificationRequest csr = CSRManager.generateCSR(login, keyPair);

            System.out.print("Création de l'objet à envoyé : ");
//            HashMap hashMap = new HashMap();
//            hashMap.put(login, c.getServInfo().getPort());
            InfoCSR clientCSR = new InfoCSR(csr.getEncoded(), login, digest(mdp));
            System.out.println("OK");

            System.out.print("Transformation en tableau de bytes : ");
            byte[] bytesCSR = ObjectToByte(clientCSR);
            System.out.println("OK");

            System.out.print("Récupération de la clé publique du Serveur de Certificats : ");
            pubKeySC = getPublicKeyInFile();
            System.out.println("OK");

            System.out.print("Chiffrement de l'objet : ");
            byte[] encrypted = encrypt(pubKeySC, bytesCSR);
            System.out.println("OK");

            System.out.print("Instanciation pour l'envoi et la réception : ");            
            readAndWriteObject readWrite2 = new readAndWriteObject(s);
            System.out.println("OK");

            System.out.print("Envoi de la demande de certification : ");            
            readWrite2.writeObject2(encrypted);
            System.out.println("OK");

            System.out.print("Réception de l'objet contenant le certificat : ");
            byte[] receive = readWrite2.readObject2();

            if (receive == null) {
                System.out.println("Démande de certification réfusée.");
            } else {
                System.out.println("OK");

                System.out.print("Réconstruction du certificat : ");
                cert = getCertBytes(receive);                
                System.out.println("OK");
                 
                storeManager = new KeyStoreManager();
                
                System.out.print("Enregistrement du certificat dans le keystore : ");
                storeManager.saveOwnCert(login, cert);
                System.out.println("OK");

                System.out.print("Enregistrement de la clé privé dans le keystore : ");
                storeManager.saveOwnKey(login, privKey, cert);
                System.out.println("OK");
                
            }
            
            System.out.println("==========Liste des certificats=========");
            storeManager.listCertAliasses(login);
            
            close();
            System.out.println("CSRRequest closed!");
            
        } catch (Exception e) {
            System.out.println("CSRRequest : " +e);
        }
    }

    public PublicKey getPubKeySC() {
        return pubKeySC;
    }

    public void close() throws IOException {
	this.s.close();
    }
}
