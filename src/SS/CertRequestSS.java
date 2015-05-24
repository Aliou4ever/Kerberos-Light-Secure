/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SS;


import static KerberosAPI.Cryptage.signVerify;
import KerberosAPI.DataSenderProtocol;
import static KerberosAPI.KeyManager.getPublicKeyInFile;
import KerberosAPI.KeyStoreManager;
import KerberosAPI.ProtocolClientSC;
import KerberosAPI.readAndWriteObject;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class CertRequestSS {

    String ip;
    ServerSocket server_sock;
    Socket s;    
    KeyStore ks;
    X509Certificate cert;
    PrivateKey privKey;
    PublicKey pubKey;
    public int port;
    String identiteB;
    String login;
    ServerServices service;

    public CertRequestSS(int port, String identiteB) {
        this.port = port;
        this.identiteB = identiteB;
    }

    public CertRequestSS(int port) {
        this.port = port;
    }

    public void connect() {
        try {
            s = new Socket(ip, 1010);
        } catch (Exception e) {
            System.out.println("CertSS_Request => connect: " + e);
        }
    }

    public void run(String idSS) {

        //try {
        System.out.print("Instance d'envoi et de réception :");
        readAndWriteObject readWrite2 = new readAndWriteObject(s);
        System.out.println("OK");

            
        KeyStoreManager storeManager = null;
        try {
            storeManager = new KeyStoreManager();
        } catch (Exception e) {
            System.out.println("CertRequestSS => KeyStoreManager: " + e);
        }
        
        System.out.print("Récupération de notre certificat : ");
        try {
            cert = storeManager.getCertInKeyStore(idSS, idSS);            
        } catch (Exception e) {
            System.out.println("CertRequestSS => getCertInKeyStore: " + e);
        }

        System.out.println("OK");

        System.out.print("Récupération la clé privé :");
        try {
            privKey = storeManager.getOwnPrivKey(idSS);            
        } catch (Exception e) {
            System.out.println("CertRequestSS => getOwnPrivKey: " + e);
        }
        System.out.println("OK");

        System.out.print("Récupération de la clé publique du SC :");

        try {
            pubKey = getPublicKeyInFile();
        } catch (Exception e) {
            System.out.println("CertRequestSS => getPublicKeyInFile: " + e);
        }        
        System.out.println("OK");       

        System.out.println("Demande de certificat d'un Client/SS.");

        System.out.print("Etape 1");
        byte[] step1 = ProtocolClientSC.AtoSC1(idSS, identiteB, pubKey);
        try {
            readWrite2.writeObject2(step1);
        } catch (Exception e) {
            System.out.println("CertRequestSS => writeObject2: " + e);
        }
        System.out.println("OK");

        System.out.print("Etape 2 ");

        byte[] step2 = null;
        try {
            step2 = readWrite2.readObject2();
        } catch (Exception e) {
            System.out.println("CertRequestSS => readObject2: " + e);
        }

        DataSenderProtocol dsp = DataSenderProtocol.getSCtoA2(step2, privKey);

        String idB = dsp.getIdB();
        X509Certificate certB = dsp.getCert();
        byte[] certSign = dsp.getCertSign();

        try {
            //vérification de la signature
            if (signVerify(pubKey, certB.getEncoded(), certSign)) {
                //A enregistre le certificat de B dans son KeyStore
                storeManager.saveCertOfSS(idSS, idB, certB);                
                System.out.println("OK");
            } else {
                System.out.println("Signature incorrecte");
            }
            
            System.out.println("==========Liste des certificats=========");
            storeManager.listCertAliasses(idSS);
            
            close();
            System.out.println("CSRRequestSS closed!");
            
        } catch (Exception e) {
            System.out.println("CertRequestSS => signVerify: " + e);
        }
    }

    public String getIdentiteB() {
        return identiteB;
    }

    public void close() throws IOException {
        this.s.close();
    }

}
