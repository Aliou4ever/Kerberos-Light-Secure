/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SC;

import Useful.InfoCSR;
import static Useful.InfoCSR.ByteToObject;
import static KerberosAPI.Certificate.createCertFromCSR;
import static KerberosAPI.Cryptage.decrypt;
import KerberosAPI.DataSenderProtocol;
import static KerberosAPI.DigestManager.digestVerify;
import KerberosAPI.ProtocolClientSC;
import KerberosAPI.readAndWriteObject;
import static SC.SetupSC.getCertOfSC;
import static SC.SetupSC.getKeyPairOfSC;
import Useful.DataBase;
import enchange.info.ClientInfo;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author Aliou
 */
public class ServerCert extends Thread {

    private KeyPair keyPair;
    private X509Certificate certSC;
    public ServerSocketChannel ssc;
    public int port;
    private String login;
    private byte[] mdp;
    KeyStoreSC keySC;
    KeyStore ks;
    FileOutputStream fos;
    FileInputStream fis;
    ClientInfo  clientInfo;

    //Ouverture d'une connexion sur un port défini
    public ServerCert(int port) throws IOException {
        this.port = port;

        //Génération de la KeyPair, création du certificat auto-signé et enrégistrement de la clé public dans un fichier
        SetupSC setup = new SetupSC();

        //Récupération de la paire de clé
        keyPair = getKeyPairOfSC();
        //Récupération du certificat auto-signé
        certSC = getCertOfSC();

        try {
            ssc = ServerSocketChannel.open();
            ssc.socket().bind(new InetSocketAddress(port));
            System.out.println("Serveur de Certificats attend des connexions sur le port "
                    + ssc.socket().getLocalPort() + "...");
        } catch (Exception e) {
            System.out.println("Echec ouverture de connexion : " + e);
        }
    }

    public void run() {

        try {
            while (true) {
                //Arrivé d'un client
                SocketChannel client = ssc.accept();

                System.out.println("un client est arrivé : ");

                System.out.print("Instanciation de la classe pour l'envoi et la réception:");
                readAndWriteObject readWrite = new readAndWriteObject(client);
                System.out.println("done");

                System.out.print("Reception de la demande du client : ");
                byte[] receive = readWrite.readObject();
                System.out.println("done");

                System.out.print("Déchiffrement de l'objet réçu :");
                byte[] decrypted = decrypt(keyPair.getPrivate(), receive);
                System.out.println("done");

                //transformation du tableau de byte en objet
                System.out.print("Reconstruction de l'objet :");
                Object obj = ByteToObject(decrypted);
                
                //connexion à la base de données pour vérifié l'identité du demandeur
                DataBase db = new DataBase("localhost", "root", "");
                db.connexion();
                //caster en ObjectToSend pour recuperer et verifier le csr le login et le mdp
                if (obj instanceof InfoCSR) {

                    System.out.println("################DEMAMANDE DE CSR################");

                    InfoCSR objectCSR = (InfoCSR) obj;
                    System.out.println("done");

                    //récuperation du csr
                    System.out.print("Récuperation du CSR : ");
                    PKCS10CertificationRequest csr = objectCSR.getCsr();
                    System.out.println("done");

                    System.out.print("Vérification de l'indentité : ");

                    login = objectCSR.getLogin();

                    if (db.userExists(login)) {
                        mdp = objectCSR.getMdp();

                        byte[] mdpVerify = db.getPassword(login);
                        if (digestVerify(mdp, mdpVerify)) {
                            
                            System.out.println("Identité valide.");
                                    
                            System.out.print("Création du certificat à partir du CSR : ");
                            X509Certificate cert = createCertFromCSR(csr, keyPair, certSC);
                            System.out.println("done");

                            System.out.print("Enregistrement du certificat dans la base : ");
                            db.addCertificate(login, cert);
                            System.out.println("done");

                            System.out.print("Envoi du certificat signé au client :  ");
                            byte[] certClient = cert.getEncoded();
                            readWrite.writeObject(certClient);
                            System.out.println("done");

                        } else {
                            System.out.println("Mot de passe incorrecte.");
                            readWrite.writeObject(null);
                            client.close();
                        }
                    } else {
                        System.out.println("login incorrecte.");
                        readWrite.writeObject(null);
                        client.close();
                    }

                } else {
                    if (obj instanceof DataSenderProtocol) {

                        System.out.println("A demande de certificat d'un autre utilisateur B");
                        
                        System.out.print("Etape 1 : ");

                        DataSenderProtocol step1 = (DataSenderProtocol) obj;
                        String idA = step1.getIdA();
                        String idB = step1.getIdB();

                        System.out.println("OK");

                        System.out.println("Etape 2 : ");
                        //vérifier l'identité de A                            
                        if (db.userExists(idA)) {                            
                            //vérifier l'identité de B
                            if (db.userExists(idB)) {
                                
                                //récupérer le certificat de B 
                                X509Certificate certB = db.getCertificate(idB);                                
                                PublicKey pubKeyB = certB.getPublicKey();
                                
                                //récupérer le certificat de A
                                X509Certificate certA = db.getCertificate(idA);                                                                    
                                PublicKey pubKeyA = certA.getPublicKey();

                                //SC envoie à A le certificat de B
                                byte[] step2 = ProtocolClientSC.SCtoA2(idB, certB, keyPair.getPrivate(), pubKeyA);
                                readWrite.writeObject(step2);
                                System.out.println("step2 : SCtoA done");

                                //SC envoie à B le certificat de A
//                                byte[] step3 = ProtocolClientSC.SCtoB3(idA, certA, keyPair.getPrivate(), pubKeyB);
//                                readWrite.writeObject(step3);
//                                System.out.println("step3 : SCtoB done");
                            }
                        }
                        System.out.println("OK");

                    } else {
                        System.out.println("Autre demande.");
                    }

                }
            }
        } catch (Exception e) {
            System.out.println("ServeurCert : " + e);
        }
    }

    public void close() {
        try {
            ssc.close();
        } catch (Exception e) {
            System.out.println("ServeurCert : " + e);
        }
    }

}
