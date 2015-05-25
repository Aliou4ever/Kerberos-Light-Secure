/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SS;

import static KerberosAPI.Cryptage.decrypt;
import static KerberosAPI.Cryptage.encrypt;
import static KerberosAPI.Cryptage.signVerify;
import KerberosAPI.DataSenderProtocol;
import static KerberosAPI.KeyManager.getPublicKeyInFile;
import KerberosAPI.KeyStoreManager;
import KerberosAPI.NShroederSender;
import static KerberosAPI.NShroederSender.genSessionKeyFromNonces;
import static KerberosAPI.NShroederSender.generateNonce;
import static KerberosAPI.NShroederSender.isEqualsNonces;
import KerberosAPI.NeedhamShroeder;
import static KerberosAPI.Symetrique.symetriqueDecrypt;
import static KerberosAPI.Symetrique.symetriqueEncrypt;
import KerberosAPI.readAndWriteObject;
import static Useful.InfoCSR.ByteToObject;
import Useful.InfoService;
import Useful.ServiceCalc;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 *
 * @author Aliou
 */
public class ServicesSocket extends Thread {

    ServerSocketChannel ssc;
    ServerSocket server_sock;
    Socket s;
    SocketChannel service;
    KeyStore ks;
    X509Certificate certSS;
    PrivateKey privKeySS;
    PublicKey pubKeySC;
    public int port;
    X509Certificate certA;
    String idA;
    public static String identite;
    String idService;
    KeyStoreManager storeManager;
    
    public ServicesSocket(int port) throws IOException {
        this.port = port;
        //this.idService = idService;

        try {
            ssc = ServerSocketChannel.open();
            ssc.socket().bind(new InetSocketAddress(port));
            System.out.println("SS attend des demandes de services sur le port "
                    + ssc.socket().getLocalPort() + "...");
        } catch (Exception e) {
            System.out.println("SS : " + e);
        }
    }

    public void run() { /*String idService*/

        try {
            while (true) {
                SocketChannel client = ssc.accept();

                System.out.println("Services Socket : un client est arrivé.");
               
                System.out.println("un client est arrivé");

                readAndWriteObject readWrite = new readAndWriteObject(client);

                System.out.print("Reception d'une demande : ");
                
                byte[] receive = readWrite.readObject();
                
                idService = ss.getLogin();                
                
                try {
                    storeManager = new KeyStoreManager();
                } catch (Exception e) {
                    System.out.println("ServicesSocket => KeyStoreManager: " + e);
                }

                System.out.print("Récupération de notre certificat et clé privé : ");
                certSS = storeManager.getCertInKeyStore(idService, idService);
                privKeySS = storeManager.getOwnPrivKey(idService);
                System.out.println("OK");
                
                System.out.print("Déchiffrement de l'objet réçu : ");
                byte[] decrypted = decrypt(privKeySS, receive);
                System.out.println("OK");
                
                System.out.print("Reconstruction de l'objet : ");
                Object obj = ByteToObject(decrypted);
                System.out.println("OK");

                System.out.print("Récupération de la clé publique du SC :");
                pubKeySC = getPublicKeyInFile();
                System.out.println("OK");
                
                //connexion à la base de données pour vérifié l'identité du demandeur   
                System.out.println("Type d'objet réçu : "+obj.getClass().getName());

                if (obj instanceof DataSenderProtocol) {
                    
                    //récevoir le certificat d'un client qui à demandé le notre au serveur    
                    byte[] step2 = readWrite.readObject2();

                    DataSenderProtocol dsp = DataSenderProtocol.getSCtoA2(step2, privKeySS);

                    idA = dsp.getIdA();
                    X509Certificate certA = dsp.getCert();
                    byte[] certSignA = dsp.getCertSign();

                    if (signVerify(pubKeySC, certA.getEncoded(), certSignA)) {
                        //SS enregistre le certificat de A dans son KeyStore
                        System.out.println("Vérification de la signature du certificat réçu : ");
                        storeManager.saveCertOfSS(idService, idA, certA);
                        System.out.println("OK");
                    } else {
                        System.out.println("Signature incorrecte");
                    }
                } else {
                    if (obj instanceof NShroederSender) {

                        System.out.println("==========Needham Shroeder==========");
                        //idA = "aliou";
                        certA = storeManager.getCertInKeyStore(idService, idA);                        
                        
                        System.out.print("Challenge 1 : ");

                        NShroederSender challenge1 = (NShroederSender) obj;
                              
                        //récupération de la nonceA
                        byte[] bytesNA = challenge1.getNonceA();
                        BigInteger nonceA = new BigInteger(bytesNA);

                        System.out.println("OK");

                        //générer nonceB et envoyer avec nonceA
                        System.out.print("Challenge 2 : ");
                        BigInteger nonceB = generateNonce();

                        byte[] challenge2 = NeedhamShroeder.BtoA2(nonceA, nonceB, certA);
                        
                        //Envoi de l'objet contenant nonceA et nonceB
                        readWrite.writeObject(challenge2);

                        System.out.println("OK");

                        System.out.print("Challenge 3 : ");

                        //réception de la nonceB
                        byte[] step3 = readWrite.readObject();
 
                        NShroederSender challenge3 = NShroederSender.getNonceBstep3(step3, privKeySS);
                        
                        //réconstruction de la nonce
                        BigInteger nonceB2 = new BigInteger(challenge3.getNonceB());
                        
                        //vérification de l'égalité des nonces A et B
                        if (isEqualsNonces(nonceB, nonceB2)) {

                            System.out.println("OK");

                            System.out.print("Génération de la clé de session : ");                            
//                           
                            byte [] secretKey = genSessionKeyFromNonces(nonceA.toByteArray(), nonceB.toByteArray());
                            
                            System.out.println("OK");
                            
                            //envoi de la clé de session
                            readWrite.writeObject(encrypt(certA.getPublicKey(), secretKey));
                            
                            System.out.println("============Traitement de Service============");
                            
                            //récéption d'une demande de calcul
                            byte [] byteCalcul = readWrite.readObject();                            
                            
                            byte [] decrypt = symetriqueDecrypt(byteCalcul, secretKey);                            
                            
                            ServiceCalc objCalc = (ServiceCalc) InfoService.ByteToObject(decrypt);                            
                            
                            double a = objCalc.getA();
                            double b = objCalc.getB();
                            String operateur = objCalc.getOperateur();                                                        
                            
                            //Obtention du résultat du calcul
                            double res = ServiceCalc.resCalcul(a, b, operateur);

                            //création de l'objet contenant le résultat du calcul
                            ServiceCalc resCalc = new ServiceCalc(res);
                                                        
                            byte [] byteResCalc = InfoService.ObjectToByte(resCalc);                            
                            
                            byte [] byteResCalcEncrypt = symetriqueEncrypt(byteResCalc, secretKey);                            
                            
                            //envoi du résultat du calcul au demandeur
                            readWrite.writeObject(byteResCalcEncrypt);
                            
                        } else {
                            System.out.println("KO");
                            client.close();
                        }

                        System.out.println("OK");
                    } else {
                        System.out.println("Objet réçu : autre");
                    }
                }

            }
        } catch (Exception e) {
            System.out.println("Echec de la connexion : " + e);
        }
    }
}
