/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client;

import KerberosAPI.*;
import static KerberosAPI.Cryptage.decrypt;
import static KerberosAPI.NShroederSender.generateNonce;
import java.math.BigInteger;
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
public class ServiceRequest {

    String ip;
    ServerSocket server_sock;
    Socket s;
    SocketChannel client;
    KeyStore ks;
    X509Certificate cert;
    X509Certificate certSS;
    PrivateKey privKey;
    PublicKey pubKeySS;
    int port;
    Client c;
    String login;
    String mdp;
    byte [] sessionKey;
    KeyStoreManager storeManager;
    double resCalc;
    readAndWriteObject readWrite2;

    public ServiceRequest(int port, String login) {
        this.port = port;
        this.login = login;        
    }

    public void connect() {        
        try {
            s = new Socket(ip, 1020);
        } catch (Exception e) {
            System.out.println("ServiceRequest => connect : " + e);
        }
    }

    public void run(String id, String idSS) {

        try {
          
            try {
                storeManager = new KeyStoreManager();
            } catch (Exception e) {
                System.out.println("CSRRequest => KeyStoreManager: " + e);
            }
            
            //récuperer le certificat de SS et le notre            
            if(storeManager.existsCert(id, idSS)){
            
                System.out.println("Posséde le certificat de : "+idSS);                
                certSS = storeManager.getCertInKeyStore(id, idSS);                
                
                System.out.println("Chargémnt de notre certificat et clé privé : "+id);
                cert = storeManager.getCertInKeyStore(id, id);
                privKey = storeManager.getOwnPrivKey(id);
                
                readWrite2 = new readAndWriteObject(s);     
                
                System.out.print("Challenge 1 : ");
                
                BigInteger nonceA = generateNonce();                   
                
                byte [] challenge1 = NeedhamShroeder.AtoB1(login, nonceA, certSS);    
                
                readWrite2.writeObject2(challenge1);
                
                System.out.println("OK");
                
                System.out.print("Challenge 2 : ");
                
                byte [] step2 = readWrite2.readObject2();                
                
                NShroederSender challenge2 = NShroederSender.getNonceANonceBstep2(step2, privKey);
                
                BigInteger nonceA2 = new BigInteger(challenge2.getNonceA());
                BigInteger nonceB = new BigInteger(challenge2.getNonceB());
                
                //vérification de l'égalité des nonces
                if(NShroederSender.isEqualsNonces(nonceA, nonceA2)){
                    
                    System.out.println("OK");
                
                }else{
                    System.out.println("KO");
                    s.close();
                }

                System.out.print("Challenge 3 : ");
                
                    byte [] challenge3 = NeedhamShroeder.AtoB3(nonceB, certSS);
                    readWrite2.writeObject2(challenge3);
                    
                System.out.println("OK");
                
                //réception de la clé de session
                byte [] keyEncrypt = readWrite2.readObject2();
                
                sessionKey = decrypt(privKey, keyEncrypt);
                
            }
            else{
                System.out.println("Ne dispose pas du certificat de : "+idSS);
            }
            
        } catch (Exception e) {
            System.out.println("ServiceRequest => run : " + e);
        }
    }

    public byte [] getSessionKey() {
        return sessionKey;
    }   

    public readAndWriteObject getReadWrite2() {
        return readWrite2;
    }

    
    public double getResCalc() {
        return resCalc;
    }
    
}
