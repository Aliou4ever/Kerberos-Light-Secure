/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SC;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 *
 * @author Aliou
 */
public class KeyStoreSC {

    KeyStore ks;
    FileInputStream fis;
    FileOutputStream fos;

    public KeyStoreSC() {
        
        try{
        
            this.ks = KeyStore.getInstance(KeyStore.getDefaultType());
            
            ks.load(null, null);
       }
        catch (Exception e) {
            System.out.println("KeyStoreSC : " + e);
        }
    }

    public KeyStore getKs() {
        return ks;
    }

    public FileInputStream getFis() {
        return fis;
    }

    public FileOutputStream getFos() {
        return fos;
    }

    
    
    //récupérer uncertificat dans un keystore à partir d'un alias
    public X509Certificate getCertInKeyStore(String alias, KeyStore ks, FileInputStream fis) {

        try {
            System.out.println("récupérer un certificat dans un keystore");
//            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//            
//            ks.load(null, null);
            
            
            char[] mdp = "serveurCert".toCharArray();           
            //ks.load(new FileInputStream("keystore.ks"), mdp);
            ks.load(fis, mdp);

            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

            System.out.println("récupération du certificat de " + alias + " : OK");
            
            fis.close();
            return cert;
            
        } catch (Exception e) {
            System.out.println("getCertInKeyStore : " + e);
        }
        return null;
    }

    //enregistrer un certificat dans un keystore
    public void saveCertInKeyStore(String alias, X509Certificate cert, KeyStore ks, FileOutputStream fos) {
        //System.out.print("Enrégistrement d'un certificat dans un keystore : ");

        try {
//            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//            ks.load(null, null);

            char[] mdp = "serveurCert".toCharArray();

            ks.setCertificateEntry(alias, cert);

            //ks.store(new FileOutputStream("keystore.ks"), mdp);
            ks.store(fos, mdp);            
            
            fos.close();
            
        } catch (Exception e) {
            System.out.println("saveCertInKeyStore : " + e);
        }
    }
    
    public static void saveCertInFile(String alias, X509Certificate cert){
        
        try{
            FileOutputStream fos = new FileOutputStream(alias+".ks");
            fos.write(cert.getEncoded());
        }
        catch(Exception e) {
            System.out.println("saveCertInFile : " + e);
        }
    }
    
//    public static X509Certificate getCertInFile(String alias){
//        
//        try{
//            FileInputStream fis = new FileInputStream(alias+".ks");
//            
//            byte [] bytes = new byte[fis.available()];
//            int read = fis.read(bytes);
//            
//            if(read == 0)   System.out.println("READ == "+read);
//            
//            System.out.println("bytes == "+bytes.length);
//            
//            X509Certificate cert = getCertytes(bytes);
//                        
//            return cert;
//        }
//        catch(Exception e) {
//            System.out.println("getCertInFile : " + e);
//        }
//        return null;
//    }
    
    public void existsCert(String login, String alias, KeyStore ks) {
    
        try {
        //KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        
        char [] mdp = ("serveurCert").toCharArray();
        ks.load(new FileInputStream("keystore.ks"), mdp);
        
        String s,t;
        Enumeration <String> e = ks.aliases();
        //for(; e.hasMoreElements();){
            s = (String)e.nextElement();
            
            System.out.println("$$$$$$$$$$$alias : "+s);
            
            t = (String)e.nextElement();
            
           // if(s.equals(alias)/*ks.isCertificateEntry(alias)*/){
                //System.out.println("isKeyEntry : "+s);
                //return true;
            //} else 
               // return false;
            
            System.out.println("%%%%%%%%%%%alias : "+t);
        //}
           } catch (Exception e) {
            System.out.println("existCert : " + e);
        }
        //return false;         
    }
    
}
