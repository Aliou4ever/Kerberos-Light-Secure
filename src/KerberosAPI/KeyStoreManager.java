/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 *
 * @author Aliou
 */
public class KeyStoreManager {

    private static KeyStore ks;

    public KeyStoreManager() throws KeyStoreException {
        this.ks = KeyStore.getInstance(KeyStore.getDefaultType());
    }

    //récupérer un certificat dans un keystore à partir d'un alias
    public X509Certificate getCertInKeyStore(String login, String alias) {

        try {
        //System.out.println("récupérer un certificat dans un keystore");

            FileInputStream fis = new FileInputStream(login + ".ks");

            char[] mdp = (login + "_Cert_").toCharArray();

            ks.load(fis, mdp);

            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

            //System.out.println("récupération du certificat de " + alias + " : OK");

            return cert;
        } catch (Exception e) {
            System.out.println("getCertInKeyStore : " + e);
        }
        return null;
    }

    //enregistrer un certificat dans un keystore
    public void saveOwnCert(String login, X509Certificate cert) {
        //System.out.print("Enrégistrement d'un certificat dans un keystore : ");
        try {
            //FileInputStream fis = new FileInputStream(login+".ks");
            char[] mdp = (login + "_Cert_").toCharArray();
            ks.load(null, mdp);

            ks.setCertificateEntry(login, cert);

            FileOutputStream fos = new FileOutputStream(login + ".ks");
            ks.store(fos, mdp);
        } catch (Exception e) {
            System.out.println("saveOwnCert : " + e);
        }
    }    
    //enregistrer le certificat d'un serveur de service dans un keystore
    public void saveCertOfSS(String login, String alias, X509Certificate cert) {
        //System.out.print("Enrégistrement d'un certificat dans un keystore : ");
        try {
            //FileInputStream fis = new FileInputStream(login + ".ks");
            char[] mdp = (login + "_Cert_").toCharArray();
            ks.load(null, mdp);

            //ks.setCertificateEntry(alias+"_Cert", cert);
            ks.setCertificateEntry(alias, cert);

            FileOutputStream fos = new FileOutputStream(login + ".ks");
            ks.store(fos, mdp);

        } catch (Exception e) {
            System.out.println("saveCertOfSS : " + e);
        }
    }

    public void saveOwnKey(String login, PrivateKey privKey, X509Certificate cert) {

        //System.out.print("Enrégistrement de la clé privé dans un keystore : ");
        try {
            //FileInputStream fis = new FileInputStream(login+".ks");
            char[] mdp = (login + "_Cert_").toCharArray();
            ks.load(new FileInputStream(login + ".ks"), mdp);   //null

            X509Certificate certChain[] = new X509Certificate[1];
            certChain[0] = cert;

            ks.setKeyEntry(login + "_Key", privKey, mdp, certChain);

            FileOutputStream fos = new FileOutputStream(login + ".ks"); /////login+"_Key.ks"
            ks.store(fos, mdp);

        } catch (Exception e) {
            System.out.println("saveOwnKey : " + e);
        }
    }

    //récupérer la clé privé dans un keystore à partir
    public PrivateKey getOwnPrivKey(String login) {

        //System.out.println("récupérer un certificat dans un keystore");       
        try {
            FileInputStream fis = new FileInputStream(login + ".ks");
            char[] mdp = (login + "_Cert_").toCharArray();
            ks.load(fis, mdp);

            PrivateKey privKey = (PrivateKey) ks.getKey(login + "_Key", mdp);

            return privKey;
        } catch (Exception e) {
            System.out.println("getOwnPrivKey : " + e);
        }
        return null;
    }   

    //Vérifier si un certificat est enrégistré avec ce alias
    public boolean existsCert(String login, String alias) {

        try {
            char[] mdp = (login + "_Cert_").toCharArray();

            ks.load(new FileInputStream(login + ".ks"), mdp);
            String s;
            Enumeration<String> e = ks.aliases();
            for (;e.hasMoreElements();) {
                
                s = e.nextElement();
                if(s.equals(alias)){  
                    
                    System.out.println("alias : " + s);
                    return true;
                }
            }
        } catch (Exception e) {
            System.out.println("existsCert : " + e);
        }
        System.out.println("n'existe pas : "+alias);
        return false;
    }
    
    public static void listCertAliasses(String login) {

        try {
            char[] mdp = (login + "_Cert_").toCharArray();

            ks.load(new FileInputStream(login + ".ks"), mdp);

            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                                    
                System.out.println("alias : " + e.nextElement());                    

            }
        } catch (Exception e) {
            System.out.println("listCertAliasses : " + e);
        }        
    }
    
}
