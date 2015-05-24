/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Useful;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author Aliou
 */
public class InfoCSR implements Serializable{

    byte[] csr;    
    String login;
    byte [] mdp;
    HashMap hashMap;
    int port;
    
    public PKCS10CertificationRequest getCsr() {
         try {
             return new PKCS10CertificationRequest(csr);
         } catch (IOException ex) {
             Logger.getLogger(InfoCSR.class.getName()).log(Level.SEVERE, null, ex);
             return null;
         }
    }        

    public InfoCSR(byte[] csr, String login, byte [] mdp) {
        this.csr = csr;
        this.login = login;
        this.mdp = mdp;        
    }
//    public InfoCSR(byte[] csr, String login, byte [] mdp, HashMap hashMap) {
//        this.csr = csr;
//        this.login = login;
//        this.mdp = mdp;
//        this.hashMap = hashMap;
//    }
    
    public String getLogin() {
        return login;
    }

    public byte [] getMdp() {
        return mdp;
    }
    
    //transformer un objet en tableau de byte
    public static byte[] ObjectToByte(Object o) throws Exception{
        
      ByteArrayOutputStream b = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(b);
      oos.writeObject(o);      
      byte[] bytes =  b.toByteArray();
        
      return bytes ;
    }
    
    //transformer un tableau de byte en objet
    public static Object ByteToObject(byte[] bytes) throws Exception{
        
        Object obj = null;
        
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bis);
        obj = ois.readObject();        
        return obj;
    }
    
     public static String stringLogin(){        
        
        Scanner scan = new Scanner(System.in);  
        System.out.println("Saisir votre login : ");
        String  login = scan.nextLine();
        
        return login;        
     }
     
     public static String stringIdentiteB() {
        
        Scanner scan = new Scanner(System.in);  
        System.out.println("Vous voulez le certificat de : ");
        String  identite = scan.nextLine();
        
        return identite; 
    }
     
     public static String stringPwd(){                
        //System.out.println("Saisir votre mot de passe : ");
        Scanner scan = new Scanner(System.in);       
        String  pwd = scan.nextLine();          
        
        return pwd;        
     }

    public InfoCSR() {
    }
    
//     public static void main(String[] args) {
//        InfoCSR cic = new InfoCSR();
//        cic.stringPwd();
//        byte [] mdp = cic.getMdp();
//         System.out.println("mdp : "+mdp);
//    }
}
