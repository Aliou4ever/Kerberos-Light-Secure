/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Aliou
 */
public class DigestManager {
    
    //haché d'une chaine de cararctère
    public static byte [] digest(String chaine) throws NoSuchAlgorithmException{
    
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(chaine.getBytes());
        byte [] hache = md.digest();
        return hache;        
    }
    
    //haché d'un tableau de bytes
    public static byte [] digest(byte [] bytes) throws NoSuchAlgorithmException{
    
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(bytes);
        byte [] hache = md.digest();
        return hache;        
    }
    
    //vérification si deux digest sont équivalentes
    public static boolean digestVerify(byte [] digestA, byte [] digestB) throws NoSuchAlgorithmException{
           
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        if(md.isEqual(digestA, digestB)){
            return true;
        }
        else{
            return false;   
        }
    }    
}
