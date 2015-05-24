/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Aliou
 */
public class KeyManager {
    
    //Enregistrer une cle publique dans un fichier
    public static void storePublicKeyInFile(PublicKey pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException, NoSuchProviderException{
        
        Security.addProvider(new BouncyCastleProvider());
        
        System.out.print("Enrégistrement la clé publique dans un fichier : ");
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        RSAPublicKeySpec rsaPubKeySpec = kf.getKeySpec(pubKey, RSAPublicKeySpec.class);
        BigInteger modulus = rsaPubKeySpec.getModulus();
        BigInteger exponent = rsaPubKeySpec.getPublicExponent();
        
        FileOutputStream fos = new FileOutputStream("publicKey.key");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        
        oos.writeObject(modulus);
        oos.writeObject(exponent);
        
        System.out.println("OK");
        fos.close();
        oos.close();
    }
    
    //récuperer une cle publique dans un fichier
    public static PublicKey getPublicKeyInFile() throws FileNotFoundException, IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeySpecException, NoSuchProviderException{
        
        Security.addProvider(new BouncyCastleProvider());
        
        FileInputStream fis = new FileInputStream("publicKey.key");                
        ObjectInputStream ois = new ObjectInputStream(fis);
        BigInteger modulus  = (BigInteger) ois.readObject();
        BigInteger exponent = (BigInteger) ois.readObject();
        
        RSAPublicKeySpec rsaPKSpec=  new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        
        PublicKey pubKey = kf.generatePublic(rsaPKSpec);
        
        fis.close();
        ois.close();
        return pubKey;
    }
    
}
