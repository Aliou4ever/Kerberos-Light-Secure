/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Aliou
 */
public class Symetrique {

    public static byte[] symetriqueEncrypt(byte[] bytes, byte [] sessionKey) {

        //Encryption AES
        try {
            sessionKey = Arrays.copyOf(sessionKey, 16);
            
            SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");
            
            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] encrypted = cipher.doFinal(bytes);

            //System.out.println("\nEncrypted : \n" + new String(encrypted));

            return encrypted;

        } catch (Exception e) {
            System.out.println("symetriqueEncrypt : " + e);
        }
        return null;

    }

    public static byte[] symetriqueDecrypt(byte[] bytes, byte [] sessionKey) {

        try {
            //Decrypt
            sessionKey = Arrays.copyOf(sessionKey, 16);
            
            SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");
            
            Cipher cipher = Cipher.getInstance("AES");
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec);

            byte decrypt[] = cipher.doFinal(bytes);
            
            //System.out.println("\nDecrypted : \n" + new String(decrypt));

            return decrypt;

        } catch (Exception e) {
            System.out.println("symetriqueDecrypt : " + e);
        }
        return null;
    }

}
