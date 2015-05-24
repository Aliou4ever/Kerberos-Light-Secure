/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;

/**
 *
 * @author aliou
 */
public class Cryptage {

    public static byte[] encrypt(PublicKey pubKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted = blockCipher(data, Cipher.ENCRYPT_MODE, cipher);
        return encrypted;

    }

    public static byte[] decrypt(PrivateKey privKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] decrypted = blockCipher(data, Cipher.DECRYPT_MODE, cipher);

        return decrypted;
    }

    private static byte[] blockCipher(byte[] bytes, int mode, Cipher cipher) throws Exception {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        byte[] scrambled = new byte[0];

        // toReturn will hold the total result
        byte[] toReturn = new byte[0];
        // if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

        // another buffer. this one will hold the bytes that have to be modified in this step
        byte[] buffer = new byte[length];

        for (int i = 0; i < bytes.length; i++) {

            // if we filled our buffer array we have our block ready for de- or encryption
            if ((i > 0) && (i % length == 0)) {
                //execute the operation
                scrambled = cipher.doFinal(buffer);
                // add the result to our total result.
                toReturn = append(toReturn, scrambled);
                // here we calculate the length of the next buffer required
                int newlength = length;

                // if newlength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + length > bytes.length) {
                    newlength = bytes.length - i;
                }
                // clean the buffer array
                buffer = new byte[newlength];
            }
            // copy byte into our buffer.
            buffer[i % length] = bytes[i];
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer);

        // final step before we can return the modified data.
        toReturn = append(toReturn, scrambled);

        return toReturn;
    }

    private static byte[] append(byte[] prefix, byte[] suffix) {
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i = 0; i < prefix.length; i++) {
            toReturn[i] = prefix[i];
        }
        for (int i = 0; i < suffix.length; i++) {
            toReturn[i + prefix.length] = suffix[i];
        }
        return toReturn;
    }

    public static byte[] signature(PrivateKey privKey, byte[] bytes) {

        try {
            Signature s = Signature.getInstance("SHA1withRSA");
            s.initSign(privKey);
            s.update(bytes);
            byte[] signe = s.sign();

            return signe;
        } catch (Exception e) {
            System.out.println("Cryptage => signature : " + e);
        }
        return null;
    }

    public static boolean signVerify(PublicKey pubKey, byte[] clair, byte[] signe) {

        try {
            Signature s = Signature.getInstance("SHA1withRSA");
            s.initVerify(pubKey);
            s.update(clair);

            return s.verify(signe);
        } catch (Exception e) {
            System.out.println("Cryptage => signVerify : " + e);
        }
        return false;
    }

}
