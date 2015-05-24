/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import static KerberosAPI.Cryptage.encrypt;
import static KerberosAPI.DigestManager.digest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

/**
 *
 * @author Aliou
 */
public class NShroederSender implements Serializable {

    String idA;
    byte[] nonceA;
    byte[] nonceB;

    //Needham Schroeder   
    public NShroederSender(String idA, byte[] nonceA) {
        this.idA = idA;
        this.nonceA = nonceA;
    }

    public NShroederSender(byte[] nonceA, byte[] nonceB) {
        this.nonceA = nonceA;
        this.nonceB = nonceB;
    }

    public NShroederSender(byte[] nonceB) {
        this.nonceB = nonceB;
    }

    //A envoie à B la nonceA
    public static byte[] createAtoB1(String identiteA, byte[] nonceA, PublicKey pubKeyB) {

        try {
            NShroederSender needShroeder = new NShroederSender(identiteA, nonceA);

            byte[] step1 = ObjectToByte(needShroeder);

            byte[] step1Encrypt = encrypt(pubKeyB, step1);

            return step1Encrypt;

        } catch (Exception e) {
            System.out.println("createAtoB1 " + e);;
        }
        return null;
    }

    //B envoie à A la nonceA et nonceB
    public static byte[] createBtoA2(byte[] nonceA, byte[] nonceB, PublicKey pubKeyA) {

        try {
            NShroederSender needShroeder = new NShroederSender(nonceA, nonceB);

            byte[] step2 = ObjectToByte(needShroeder);

            byte[] step2Encrypt = encrypt(pubKeyA, step2);
            return step2Encrypt;

        } catch (Exception e) {
            System.out.println("createBtoA2 " + e);;
        }
        return null;
    }

    //A envoie à B la nonceB
    public static byte[] createAtoB3(byte[] nonceB, PublicKey pubKeyB) {

        try {
            NShroederSender needShroeder = new NShroederSender(nonceB);

            byte[] step3 = ObjectToByte(needShroeder);

            byte[] step3Encrypt = encrypt(pubKeyB, step3);

            return step3Encrypt;
        } catch (Exception e) {
            System.out.println("createAtoB3 " + e);;
        }
        return null;
    }

    //B récupère la nonceA
    public static NShroederSender getNonceAstep1(byte[] step1, PrivateKey privKeyB) {

        try {
            byte step1Decrypt[] = Cryptage.decrypt(privKeyB, step1);

            NShroederSender needShroeder = (NShroederSender) ByteToObject(step1Decrypt);

            return needShroeder;
        } catch (Exception e) {
            System.out.println("getNonceAstep1 " + e);;
        }
        return null;
    }

    //A récupère la nonceA et nonceB
    public static NShroederSender getNonceANonceBstep2(byte[] step2, PrivateKey privKeyA) {

        try {

            byte step2Decrypt[] = Cryptage.decrypt(privKeyA, step2);

            NShroederSender needShroeder = (NShroederSender) ByteToObject(step2Decrypt);

            return needShroeder;
        } catch (Exception e) {
            System.out.println("getNonceANonceBstep2 " + e);;
        }
        return null;
    }

    //B récupère la nonceB
    public static NShroederSender getNonceBstep3(byte[] step3, PrivateKey privKeyB) {

        try {
            byte step3Decrypt[] = Cryptage.decrypt(privKeyB, step3);

            NShroederSender needShroeder = (NShroederSender) ByteToObject(step3Decrypt);

            return needShroeder;
        } catch (Exception e) {
            System.out.println("getNonceBstep3 " + e);;
        }
        return null;
    }

    ///////////////////////////////
    public static byte[] ObjectToByte(Object o) {//transformer un objet en tableau de byte

        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(b);
            oos.writeObject(o);
            byte[] bytes = b.toByteArray();

            return bytes;
        } catch (Exception e) {
            System.out.println("ObjectToByte " + e);;
        }
        return null;
    }

    public static Object ByteToObject(byte[] bytes) {//transformer un tableau de byte en objet

        try {
            Object obj = null;

            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            obj = ois.readObject();

            return obj;

        } catch (Exception e) {
            System.out.println("ByteToObject " + e);;
        }
        return null;
    }

    //B récupère la nonceA
    public static BigInteger nonceAstep1(byte[] step1, PrivateKey privKeyB) {

        NShroederSender ns;
        try {
            ns = NShroederSender.getNonceAstep1(step1, privKeyB);
            byte[] bytesNonceA = ns.getNonceA();
            BigInteger nonceA = new BigInteger(bytesNonceA);

            return nonceA;

        } catch (Exception e) {
            System.out.println("nonceAStep1 " + e);;
        }
        return null;
    }

    //A récupère la nonceA et nonceB
    public static BigInteger[] nonceAnonceBstep2(byte[] step2, PrivateKey privKeyA) {

        try {
            NShroederSender ns = NShroederSender.getNonceANonceBstep2(step2, privKeyA);
            byte[] bytesNonceA = ns.getNonceA();
            byte[] bytesNonceB = ns.getNonceB();
            BigInteger[] tabBigInt = new BigInteger[2];

            tabBigInt[0] = new BigInteger(bytesNonceA);
            tabBigInt[1] = new BigInteger(bytesNonceB);

            return tabBigInt;
        } catch (Exception e) {
            System.out.println("nonceBstep2 " + e);
        }
        return null;
    }

    //B récupère la nonceB
    public static BigInteger nonceBstep3(byte[] step3, PrivateKey privKeyB) {

        try {
            NShroederSender ns = NShroederSender.getNonceBstep3(step3, privKeyB);
            byte[] bytesNonceB = ns.getNonceB();

            BigInteger nonceB = new BigInteger(bytesNonceB);

            return nonceB;
        } catch (Exception e) {
            System.out.println("nonceAStep3 " + e);;
        }
        return null;
    }

    //génère un bigInteger 
    public static BigInteger generateNonce() {

        Random random = new Random();

        BigInteger nonce = new BigInteger(53, random);

        return nonce;
    }

    //Vérifie si deux nonces sont identiques
    public static boolean isEqualsNonces(BigInteger nonce1, BigInteger nonce2) {

        if (nonce1.equals(nonce2)) {
            return true;
        } else {
            return false;
        }
    }

    //générer ybe clé de session en utilisant les nonces
    public static byte[] genSessionKeyFromNonces(byte[] nonceA, byte[] nonceB) {

        try {
            int size = nonceA.length + nonceB.length;
            byte[] key = new byte[size];

            System.arraycopy(nonceA, 0, key, 0, nonceA.length);
            System.arraycopy(nonceB, 0, key, nonceA.length, nonceB.length);
            
            return digest(key);
        } 
        catch (Exception e) {
            System.out.println("genSessionKeyFromNonces : " + e);
        }
        return null;
    }

    public String getIdA() {
        return idA;
    }

    public byte[] getNonceA() {
        return nonceA;
    }

    public byte[] getNonceB() {
        return nonceB;
    }

}
