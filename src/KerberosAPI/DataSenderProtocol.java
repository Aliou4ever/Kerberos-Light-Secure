/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import static KerberosAPI.Cryptage.encrypt;
import static KerberosAPI.Cryptage.signature;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class DataSenderProtocol implements Serializable {

    //Construction des messages à échanger dans un protocole de CSR
    //////////////////////////////////////////////////////
    String idA;
    String idB;
    String idSC;
    X509Certificate cert;
    byte[] certSign;

    public DataSenderProtocol(String idA, String idB) {
        this.idA = idA;
        this.idB = idB;
    }

    public DataSenderProtocol(String idB, X509Certificate cert, byte[] certSign) {
        this.idB = idB;
        this.cert = cert;
        this.certSign = certSign;
    }

    //A envoie à SC : {A, B}Ksc
    public static byte[] createAtoSC1(String idA, String idB, PublicKey pubKeySC) {

        try {
            DataSenderProtocol dsp = new DataSenderProtocol(idA, idB);

            byte[] msg = ObjectToByte(dsp);

            byte[] msgEncrypt = encrypt(pubKeySC, msg);

            return msgEncrypt;
        } catch (Exception e) {
            System.out.println("createAtoSC1 " + e);;
        }
        return null;
    }

    //SC decrypte le message réçu de A
    public static DataSenderProtocol getAtoSC1(byte[] dataEncrypt, PrivateKey privKey) {

        try {
            byte decrypt[] = Cryptage.decrypt(privKey, dataEncrypt);

            DataSenderProtocol dsp = (DataSenderProtocol) ByteToObject(decrypt);

            return dsp;

        } catch (Exception e) {
            System.out.println("getAtoSC1 " + e);;
        }
        return null;
    }

    //SC envoie à A {B, Kb, {Kb}Ksc-1}Ka
    public static byte[] createSCtoA2(String idB, X509Certificate certB, PrivateKey privKeySC, PublicKey pubKeyA) {

        try {
            byte[] certBytes = certB.getEncoded();
            byte[] certSignB = signature(privKeySC, certBytes);

            DataSenderProtocol dsp = new DataSenderProtocol(idB, certB, certSignB);

            byte[] msg = ObjectToByte(dsp);

            byte[] msgEncrypt = encrypt(pubKeyA, msg);

            return msgEncrypt;

        } catch (Exception e) {
            System.out.println("createSCtoA2 " + e);;
        }
        return null;
    }

    //A decrypte le message réçu de SC
    public static DataSenderProtocol getSCtoA2(byte[] dataEncrypt, PrivateKey privKey) {

        try {            
            byte decrypt[] = Cryptage.decrypt(privKey, dataEncrypt);

            DataSenderProtocol dsp = (DataSenderProtocol) ByteToObject(decrypt);

            return dsp;
        } catch (Exception e) {
            System.out.println("getSCtoA2 " + e);
        }
        return null;
    }

    //SC envoie à B {B, Ka, {Ka}Ksc-1}Kb
    public static byte[] createSCtoB3(String idA, X509Certificate certA, PrivateKey privKeySC, PublicKey pubKeyB) {

        try {
            byte[] certBytes = certA.getEncoded();
            byte[] certSignA = signature(privKeySC, certBytes);

            DataSenderProtocol dsp = new DataSenderProtocol(idA, certA, certSignA);

            byte[] msg = ObjectToByte(dsp);

            byte[] msgEncrypt = encrypt(pubKeyB, msg);

            return msgEncrypt;
        } catch (Exception e) {
            System.out.println("createSCtoB3 " + e);;
        }
        return null;
    }   

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

    //récuperer l'identité de A    
    public String getIdA() {

        return idA;
    }
    //récuperer l'identité de B

    public String getIdB() {
        return idB;
    }
        
    public String getIdSC() {
        return idSC;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public byte[] getCertSign() {
        return certSign;
    }
}
