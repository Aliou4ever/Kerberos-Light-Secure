/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class ProtocolClientSC {

    public static byte[] AtoSC1(String identiteA, String identiteB, PublicKey pubKeySC) {

        try {
            byte [] A_SC = DataSenderProtocol.createAtoSC1(identiteA, identiteB, pubKeySC);
            
            return A_SC;
        } 
        catch (Exception e) {
            System.out.println("AtoSC1 : "+e);
            return null;
        }
    }
    
    public static byte [] SCtoA2(String identiteB, X509Certificate certB, PrivateKey privKeySC, PublicKey pubKeyA){
    
        try {
            byte [] SC_A = DataSenderProtocol.createSCtoA2(identiteB, certB, privKeySC, pubKeyA);
            
            return SC_A;
        } 
        catch (Exception e) {
            System.out.println("SCtoA2 : "+e);
            return null;
        }
    }
    
    public  static byte [] SCtoB3(String identiteA, X509Certificate certA, PrivateKey privKeySC, PublicKey pubKeyB){
    
        try {
            byte [] SC_B = DataSenderProtocol.createSCtoB3(identiteA, certA, privKeySC, pubKeyB);
            
            return SC_B;
            
        } catch (Exception e) {
            System.out.println("SCtoB3 : "+e);
            return null;
        }
    }
}
