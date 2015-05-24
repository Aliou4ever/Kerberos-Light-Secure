/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class NeedhamShroeder {
    
    public static byte[] AtoB1(String identiteA, BigInteger nonceA, X509Certificate certB) {        
        //A envoie {nonceA} à B
        try {
            byte [] A_B1 = NShroederSender.createAtoB1(identiteA, nonceA.toByteArray(), certB.getPublicKey());
            
            return A_B1;
        } 
        catch (Exception e) {
            System.out.println("AtoB1 : "+e);
            return null;
        }
    }
    
    public static byte[] BtoA2(BigInteger nonceA, BigInteger nonceB, X509Certificate certA) {        
        //B envoie {nonceA,nonceB} à A
        try {
            byte [] B_A2 = NShroederSender.createBtoA2(nonceA.toByteArray(), nonceB.toByteArray(), certA.getPublicKey());
            
            return B_A2;
        } 
        catch (Exception e) {
            System.out.println("BtoA2 : "+e);
            return null;
        }
    }
    
    public static byte[] AtoB3(BigInteger nonceB, X509Certificate certB) {        
    //A envoie {nonceB} à B
        try {
            byte [] A_B3 = NShroederSender.createAtoB3(nonceB.toByteArray(), certB.getPublicKey());
            
            return A_B3;
        } 
        catch (Exception e) {
            System.out.println("AtoB3 : "+e);
            return null;
        }
    }
    
   
}
