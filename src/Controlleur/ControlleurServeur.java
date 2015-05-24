/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlleur;

import static KerberosAPI.DigestManager.digest;
import SC.ServerCert;
import Useful.DataBase;

/**
 *
 * @author Aliou
 */
public class ControlleurServeur {
    
    ServerCert sc ;
    
    public ControlleurServeur(){
        
    }
    
    public void addUser(String login, String mdp){
    
        DataBase db = new DataBase("localhost", "root", "");        
        db.connexion();
        
        try {
            db.addUser(login, digest(mdp));
        } catch (Exception e) {
            System.out.println(e);
        }
        db.deconnexion();
    }
    
    public void LancerServeur(){
       
        try {
            sc = new ServerCert(1010);
        } catch (Exception e) {
            System.out.println(e);
        }
        sc.start();
    }
    
    public void arreterServeur(){
        sc.close();
        System.out.println("serveur stoppé");
    }
    
}
