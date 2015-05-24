/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlleur;

import KerberosAPI.DigestManager;
import SS.CertRequestSS;
import SS.ServerServices;
import SS.ServicesSocket;
import Useful.DataBase;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class ControlleurService {
    
    ServerServices service;
    ServicesSocket serviceSocket;
    X509Certificate certSS;
    public ControlleurService() {

    }

    
    public void lancerSS() {

        service.start();                
    }
    
    public void lancerService() {
        try{
            System.out.println("Lancement Serveur de Service");
            serviceSocket = new ServicesSocket(1020);
        }
        catch(Exception e){
            System.out.println(e);
        }
            serviceSocket.start();
    }
        
    public boolean connect(String login, String mdp) {
        boolean res = false;
        try {
            DataBase db = new DataBase("localhost", "root", "");
            db.connexion();
            byte[] mdpdb;
            byte[] mdpEntred = DigestManager.digest(mdp);

            if (db.userExists(login)) {
                mdpdb = db.getPassword(login);
                if (DigestManager.digestVerify(mdpdb, mdpEntred)) {
                    service = new ServerServices(login, mdp);
                    res= true;
                } else {
                    System.out.println("Erreur de comparaison de mot de passe");
                }

            }
            db.deconnexion();
        } catch (Exception e) {
            System.out.println("erreur : " + e.toString());
        }

        return res;
    }   
    
    public boolean getCertSS(String loginSS) {
        boolean res = false;
        try {
            DataBase db = new DataBase("localhost", "root", "");
            db.connexion();
            if (db.userExists(loginSS)) {
                
                CertRequestSS certReqSS = new CertRequestSS(1010, loginSS);
               
                certReqSS.connect();
                
                String ssID = service.getLogin();
                                
                certReqSS.run(ssID);
                res = true;
          }
            db.deconnexion();
        } catch (Exception e) {
            System.out.println("ControlleurService => getCertSS : "+e);
        }
        return res;
    }    
}
