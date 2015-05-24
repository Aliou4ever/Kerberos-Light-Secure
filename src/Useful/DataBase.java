/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Useful;

import static KerberosAPI.Certificate.getCertBytes;
import enchange.info.ServiceObject;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;

/**
 *
 * @author Aliou
 */
public class DataBase {

    private String url;
    private String login;
    private String mdp;
    private Connection con;

    public DataBase(String url, String login, String mdp) {
        this.url = url;
        this.login = login;
        this.mdp = mdp;
    }

    public boolean connexion() {
        boolean openCon = false;
        try {
            Class.forName("com.mysql.jdbc.Driver");
            String url = "jdbc:mysql://" + this.url + "/KerberosDB?user=" + login + "&password=" + mdp;
            con = DriverManager.getConnection(url, login, mdp);
            System.out.println("Connexion : OK");
            openCon = true;
        } catch (Exception e) {
            System.err.println("Echec de connexion ) la base" + e);
            openCon = false;
        }
        return openCon;
    }

    public boolean deconnexion() {
        boolean closeCon = false;
        try {
            con.close();
            //System.out.println("Deconnexion OK");
            closeCon = true;
        } catch (Exception e) {
            System.out.println("Echec deconnexion : "+e);
        }
        return closeCon;
    }

    public void addUser(String login, byte[] mdp) {
        try {

            String requete = "insert into users(login,mdp)values(?,?)";

            PreparedStatement statement = (PreparedStatement) con.prepareStatement(requete);
            statement.setObject(1, login);
            statement.setObject(2, mdp);
            statement.execute();

            System.out.println("Ajout d'un utilisateur OK");
            statement.close();
        } catch (Exception e) {
            System.out.println("Erreur d'ajout de l'utlisateur " + login + " : " + e);
        }
    }

    public boolean userExists(String login) {
        boolean res = false;
        try {
            String requete = "select * from users where login='" + login + "'";

            PreparedStatement statement = con.prepareStatement(requete);
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                res = true;
            }
            statement.close();
        } catch (Exception ex) {
            System.out.println("user : " + login + " n'existe pas dans la base: " + ex);
        }
        return res;
    }

    public byte[] getPassword(String login) {
        byte[] res = null;
        try {
            String requete = "select * from users where login='" + login + "'";
            PreparedStatement statement = con.prepareStatement(requete);
            ResultSet rs = statement.executeQuery();
            if (rs.next()) {
                res = rs.getBytes("mdp");
            }
            statement.close();
        } catch (Exception e) {
            System.out.println("Problème de recherche user "+login+" dans la base: " + e);
        }
        return res;
    }
    
    //ajouter un certificat dans la base 
     public void addCertificate(String login, X509Certificate cert) {
        try {
            byte[] bytesCert = cert.getEncoded();
            String requete = "insert into Certificat(login,certificat)values(?,?)";
            
            PreparedStatement statement = (PreparedStatement) con.prepareStatement(requete);
            statement.setObject(1, login);
            statement.setBytes(2, bytesCert);            
            statement.execute();
            System.out.println("Insertion de certificat réussi.");
            statement.close();
        } catch (Exception e) {
            System.out.println("Echec d'insertion de certificat : " + e);
        }
    }
     
     //récupérer un certificat dans la base
     public X509Certificate getCertificate(String login) {
        byte[] bytes = null;
        try {
            String requete = "select * from Certificat where login='" + login + "'";
            PreparedStatement statement = con.prepareStatement(requete);
            ResultSet rs = statement.executeQuery();
            rs.next();
            bytes = rs.getBytes("certificat");
            statement.close();
        } catch (Exception e) {
            System.out.println("récuperation du certificat : " + e);
            return null;
        }
        return getCertBytes(bytes);
    }

     //récupérer liste de services avec leurs numéros port 
     public ArrayList<ServiceObject> getListService(){
     
         ArrayList servObj = new ArrayList<ServiceObject>();
         try{         
            String requete = "select * from services ";
            PreparedStatement statement = con.prepareStatement(requete);
            ResultSet res = statement.executeQuery();
            while(res.next()){
                ServiceObject obj = new ServiceObject();
                obj.setLogin((String) res.getObject("login"));
                obj.setService((String)res.getObject("service"));
                obj.setPort(res.getInt("port"));
                
                servObj.add(obj);                
            }
         statement.close();;
         }
         catch (Exception e) {
            System.out.println("récuperation de services : " + e);
        }
         return servObj;
     }
     
    public void setLogin(String login) {
        this.login = login;
    }

    public void setMdp(String mdp) {
        this.mdp = mdp;
    }

    public String getLogin() {
        return login;
    }

    public String getMdp() {
        return mdp;
    }

    public Connection getCon() {
        return con;
    }

    public void setCon(Connection con) {
        this.con = con;
    }
    
//    public static void main(String[] args) {
//        
//        DataBase db = new DataBase("localhost", "root", "");
//        db.connexion();
//        
//        ArrayList <ServiceObject> servObj;
//        servObj = db.getListService();
//        
//        for(int i = 0; i<servObj.size(); i++){
//            ServiceObject obj = servObj.get(i);
//            
//            System.out.println("login : "+obj.getLogin()+"  service : "+obj.getService()+"  port : "+obj.getPort());
//        }
//        
//    }

}
