/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enchange.info;

import KerberosAPI.Cryptage;
import static KerberosAPI.Cryptage.encrypt;
import KerberosAPI.DataSenderProtocol;
import KerberosAPI.readAndWriteObject;
import Useful.DataBase;
import Useful.InfoService;
import static enchange.info.ServiceObject.ObjectToByte;
import java.io.IOException;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.PublicKey;
import java.util.ArrayList;

/**
 *
 * @author Aliou
 */
public class ClientInfo extends Thread {
        
    String ip;
    int port;
    Socket s;
    String login;

    public ClientInfo(int port, String login) {
        this.port = port;
        this.login = login;
    }
    
    public void run(){
    
        try{
            
        
        DataBase db = new DataBase("localhost", "root", "");
        db.connexion();
        
        PublicKey pubKeyClient = db.getCertificate(login).getPublicKey();
        
        ArrayList <ServiceObject> servObject = db.getListService();
        
         for(int i = 0; i<servObject.size(); i++){
            
             ServiceObject object = servObject.get(i);
             
             byte [] toSend = encrypt(pubKeyClient, ObjectToByte(object));
             
             s = new Socket(ip, port);
             readAndWriteObject readWrite = new readAndWriteObject(s);
             
             readWrite.writeObject(toSend);   
             
             s.close();
         }
        
       } 
        catch (Exception e) {
            System.out.println("CSRRequest => connect : "+e);
        }
    }
}
