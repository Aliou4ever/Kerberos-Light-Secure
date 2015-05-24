/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enchange.info;

import Client.Client;
import static KerberosAPI.Cryptage.decrypt;
import KerberosAPI.readAndWriteObject;
import static enchange.info.ServiceObject.ByteToObject;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.PublicKey;

/**
 *
 * @author Aliou
 */
public class ServeurInfo extends Thread {

    int port;
    ServerSocketChannel ssc;
    Client client;

    //
    public ServeurInfo(Client client) {

        this.client = client;
        
        try {
            
            ssc = ServerSocketChannel.open();
            ssc.socket().bind(new InetSocketAddress(0));

            port = ssc.socket().getLocalPort();

            System.out.println("Port  : " + port);
            System.out.println("ServeurInfo attend sur le port "
                    + ssc.socket().getLocalPort() + "...");
            
            //run();
            
        } catch (Exception e) {
            System.out.println("");
        }
    }

    public void run() {
        while (true) {
            try {

                SocketChannel channel = ssc.accept();      
                
                readAndWriteObject readWrite = new readAndWriteObject(channel);
                
                byte[] receive = readWrite.readObject();
                
                PublicKey pubKey = client.getCsr().getPubKeySC();
                                
                byte[] decrypted = decrypt(client.getPrivKey(), receive);
                
                ServiceObject servObject = (ServiceObject) ByteToObject(decrypted);
                                
                if(!client.containsContact(servObject)) client.getListeContact().add(servObject);               
                

            } catch (Exception e) {
                System.out.println("ServeurInfo => run : " + e);
            }

        }
    }

    public int getPort() {
        return port;
    }

}
