/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enchange.info;


import static KerberosAPI.Cryptage.decrypt;
import KerberosAPI.readAndWriteObject;
import SS.ServerServices;
import static enchange.info.ServiceObject.ByteToObject;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.PublicKey;

/**
 *
 * @author Aliou
 */
public class ServeurInfoSS extends Thread {

    int port;
    ServerSocketChannel ssc;
    ServerServices servService;

    //
    public ServeurInfoSS(ServerServices servService) {

        this.servService = servService;
        
        try {
            
            ssc = ServerSocketChannel.open();
            ssc.socket().bind(new InetSocketAddress(0));

            port = ssc.socket().getLocalPort();

            System.out.println("Port  : " + port);
            System.out.println("ServeurInfo attend sur le port "
                    + ssc.socket().getLocalPort() + "...");
            
            run();
            
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
                
                //PublicKey pubKey = servService.getCsr().getPubKeySC();
                                
                byte[] decrypted = decrypt(servService.getCsr().getPrivKey(), receive);
                
                ServiceObject servObject = (ServiceObject) ByteToObject(decrypted);
                                
                if(!servService.containsContact(servObject)) servService.getListeContact().add(servObject);               
                

            } catch (Exception e) {
                System.out.println("ServeurInfo => run : " + e);
            }

        }
    }

    public int getPort() {
        return port;
    }

}
