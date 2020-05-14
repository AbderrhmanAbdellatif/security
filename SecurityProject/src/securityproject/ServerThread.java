/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author 572G
 */
public class ServerThread extends Thread {
    private ServerSocket serverSocket;
    private Set<ServerThreadThread> serverThreadThreads =new HashSet<>();
    
    public ServerThread(int portNumber) throws IOException {
        serverSocket = new ServerSocket(portNumber);
    }
    @Override
    public void run(){
         try {
            ServerThreadThread serverThreadThread=new ServerThreadThread(serverSocket.accept(), this);
            serverThreadThreads.add(serverThreadThread);
            serverThreadThread.start();
        } catch (Exception e) {
        }
    }
    void sendMessage(String message){
        try {
            serverThreadThreads.forEach(t -> {
                t.getPrintWriter().println(message);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public  Set<ServerThreadThread> getServerThreadThreads (){ return  serverThreadThreads;}
}
