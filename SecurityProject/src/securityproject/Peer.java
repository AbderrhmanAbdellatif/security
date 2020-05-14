/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.Socket;
import javax.json.Json;

/**
 *
 * @author 572G
 */
public class Peer {

    public static void main(String[] args) throws IOException, Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("> enter username & port # for this peer:");
        String[] setupValues = bufferedReader.readLine().split(" ");
        ServerThread serverThread = new ServerThread(Integer.parseInt(setupValues[1]));
        serverThread.start();

        new Peer().listenToPeer(bufferedReader, setupValues[0], serverThread);
    }

    public void listenToPeer(BufferedReader bufferedReader, String username, ServerThread serverThread) throws Exception {
        System.out.println("> enter (space seperated) hostname:port#");
        System.out.println(" peers to receive messages from");
        String input = bufferedReader.readLine();
        String[] inputValues = input.split(" ");
        if (!input.equals("s")) {
            for (int i = 0; i < inputValues.length; i++) {
                String[] address = inputValues[i].split(":");
                Socket socket = null;
                try {
                    socket = new Socket(address[0], Integer.valueOf(address[1]));
                    new PeerThread(socket).start();
                 } catch (IOException | NumberFormatException e) {
                    if (socket != null) {
                        socket.close();
                    } else {
                        System.out.println("invalid input");
                    }
                }
            }
        }
        communicate(bufferedReader,username,serverThread);
    }
    public void communicate(BufferedReader bufferedReader, String username, ServerThread serverThread){
        try{
            System.out.println("you can communicate");
            boolean flag = true;
            while(flag){
                String mesaage = bufferedReader.readLine();
                if(mesaage.equals("e")){
                    flag = false;
                    break; 
                }else if(mesaage.equals("c")){
                    listenToPeer(bufferedReader, username, serverThread);
                }else{
                    StringWriter stringWriter = new StringWriter();
                    Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                                                                .add("username",username)
                                                                .add("message",mesaage)
                                                                .build());
                    serverThread.sendMessage(stringWriter.toString());
                }
            }
            System.exit(0);
        } catch(Exception e){
            
        }
    }
}
