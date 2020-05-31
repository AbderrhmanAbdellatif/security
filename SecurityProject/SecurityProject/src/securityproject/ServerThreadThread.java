/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
/**
 * @Teachers  Ömer KORÇAK
 * @author Abderrhman Abdellatif ,Mehmet Fatih GEZEN
 * @date 31/05/2020
 * @time  2:25 PM
 * @class BLM442E Computer System Security
 * @ID    1421221042 ,1821221017
 **/
public class ServerThreadThread extends Thread {

    private ServerThread serverThread;
    private Socket socket;
    private PrintWriter printWriter;

    public ServerThreadThread(Socket socket, ServerThread serverThread) {
        this.serverThread = serverThread;
        this.socket = socket;
    }


    @Override
    public void run() {
        try {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

            this.printWriter = new PrintWriter(socket.getOutputStream(), true);
            
            while (true) {
                serverThread.sendMessage(bufferedReader.readLine());
            }
        } catch (IOException e) {
            serverThread.getServerThreadThreads().remove(this);
        }

    }
    
    public PrintWriter getPrintWriter() {
        return printWriter;
    }

}
