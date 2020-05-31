/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.json.Json;
/**
 * @Teachers  Ömer KORÇAK
 * @author Abderrhman Abdellatif ,Mehmet Fatih GEZEN
 * @date 31/05/2020
 * @time  2:25 PM
 * @class BLM442E Computer System Security
 * @ID    1421221042 ,1821221017
 **/
public class ServerThread extends Thread {

    private final ServerSocket serverSocket;
    private final Set<ServerThreadThread> serverThreadThreads = new HashSet<>();
    public int peerCount = 0;

    public ServerThread(int portNumber) throws IOException {
        serverSocket = new ServerSocket(portNumber);
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    @Override
    public void run() {

        try {
            ServerThreadThread serverThreadThread = new ServerThreadThread(serverSocket.accept(), this);
            peerCount++;

            serverThreadThreads.add(serverThreadThread);
            serverThreadThread.start();
        } catch (IOException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    void sendMessage(String message) {
        //carrierObject take the object between Peer and ServerThread and transfer the object to ServerThread class
        ServerThread serverThread= (ServerThread) Peer.carrierObject[2];
        try {
            serverThread.serverThreadThreads.forEach(t -> {
                t.getPrintWriter().println(message);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendSignal() {
        //sendSignal method for bob sends connection signal if connection complete
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("signal", "ACK")
                .build());
        sendMessage(stringWriter.toString());
    }

    void sendCommunicationSignal() {
        // sendCommunicationSignal 
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("communicationSignal", "ACK")
                .build());
        sendMessage(stringWriter.toString());
    }
     //send public key to bob
    public void sendHandshake(PublicKey publicKey) {

        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());  
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("publicKey", publicKeyString)
                .build());
        
        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });
    }

    public void sendKeys(SecretKey kA, SecretKey kB, byte ivA[], byte ivB[]) throws UnsupportedEncodingException {
       //send key to bob 
        String kAString = new String(kA.getEncoded(), Constants.charsetName); 
        String kBString = new String(kB.getEncoded(), Constants.charsetName); 
        String ivAString = new String(ivA, Constants.charsetName); 
        String ivBString = new String(ivB, Constants.charsetName); 

        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("kA", kAString)
                .add("kB", kBString)
                .add("ivA", ivAString)
                .add("ivB", ivBString)
                .build());

        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });
    }

    public void sendCertificate(X509Certificate certificate, int nonce) {
            // bob to  alice 
        try {
            String publicCertificateString = new String(certificate.getEncoded(), Constants.charsetName); 

            StringWriter stringWriter = new StringWriter();
            Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                    .add("publicCertificateString", publicCertificateString)
                    .add("authenticationNonce", nonce)
                    .build());

            serverThreadThreads.forEach(t -> {
                t.getPrintWriter().println(stringWriter.toString());
            });
        } catch (CertificateEncodingException | UnsupportedEncodingException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void sendNonceBack(PrivateKey privateKey, int nonce) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
       // send Nonce Back to bob 
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] array = ByteBuffer.allocate(4).putInt(nonce).array();
        byte[] encryptedNonceBytes = cipher.doFinal(array);
        
        String encryptedNonceString = new String(encryptedNonceBytes, Constants.charsetName); 
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("nonceBack", encryptedNonceString)
                .build());
        
        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });
    }

    public void sendAcknowledgement() {
        //if nonce is equal send acknowledgement to  alice 
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("ACK", "ack")
                .build());
        
        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });
    }

    public Set<ServerThreadThread> getServerThreadThreads() {
        return serverThreadThreads;
    }

}
