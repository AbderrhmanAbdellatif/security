/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.json.Json;

public class ServerThread extends Thread {

    private ServerSocket serverSocket;
    private Set<ServerThreadThread> serverThreadThreads = new HashSet<>();
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
//            SecurityManager sm = new SecurityManager();
//            sm.checkAccept("localhost", serverSocket.getLocalPort());
//            System.out.println("Bağlandı");
            peerCount++;

            serverThreadThreads.add(serverThreadThread);
            serverThreadThread.start();
        } catch (Exception e) {

        }

    }

    void sendMessage(String message) {
        try {
            serverThreadThreads.forEach(t -> {
                t.getPrintWriter().println(message);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendSignal() {
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("signal", "ACK")
                .build());
        System.out.println("sendSignal");
        sendMessage(stringWriter.toString());
    }

    public void sendHandshake(PublicKey publicKey) {

        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
//        String publicKeyString2 = "publickey="+publicKeyString; //TODO: İSİMLENDİRME YAPILACAK  
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("publicKey", publicKeyString)
                .build());
//        serverThread.sendMessage(stringWriter.toString());
        System.out.println("sendHandshake");
        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });

    }

    public void sendCertificate(X509Certificate certificate,int nonce) throws CertificateEncodingException, UnsupportedEncodingException {
        
        System.out.println("sendCertificate");
        System.out.println("this nonce is send certificate "+nonce);
        String charsetName = "ISO-8859-1";
        String publicCertificateString = new String(certificate.getEncoded(), charsetName); // TODO: mustafa base64 kullanmasi D:"  https://gist.github.com/RevenueGitHubAdmin/90d3af2f4fbe13fec85a763066e7bab0

        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("publicCertificateString", publicCertificateString)
                .add("nonce",nonce)
                .build());
//        serverThread.sendMessage(stringWriter.toString());
        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });

    }

    public void sendNonceBack(PrivateKey privateKey, int nonce) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] array = ByteBuffer.allocate(4).putInt(nonce).array();
        byte[] encryptedNonceBytes = cipher.doFinal(array);
        String charsetName = "ISO-8859-1";
        String encryptedNonceString = new String(encryptedNonceBytes, charsetName); // TODO: mustafa base64 kullanmasi D:"  https://gist.github.com/RevenueGitHubAdmin/90d3af2f4fbe13fec85a763066e7bab0
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
                .add("nonce", encryptedNonceString)
                .build());
        serverThreadThreads.forEach(t -> {
            t.getPrintWriter().println(stringWriter.toString());
        });
    }

    public Set<ServerThreadThread> getServerThreadThreads() {
        return serverThreadThreads;
    }
     
}
