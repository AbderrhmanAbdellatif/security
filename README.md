# Security
computer system security

Abderrhman Abdellatif ,Mehmet Fatih GEZEN
1421221042 ,1821221017 

# Platform 
 zoom
 hangout
 netbeans 8.2 with jdk
 java

# Communication
we spoke on zoom and hangout 
Handshaking,Resistance to Replay Attacks:Mehmet Fatih GEZEN
Integrity Check:Mehmet Fatih GEZEN,Abderrhman Abdellatif
Message Encryption,Key Generation:Abderrhman Abdellatif
we did not  merge our code.We wrote code on Abderrhman's machine

# Design Choices:
Q4:Integrity Check
We used HMAC for integrity check.We put message nonce and message into HMAC.
We used SHA256 algorithm.On target side took the nonce and replayed HMAC and
compared this with JSON.

Q5:Resistance to Replay Attacks
We used Nonce.We increased sequence number for each message send.we store each HMAC
of message  in  a collection (List).If the gotten message is in collection it is a Replay Attack.

# Source
https://www.youtube.com/watch?v=CcLOj3uhb0A&feature=youtu.be
https://www.codeproject.com/Tips/991180/Java-Sockets-and-Serialization
https://www.it-swarm.dev/tr/java/hmac-sha256-imza-hesaplama-icin-algoritma/940318319/amp/
