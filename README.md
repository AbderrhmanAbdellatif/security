# Security
computer system security

Abderrhman Abdellatif ,Mehmet Fatih GEZEN<br />
1421221042 ,1821221017 

# Platform 
 zoom<br />
 hangout<br />
 netbeans 8.2 with jdk<br />
 java<br />

# Communication
we spoke on zoom and hangout <br />
Handshaking,Resistance to Replay Attacks:Mehmet Fatih GEZEN<br />
Integrity Check:Mehmet Fatih GEZEN,Abderrhman Abdellatif<br />
Message Encryption,Key Generation:Abderrhman Abdellatif<br />
we did not  merge our code.We wrote code on Abderrhman's machine<br />

# Design Choices:
Q4:Integrity Check<br />
We used HMAC for integrity check.We put message nonce and message into HMAC.<br />
We used SHA256 algorithm.On target side took the nonce and replayed HMAC and<br />
compared this with JSON.<br />

Q5:Resistance to Replay Attacks<br />
We used Nonce.We increased sequence number for each message send.we store each HMAC<br />
of message  in  a collection (List).If the gotten message is in collection it is a Replay Attack.<br />

# Source
https://www.youtube.com/watch?v=CcLOj3uhb0A&feature=youtu.be<br />
https://www.codeproject.com/Tips/991180/Java-Sockets-and-Serialization<br />
https://www.it-swarm.dev/tr/java/hmac-sha256-imza-hesaplama-icin-algoritma/940318319/amp/<br />
