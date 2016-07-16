# Document-Digital-Signature-and-Verification-

### Acknoweldgements
This project was done in collaboration with teammate <b> Amine Ouahi </b> under the supervision of <b> Dr. Tajj Eddine Rachidi </b>.

### Project Description
This project makes use of Java Cryptography Extension to implement an application that digitally signs and
verifies the signature of any document.

The certificate ‘name-cert.p12’ that contains a public key and a corresponding private key ‘name-key.pem’ is downloaded and created
from http://www.flatmtn.com/article/creating-pkcs12-certificate.  

This application browses to get the file to be signed, as well as the name-key.pem file
that contains the private key. It signs the file and writes both the file and its signature in a PKCS7 format.
The application also provides a verification function. That is, given a PKCS7 file (including file
and its signature), and a certificate with the public key name-cert.p12, it states whether
the file has or has not been tempered with. 
