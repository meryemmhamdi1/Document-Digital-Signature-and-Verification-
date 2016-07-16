package cryptoproject2;

import java.awt.BorderLayout;
import java.io.*;
import java.security.*;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.lang.Object;

import javax.xml.bind.DatatypeConverter; 

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import java.util.*;


public class FileSigner extends JFrame {

	private JPanel contentPane;
	private JTextField fileField;
	private JTextField keyField;
	private PKCS8EncodedKeySpec spec;
	private KeyFactory kf;
	private  PrivateKey privatekey;
	

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		
				try {
					FileSigner frame = new FileSigner();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			 /* Generate a DSA signature */

	        if (args.length != 1) {
	            System.out.println("Usage: GenSig nameOfFileToSign");
	        }
	        else try {

	        // the rest of the code goes here

	        } catch (Exception e) {
	            System.err.println("Caught exception " + e.toString());
	        }
		
	}

	/**
	 * Create the frame.
	 */
	public FileSigner() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		setTitle("PKCS7 Signature of Files");
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JLabel label1 = new JLabel("File to be Signed:");
		label1.setBounds(20, 35, 128, 16);
		contentPane.add(label1);
		
		fileField = new JTextField();
		fileField.setBounds(166, 29, 154, 28);
		contentPane.add(fileField);
		fileField.setColumns(10);
		
		JButton BrowseFile = new JButton("Browse");
		BrowseFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				final JFileChooser fc = new JFileChooser();
	            fc.showOpenDialog(contentPane);

	            try {
	                // Open an input stream
	                Scanner reader = new Scanner(fc.getSelectedFile());
	                File file_to_sign = fc.getSelectedFile();
	                fileField.setText(file_to_sign.toString());
	                
	               
	                
	            }
	            catch (Exception e){
	            	System.out.println(e);
	            }
	            
			}
		});
		BrowseFile.setBounds(332, 30, 117, 29);
		contentPane.add(BrowseFile);
		
		JLabel lblPrivateKey = new JLabel("Private Key (.p12 file)");
		lblPrivateKey.setBounds(20, 92, 134, 16);
		contentPane.add(lblPrivateKey);
		
		keyField = new JTextField();
		keyField.setColumns(10);
		keyField.setBounds(166, 86, 154, 28);
		contentPane.add(keyField);
		

		JButton BrowseKey = new JButton("Browse");
		BrowseKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fc = new JFileChooser();
	            fc.showOpenDialog(contentPane);

	            try {
	            	java.security.Security.addProvider(
	            	         new org.bouncycastle.jce.provider.BouncyCastleProvider()
	            	);
	                // Open an input stream
	                Scanner reader = new Scanner(fc.getSelectedFile());
	                File file = fc.getSelectedFile();
	                keyField.setText(file.toString());
	                FileInputStream fis = new FileInputStream(file);
	                DataInputStream dis = new DataInputStream(fis);
	                byte[] keyBytes = new byte[(int) file.length()];
	                dis.readFully(keyBytes);
	                dis.close();
	            }
	            
	            catch (Exception e1){
	            	System.out.println("Bad Error =>"+e1);
	            }
			}
		});
		BrowseKey.setBounds(327, 87, 117, 29);
		contentPane.add(BrowseKey);
		
		JButton btnSignFile = new JButton("Sign File");
		btnSignFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				try {
					
					KeyStore ks = null;
					char[] password = null;

					Security.addProvider(new BouncyCastleProvider());
					//extracting information about certificate, private key from .p12 file
					try {
						ks = KeyStore.getInstance("PKCS12");
						// password name-cert.p12
						password = "private".toCharArray();
						ks.load(new FileInputStream(keyField.getText()), password);
					} catch (Exception ex) {
						System.out.println("Error: file " +
					                       "name-cert.p12" +
					                       " is not in pkcs#12 format or passphrase is incorrect");
						return ;
					}

					// get certificate and public key from the name-cert.p12

					X509Certificate cert = null;
					PublicKey publickey = null;
					PrivateKey privatekey = null;

					try {
						Enumeration en = ks.aliases();
						String ALIAS = "";
						Vector vectaliases = new Vector();

						while (en.hasMoreElements())
							vectaliases.add(en.nextElement());
						String[] aliases = (String []) (vectaliases.toArray(new String[0]));
						for (int i = 0; i < aliases.length; i++)
							if (ks.isKeyEntry(aliases[i]))
							{
								ALIAS = aliases[i];
								break;
							}
						cert = (X509Certificate)ks.getCertificate(ALIAS);
						privatekey = (PrivateKey)ks.getKey(ALIAS, password);
						publickey = ks.getCertificate(ALIAS).getPublicKey();
						
						// Load file to be signed in an array of bytes 

						File file_to_sign = new File(fileField.getText());
						byte[] buffer = new byte[(int)file_to_sign.length()];
						DataInputStream in = new DataInputStream(new FileInputStream(file_to_sign));
						in.readFully(buffer);
						in.close();
						
						// Load certificate to be stored in pk7 file

						ArrayList certList = new ArrayList();
						certList.add(cert);
						CertStore certs = CertStore.getInstance("Collection",
											new CollectionCertStoreParameters(certList), "BC");

						CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();

						// private key is the key that was extracted from p12 file previously

						signGen.addSigner(privatekey, cert, CMSSignedDataGenerator.DIGEST_SHA1);
						signGen.addCertificatesAndCRLs(certs);
						CMSProcessable content = new CMSProcessableByteArray(buffer);

						// Creation of CMS/PKCS7 file 
						// We chose the second argument as true so that the content of file to be signed is attached with the signature
						
						CMSSignedData signedData = signGen.generate(content, true, "BC");
						byte[] signeddata = signedData.getEncoded();

						// Writing the buffer in a .pk7 file

						FileOutputStream envfos = new FileOutputStream(fileField.getText() + ".pk7");
						envfos.write(signeddata);
						envfos.close();
						
						
					} catch (Exception ex) {
						ex.printStackTrace();
						return ;
					}

					} catch (Exception ex) {
						ex.printStackTrace();
						return ;
					} 
				
			}
		});
		btnSignFile.setBounds(151, 173, 117, 29);
		contentPane.add(btnSignFile);
		
		JButton btnReturnToMain = new JButton("Return to Main Menu");
		btnReturnToMain.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Main main = new Main();
				main.setVisible(true);
			}
		});
		btnReturnToMain.setBounds(122, 229, 198, 29);
		contentPane.add(btnReturnToMain);
		
			}
	
}
