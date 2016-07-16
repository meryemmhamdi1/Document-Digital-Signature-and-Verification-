package cryptoproject2;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.List;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;

import java.util.*;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.omg.CORBA.portable.InputStream;



import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import javax.swing.JPasswordField;
import java.awt.Color;



public class FileVerifier extends JFrame {

	private JPanel contentPane;
	private JTextField pkcs7File;
	private JTextField p12File;
	private JPasswordField passphrase;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					FileVerifier frame = new FileVerifier();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public FileVerifier() throws Exception {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 484, 335);
		setTitle("PKCS7 File Signature Verification");
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JLabel lblNewLabel = new JLabel("PKCS7 File");
		lblNewLabel.setBounds(24, 44, 84, 16);
		contentPane.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel(".p12 Certificate File");
		lblNewLabel_1.setBounds(17, 113, 129, 16);
		contentPane.add(lblNewLabel_1);
		
		pkcs7File = new JTextField();
		pkcs7File.setColumns(10);
		pkcs7File.setBounds(142, 38, 154, 28);
		contentPane.add(pkcs7File);
		
		p12File = new JTextField();
		p12File.setColumns(10);
		p12File.setBounds(142, 107, 154, 28);
		contentPane.add(p12File);
		final JLabel result = new JLabel("New label");
		
		result.setBounds(60, 196, 403, 40);
		result.setVisible(false);
		contentPane.add(result);
		
		JButton browsePkcs7File = new JButton("Browse");
		browsePkcs7File.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fc = new JFileChooser();
	            fc.showOpenDialog(contentPane);

	            try {
	                // Open an input stream
	                File file = fc.getSelectedFile();
	                pkcs7File.setText(file.toString());
	                
	            }
	            catch (Exception e1){
	            	System.out.println(e1);
	            }
			}
		});
		browsePkcs7File.setBounds(327, 39, 117, 29);
		contentPane.add(browsePkcs7File);
		
		JButton btnVerifySignatureOf = new JButton("Verify Signature of File");
		btnVerifySignatureOf.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					
					/*Get certificate and public key from p12 file*/
					// Get contents of p12 file
					KeyStore ks = null;
					char[] password = null;

					Security.addProvider(new BouncyCastleProvider());
					try {
						ks = KeyStore.getInstance("PKCS12");
						// password of name-cert.p12
						password = (passphrase.getText()).toCharArray();
						ks.load(new FileInputStream(p12File.getText()), password);
					} catch (Exception ex) {
						System.out.println("Error: file " +
					                       "name-cert.p12" +
					                       " is not in pkcs#12 format or passphrase is incorrect");
						return ;
					}

					// get certificate and public key from the name-cert.p12

					X509Certificate cert = null;
					PublicKey publickey = null;

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
						publickey = ks.getCertificate(ALIAS).getPublicKey();
					} catch (Exception ex) {
						ex.printStackTrace();
						return ;
					}
					
					//Security.addProvider(new FlexiCoreProvider());
					// Get contents of PKCS7 signed file into an array of bytes
					File f = new File(pkcs7File.getText());
					byte[] sigmessage = new byte[(int)f.length()];
					DataInputStream in = new DataInputStream(new FileInputStream(f));
					in.readFully(sigmessage);
					in.close();
			
					Security.addProvider(new BouncyCastleProvider());
					CMSSignedData signature = new CMSSignedData(sigmessage);
					CMSProcessable sc = signature.getSignedContent();
					byte[] data = (byte[]) sc.getContent();
					

					SignerInformation signer = (SignerInformation)signature
			                .getSignerInfos().getSigners().iterator().next();
					
					boolean isvalid=signer.verify(cert, "BC");
					result.setText("The signature of the file verifies: "+isvalid);
					result.setVisible(true);
					if(isvalid==true){
						result.setForeground(Color.BLUE);
					}
					else {
						result.setForeground(Color.RED);
					}
					FileOutputStream envfos = new FileOutputStream("document_non_signer.txt");
					envfos.write(data);
					envfos.close();
					
				} catch (Exception ex) {
					ex.printStackTrace();
					return ;
				}
			}
			
		});
		btnVerifySignatureOf.setBounds(142, 247, 168, 29);
		contentPane.add(btnVerifySignatureOf);
		
		JButton browseP12File = new JButton("Browse");
		browseP12File.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fc = new JFileChooser();
	            fc.showOpenDialog(contentPane);

	            try {
	                // Open an input stream
	                File file = fc.getSelectedFile();
	                p12File.setText(file.toString());
	                
	            }
	            catch (Exception e1){
	            	System.out.println(e1);
	            }
			}
		});
		browseP12File.setBounds(327, 108, 117, 29);
		contentPane.add(browseP12File);
		
		JButton btnReturnToMain = new JButton("Return To Main Menu");
		btnReturnToMain.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Main main = new Main();
				main.setVisible(true);
			}
		});
		btnReturnToMain.setBounds(142, 278, 168, 29);
		contentPane.add(btnReturnToMain);
		
		JLabel labelpass = new JLabel("Password");
		labelpass.setBounds(24, 165, 70, 16);
		contentPane.add(labelpass);
		
		passphrase = new JPasswordField();
		passphrase.setBounds(142, 159, 154, 28);
		contentPane.add(passphrase);
		
		
		
	}
static void dumpChain(Certificate[] chain)
{
  for (int i = 0; i < chain.length; i++) {
     Certificate cert = chain[i];
     if (cert instanceof X509Certificate) {
        X509Certificate x509 = (X509Certificate)chain[i];
        System.err.println("subject: " + x509.getSubjectDN());
        System.err.println("issuer: " + x509.getIssuerDN());
     }
  }
}

static char[] readPassphrase() throws IOException
{
  InputStreamReader in = new InputStreamReader(System.in);

  char[] cbuf = new char[256];
  int i = 0;

readchars:
  while (i < cbuf.length) {
     char c = (char)in.read();
     switch (c) {
        case '\r':
           break readchars;
        case '\n':
           break readchars;
        default:
           cbuf[i++] = c;
     }
  }

  char[] phrase = new char[i];
  System.arraycopy(cbuf, 0, phrase, 0, i);
  return phrase;
}
}
