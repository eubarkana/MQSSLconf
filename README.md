

# IBMMQSSL
SSL configuration of IBM MQ

## Table of contents

- [IBMMQSSL](#ibmmqssl)
  - [Table of contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Introduction](#introduction)
  - [New MQ Channel Creation](#new-mq-channel-creation)
  	- [Message security setting](#message-security-setting)
  - [MQ server self signed certificate](#mq-server-self-signed-certificate)
  - [Queue Manager SSL settings](#queue-manager-ssl-settings)
  - [Label check for Queue Manager and Channel](#label-check-for-queue-manager-and-channel)
  - [MQ client self signed certificate](#mq-client-self-signed-certificate)
  - [Client side Configurations](#client-side-configurations)
  - [Java MQ client Example](#java-mq-client-example)

## Prerequisites

In order to execute the scenario in this document, you need to have
* IBM MQ v9.2 or higher installed and configured with queue managers/queues
* IBM MQ explorer v9.2 or higher (Eclipse MQ explorer v9.2 plugin is used in this document)
* Open ssl to be installed

## Introduction

This tutorial will get you started with securing messages in transit through the use of Transport Layer Security (TLS) for IBM MQ.

TLS is a cryptographic encryption protocol that protects data in transit. See the figure below for an explanation of how the TLS handshake between a client and a server works:

<img width="708" alt="Screenshot 2023-09-05 at 9 18 12 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/7ce896f7-1a17-4e0d-a8b8-4b1c266e8170">

1. The server and client communicate to establish connection seEngs.
2. The client verifies the server certificate.
3. The client generates a cipher and encrypts it using the server’s public key. This is shared with the server and used to generate a symmetric key to encrypt the remainder of the session.

TLS authentication methods include anonymous and mutual authentication.

In this document, we will set up the simplest configuration, in which we provide a certificate to the server and client side. In which case, mutual authentication is used in this document as shown in the figure below:

<img width="721" alt="Screenshot 2023-09-05 at 9 26 59 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/17d4546f-0199-41a8-84d8-aab75914b428">

1. Anonymous authentication: The server provides a certificate to the client.
2. Mutual authentication: Both the server and the client provide a certificate and authenticate each other.

We will need to specify the same CipherSpec on the client side for the client and server to be able to connect and carry out the TLS handshake.

Client side will have its own keystore with self CA signed certificate and server side will have self CA signed certificate in keystore where client certificate is set to be trusted on server side.

Check the URL for more information:
(https://developer.ibm.com/tutorials/mq-secure-msgs-tls/)


## New MQ Channel Creation

This document shows how to define the channel through MQ explorer(GUI based). You can also define the channel with runmqsc commands.

1. Connect to MQ QMGR through MQ explorer

<img width="523" alt="Screenshot 2023-09-05 at 9 40 16 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/3ca9bc11-3008-4075-89ed-179db0ddfebe">

2. In the Navigator view, expand the Queue Managers folder, then click the Channels folder.

<img width="1562" alt="Screenshot 2023-09-05 at 9 43 17 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/a3997cc9-d977-4aa9-a7f5-0e0edddf1162">

3. Right click the channel folder and create a new server connection channel 

<img width="683" alt="Screenshot 2023-09-05 at 9 45 49 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/8ad88f25-c22d-4a88-89b0-ecf40a05b7fb">

4. Name the channel

<img width="711" alt="Screenshot 2023-09-05 at 9 47 58 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/aed5a216-a876-4f7d-9877-bc25dd5417fb">

5. Write a description (OPTIONAL)

<img width="708" alt="Screenshot 2023-09-05 at 9 49 38 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/8881ede5-a185-4779-af16-a4f19a6fd226">

6. Change the properties on the SSL tab, select the chipper you wan to use:

<img width="710" alt="Screenshot 2023-09-05 at 9 50 57 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/2e18b118-0ee8-4f09-9fe9-767484366827">


### Message security setting
TLS-enabled messaging offers two methods of ensuring message security:

* Encryption ensures that if the message is intercepted, it is unreadable.
* Hash functions ensure that if the message is altered, this is detected.

The combination of these methods is called the cipher specification or CipherSpec. The same CipherSpec must be set for both ends of a channel, otherwise TLS-enabled messaging fails.


## MQ server self signed certificate

If you cannot use strmqikm(ikeyman) for display, use the command line to create certificate.

The key database password is set to be passw0rd for this document.

1- Create a key database
```
runmqakm -keydb -create -db /var/mqm/SSL_kdb/sslnew.kdb -pw passw0rd -type cms -expire 3650 -stash
```

2- If possible retrieve the certificate that is created by the customer.
	For test purposes, self signed certificate will be generated. Use the command below to create the self signed certificate within the key DB:
```
runmqakm -certreq -create -db /var/mqm/SSL_kdb/sslnew.kdb -pw passw0rd -label ibmwebspheremqcaudaqm -dn "CN=ablates1.ibm.com,O=IBM,S=TN,C=US" -size 2048 -file sslnew.csr -sig_alg sha256
```

3- To verif the certificates, run the command below:
```
runmqckm -certreq -details -label ibmwebspheremqcaudaqm -db /var/mqm/SSL_kdb/sslnew.kdb -pw passw0rd
```

4- Sign the certificate with CA with the commands below:
```
# Sign the certificate with CA
openssl ca -in /var/mqm/SSL_kdb/sslnew.csr

# Create private CA and certificate
openssl req -new -newkey rsa:2048 -nodes -out CA_CSR.csr -keyout CA_private_key.key -sha256

# Create a certificate for your private CA. This step creates a certificate(.arm) that you can use to sign your CSR
openssl x509 -signkey CA_private_key.key -days 120 -req -in CA_CSR.csr -out CA_certificate.arm -sha256

# Use the CA certificate to sign the certificate signing request that you created
openssl x509 -req -days 3650 -in sslnew.csr -CA CA_certificate.arm -CAkey CA_private_key.key -out sslnewcertificate.arm -set_serial 01 -sha256
```

Final certificate will be `sslnewcertificate.arm`

5- Add the signed certificate to key database:
```
runmqckm -cert -add -db /var/mqm/SSL_kdb/sslnew.kdb -pw passw0rd -label ibmwebspheremqcaudaqm -file sslnewcertificate.arm -format ascii
```

6- Also need to add the CA root certificate to signer in key database:
	In this scenario, `CA_certificate.arm` has to be added to `/var/mqm/SSL_kdb/sslnew.kdb`

7- Validate the certificates
```
runmqakm -cert -list -db /var/mqm/SSL_kdb/sslnew.kdb -stashed
```

<img width="704" alt="Screenshot 2023-09-05 at 11 03 28 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/fcc9106a-c31a-44bb-a749-c1e4d4d7c71f">

`caudaqmcli` is the label for client personal certificate which will be described later on.

`ibmwebspheremqcaudaqm` is the server side certificate.

`root` is the label for CA signer certificate.

8- Copy `/var/mqm/SSL_kdb/ssl*` to `/var/mqm/qmgrs/CAUDAQM/ssl/`

<img width="387" alt="Screenshot 2023-09-05 at 11 06 47 AM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/648184cb-9b1a-4e05-8303-1833602bf29c">


## Queue Manager SSL settings

This documents covers the settings to be done from MQ explorer. You can also use the commands to fullfill the same settings.

1- From the MQ explorer, right click on the QMGR and navigate to “Properties”

<img width="595" alt="Screenshot 2023-09-05 at 1 09 14 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/4ab2b08b-86c4-4eac-a9c4-2b9ea6253af5">

2- From the SSL tab,change the SSL Key repository location to be the new created key db.

<img width="708" alt="Screenshot 2023-09-05 at 1 11 00 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/da1b44b6-8553-4935-9bdc-d6aaf48841a4">

3- Click “_**Apply**_” and watch for the warning:

<img width="711" alt="Screenshot 2023-09-05 at 1 12 03 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/8c59b35a-be6e-4d5e-bd9c-760a4dcb68c7">

4- Click “_**Yes**_” and “_**Ok**_”.


## Label check for Queue Manager and Channel

1- Connect to MQ machine and display the channel info in MQSC command:

<img width="1335" alt="Screenshot 2023-09-05 at 1 16 03 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/25e6744c-e005-43e0-ae30-b3ebc2460a1d">

Verify `CERTLABL`. If blank as seen in the above screen, same label from QMGR has to be set.

2- Display the queue manager details from MQSC:

<img width="565" alt="Screenshot 2023-09-05 at 1 18 32 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/8a7feab9-058d-444b-8ff9-b95da42ae9c5">

Verify the `CERTLABL` and also verify the `SSLKEYR` location.

<img width="707" alt="Screenshot 2023-09-05 at 1 20 00 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/aa1eba61-63a8-4e91-a8ac-ffd874f960ce">

3- From MQ explorer or from command line, change the certificate label for the new channel as with the same name for queue manager:

<img width="710" alt="Screenshot 2023-09-05 at 1 21 42 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/7a21e2be-c036-40ab-9765-5dd71074d7e9">

`SSL Authentication` is set to be `REQUIRED` and should stay that was for SSL communication. If you want to use anonymous clients to connect to QMGR then `SSL Authentication` must be set to `OPTIONAL`.

## MQ client self signed certificate

1- Create the key database for client
```
runmqakm -keydb -create -db /var/mqm/SSL_kdb/sslCli.kdb -pw passw0rd -type cms -expire 3650 -stash
```

2- Add the CA root certificate to client key database as personal
```
runmqckm -cert -add -db /var/mqm/SSL_kdb/sslCli.kdb -pw passw0rd -label root -file /var/mqm/SSL_kdb/CA_certificate.arm -format ascii
```

3- Request client side personal certificate
```
runmqakm -certreq -create -db /var/mqm/SSL_kdb/sslCli.kdb -pw passw0rd -label caudaqmcli -dn "CN=ibm.com,O=IBM,S=TN,C=US" -size 2048 -file sslCli.csr -sig_alg sha256
```

4- Use CA root certificate to sign the created client certificate:
```
openssl x509 -req -days 3650 -in sslCli.csr -CA CA_certificate.arm -CAkey CA_private_key.key -out sslClicertificate.arm -set_serial 01 -sha256
```

5- Add certificate to key database:
```
runmqckm -cert -add -db /var/mqm/SSL_kdb/sslCli.kdb -pw passw0rd -label caudaqmcli -file sslClicertificate.arm -format ascii
```

6- List the certificates
```
runmqakm -cert -list -db /var/mqm/SSL_kdb/sslCli.kdb -stashed
```

<img width="708" alt="Screenshot 2023-09-05 at 1 31 53 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/5af4be00-214d-4714-84e4-186413e5a51b">

Client side perfonal certificate is labeled as `caudaqmcli`. This labeled certificate must be trusted by the server side as it was mentioned earlier.

CA root certificate has the label as `root`.

## Client side Configurations

MQ Java test code is written on Eclipse IDE. Code includes all connection information to new SSL channel created earlier:

<img width="712" alt="Screenshot 2023-09-05 at 1 38 40 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/a75ad93e-04a6-41db-9fba-ede96a33f731">

Also the JMSConnectionFactory has the following properties set including the chipper spec that was set earlier for the channel.

<img width="709" alt="Screenshot 2023-09-05 at 1 39 43 PM" src="https://github.com/eubarkana/MQSSLconf/assets/52744532/8ccd8061-0911-4229-929b-cd0390db9b73">

Since the chipper spec is set within the code, depending on which Java you use(Using Oracle 1.8 for this scenario), you may need to set the
*		`-Dcom.ibm.mq.cfg.useIBMCipherMappings=false`
Jvm argument to run the code. This parameter tells that not to use the chipper mapping for IBM but continue on Oracle mapping.

The JVM parameters used for the Java test code are as follows:
*	`-Djavax.net.ssl.keyStore=/Users/eubarkana/Documents/Customers/Halkbank/MQSSL/sslCli.p12`
*	`-Djavax.net.ssl.keyStorePassword=passw0rd`
*	`-Dcom.ibm.mq.cfg.preferTLS=true`
*	`-Dcom.ibm.mq.cfg.useIBMCipherMappings=false`
Keystore format is changed to be p12 instead kdb created earlier.

## Java MQ client Example

Below is the MQ client code written with Java. Host is deleted so you can configure your own for testing.

```
package com.test.put;

import java.io.Console;
import javax.jms.Destination;
import javax.jms.JMSConsumer;
import javax.jms.JMSContext;
import javax.jms.JMSException;
import javax.jms.JMSProducer;
import javax.jms.TextMessage;

import com.ibm.msg.client.jms.JmsConnectionFactory;
import com.ibm.msg.client.jms.JmsFactoryFactory;
import com.ibm.msg.client.wmq.WMQConstants;

/**
 * A minimal and simple application for Point-to-point messaging.
 *
 * Application makes use of fixed literals, any customisations will require
 * re-compilation of this source file. Application assumes that the named queue
 * is empty prior to a run.
 *
 * Notes:
 *
 * API type: JMS API (v2.0, simplified domain)
 *
 * Messaging domain: Point-to-point
 *
 * Provider type: IBM MQ
 *
 * Connection mode: Client connection
 *
 * JNDI in use: No
 *
 */
public class JmsPutGet {
    // System exit status value (assume unset value to be 1)
	  private static int status = 1;

    // Create variables for the connection to MQ
  	private static final String HOST = "xxx.xxx.xxx.xxx"; // Host name or IP address
  	private static final int PORT = 1414; // Listener port for your queue manager
  	private static final String CHANNEL = "SSL.TO.CAUDAQM"; // Channel name
  	private static final String QMGR = "CAUDAQM"; // Queue manager name
  	private static final String APP_USER = "mqm"; // User name that application uses to connect to MQ
  	private static final String APP_PASSWORD = "passw0rd"; // Password that the application uses to connect to MQ
  	private static final String QUEUE_NAME = "TESTQ"; // Queue that the application uses to put and get messages to and from

    public static void main(String[] args) {
    		// Sanity check main() arguments and warn user
    		if (args.length > 0) {
                    	System.out.println("\n!!!! WARNING: You have provided arguments to the Java main() function. JVM arguments (such as -Djavax.net.ssl.trustStore) must be passed before the main class or .jar you wish to run.\n\n");
                    	Console c = System.console();
                    	System.out.println("Press the Enter key to continue");
                    	c.readLine();
                    }
    
    		// Variables
    		JMSContext context = null;
    		Destination destination = null;
    		JMSProducer producer = null;
    		//JMSConsumer consumer = null;
    
    
    
    		try {
    			// Create a connection factory
    			JmsFactoryFactory ff = JmsFactoryFactory.getInstance(WMQConstants.WMQ_PROVIDER);
    			JmsConnectionFactory cf = ff.createConnectionFactory();
    
    			// Set the properties
    			cf.setStringProperty(WMQConstants.WMQ_HOST_NAME, HOST);
    			cf.setIntProperty(WMQConstants.WMQ_PORT, PORT);
    			cf.setStringProperty(WMQConstants.WMQ_CHANNEL, CHANNEL);
    			cf.setIntProperty(WMQConstants.WMQ_CONNECTION_MODE, WMQConstants.WMQ_CM_CLIENT);
    			cf.setStringProperty(WMQConstants.WMQ_QUEUE_MANAGER, QMGR);
    			cf.setStringProperty(WMQConstants.WMQ_APPLICATIONNAME, "JmsPutGet (JMS)");
    			cf.setBooleanProperty(WMQConstants.USER_AUTHENTICATION_MQCSP, true);
    			cf.setStringProperty(WMQConstants.USERID, APP_USER);
    			cf.setStringProperty(WMQConstants.PASSWORD, APP_PASSWORD);
    			cf.setStringProperty(WMQConstants.WMQ_SSL_CIPHER_SPEC, "TLS_RSA_WITH_AES_256_CBC_SHA256");
    			
    			//cf.setStringProperty(WMQConstants.WMQ_SSL_CIPHER_SUITE, "TLS_RSA_WITH_AES_256_CBC_SHA256");
    
    			// Create JMS objects
    			context = cf.createContext();
    			destination = context.createQueue("queue:///" + QUEUE_NAME);
    
    			long uniqueNumber = System.currentTimeMillis() % 1000;
    			TextMessage message = context.createTextMessage("Your lucky number today is " + uniqueNumber);
    
    			producer = context.createProducer();
    			producer.send(destination, message);
    			System.out.println("Sent message:\n" + message);

            context.close();

    			recordSuccess();
    		} catch (JMSException jmsex) {
    			recordFailure(jmsex);
    		}
    
    		System.exit(status);
    
    	} // end main()


       /**
    	 * Record this run as successful.
    	 */
    	private static void recordSuccess() {
    		System.out.println("SUCCESS");
    		status = 0;
    		return;
    	}
    
    	/**
    	 * Record this run as failure.
    	 *
    	 * @param ex
    	 */
    	private static void recordFailure(Exception ex) {
    		if (ex != null) {
    			if (ex instanceof JMSException) {
    				processJMSException((JMSException) ex);
    			} else {
    				System.out.println(ex);
    			}
    		}
    		System.out.println("FAILURE");
    		status = -1;
    		return;
    	}
  
      /**
    	 * Process a JMSException and any associated inner exceptions.
    	 *
    	 * @param jmsex
    	 */
    	private static void processJMSException(JMSException jmsex) {
    		System.out.println(jmsex);
    		Throwable innerException = jmsex.getLinkedException();
    		if (innerException != null) {
    			System.out.println("Inner exception(s):");
    		}
    		while (innerException != null) {
    			System.out.println(innerException);
    			innerException = innerException.getCause();
    		}
    		return;
    	}
}

```
