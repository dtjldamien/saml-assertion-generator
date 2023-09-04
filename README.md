# SAMLAssertionGen User Guide

Prerequisite：

This project is a maven project. We need to install maven in local firstly to compile and package this project. For maven install guide, you can refer to https://maven.apache.org/install.html.


Steps:

1. Download this project, it includes three parts: src folder, pom.xml and SAMLAssertion.properties

2. Go to project diretory, modify SAMLAssertion.properties</br>
    * tokenUrl should be the URL you want to get token against</br>
    * clientId should be the client Id registered in BizX application</br>
    * userId/userName should be the userId/userName you want to assert for</br> 
      Note:userName will only be considered when userId is null/empty.
    * privateKey should be the private Key which matches the public key configured in BizX application</br>
    * expireInMinutes should be the minutes you want to make the signed saml assertion valid for to get the token;
   
   
3.  There are two ways to generate SAML Assertion:

    Option 1:  Run below command against your project directory directly:

        mvn compile exec:java -Dexec.args="SAMLAssertion.properties"

    Option 2: 
    
      #1: Run below command against your project directory to compile and package this project:

        mvn clean compile package
  
      After execution complete, you should see a "target" directory generated. Under "target" directory, you should see "SAMLAssertionGen-1.0.0.jar" in it.


     #2: Then copy SAMLAssertionGen-1.0.0.jar and modified SAMLAssertion.properties into same directory.
     
     #3: Execute below command to generate SAML Assertion:
    
        java -jar SAMLAssertionGen-1.0.0.jar "SAMLAssertion.properties"

4. Using any option in step 3 Then you can get the SAML Assertion in command line following below message: "The generated Signed SAML Assertion is: ****".
