# Certificate-Management-Service

## USAGE
1. Set up an ec2 (Amazon Linux 2) instance with cloud HSM service running on it.
2. Clone this repository and move into a directory.
3. Modify the source and destination file path in [performSignOps](src/main/java/com/hackweek/certificatemanagementservice/signing/SignOperation.java). Sample files present in [files](/files) folder.
4. Build the jars : 
    ```
    mvn clean install
    ```
5. Run the spring boot application
    ```
    java -jar target/certificate-management-service-0.0.1-SNAPSHOT.jar
    ```
6. Hit the sign API.
    ```
    curl --location --request GET http://localhost:8080/sign
    ```
   
## Response
[Output signed document](/files/signedDocument.pdf) generated can be found in [files](/files).
