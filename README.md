This is a prototype of a simple ACME protocol server. The aims is to be able to reproduce the let's encrypt feature inside your organization for private server or private internal infrastructure.

#Features
*Test with lego client to generate an end user certificate

#Roadmap
*Correctly validate JWS message 
*Self signed server https certificate so client just have to trust the ca certificate
*Add a landing html page with help and link to CA certificate (help user to add CA as trust in their browser)
*Persistence of clients and generated certificate
*Support of renewing certificate
*Parameters for CA configuration, CA keys (for using an specific instead of generating one), server domain name, listen port, etc ...
*Unit testing
*Support of others challenges

#Test
Currently it is tested against lego client. 

>./lego -d <commonname> -s https://localhost:81/directory -m 'user@example.org' -a=true --path . run
