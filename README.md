This is a prototype of a simple ACME protocol server. The aims is to be able to reproduce the let's encrypt feature inside your organization for private server or private internal infrastructure.

# Features
* Test with lego client to generate an end user certificate

# Parameters
* "hostname": Hostname of server
* "port": Port of server
* "ca-key": Path to the pem file containing CA key
* "ca-crt": Path to the pem file containing CA crt
* "renew": Force renew of CA key and crt
* "ca-key-size": CA rsa key size
* "ca-year": Number of year CA crt is valid
* "ca-country": Country code of CA subject
* "ca-common-name": Common name of CA subject


# Roadmap
* <del>Parameters for CA configuration, CA keys (for using an specific instead of generating one), server domain name, listen port, etc ...</del>
* Correctly validate JWS message 
* <del>Self signed server https certificate so client just have to trust the ca certificate</del>
* <del>Add a landing html page with help and link to CA certificate (help user to add CA as trust in their browser)</del>
* <del>Persistence of clients and generated certificate</del>
* Support of renewing certificate
* Unit testing
* Support of others challenges
* Add a CRL url and CRL gen

# Test
Currently it is tested against lego client. 

>./lego -d <commonname> -s https://localhost:81/directory -m 'user@example.org' -a=true --path . run
