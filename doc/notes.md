# Other Chibi CM tasks.

Create a self signed certificate.
```
chibicu self --out myself.pem [OPTIONS]
```

Where options can be used to select:
* key size
* algorithm
* CN and other cerificate fields.

Create an intermediate certificate.
```
chibicu csr --out mycsr.pem --ca [OPTONS]
chibica sign --in mycsr.pem --out myintermedate.pem
```

Sign with an intermediate certificate.
```
chibica sign --in mycsr.pem --ca myintermedate.pem --out mycert.pem
```

Shortcut to create single client certificate with chibica (after ca has been created).
```
chibica client --out mycert.pem [OPTONS]
```

# Files

The root directory for files under linux is $HOME/.local/etc/chibicm with subdirectories ca and cu.

Under Windows files are stored in %HOMEPATH%\AppData\Local\chibicm.

We use $CA to refer to chibica file root and $CU to refer to the chibicu file root.

chibica private keys are stored in $CA/<ca-name>-key.pem Where ca-name is the DN of the certificate.

chibica generated CA certificates are stored in $CA/<ca-name>-crt.pem.

chibica generated userA certificates are stored in the file name specified by the --out option.

chibicu private keys are stored in $CU/<crt-name>-key.pem. Where crt-name in the DN of the certificate.

Theefore in order to use chibica to sign user certs with an intemediate crt the intermediate
data must me imported into the $CA directory.
```
chibica import --in myintermediate.pem
```

The import operation with use the DN of the certifiace to find the private key in the $CA
directory and copy it to the correct location in the $CU directory.

chibica and chibicu keep configuration files in $CA and $CU.

# Trusted root certificate.

By default the CA root is in $CA/root-crt.pem, adding the root cert to the locally trusted cert list:
```
chibica pub
```

To publish it to a specified directory:
```
chibica pub --to path/to/directory
```

To publish an intermediate certificate:
```
chibica pub --ca <ca-name>
```

Published certificates include the full certificate chain.

# Command Summary

* chibica
  * client --out OUT [--name CN] [--organization O] [--unit OU] [--country C] [--state ST] [--location L] [--email EM] [--bits N] [--start TM] [--days DY]
  * exists --name NM
  * import --in IN
  * list
  * new [--name CN] [--organization O] [--unit OU] [--country C] [--state ST] [--location L] [--email EM] [--bits N] [--start TM] [--days DY]
  * pub [--dir DIR]
  * sign --in IN --out OUT [--ca CA]
  
* chibicu
  * csr --out OUT [--name CN] [--organization O] [--unit OU] [--country C] [--state ST] [--location L] [--email EM] [--bits N] [--ca]
  * list
  * self --out OUT [--name CN] [--organization O] [--unit OU] [--country C] [--state ST] [--location L] [--email EM] [--bits N] [--start TM] [--days DY]
  
  
