** This is just an experiment with SPNEGO. Nothing stable yet! **


This requires version 1.1-SNAPSHOT of Restlet as of early August 2008, or
1.1-M5.


'src/main/resources' contains 'config.sample.xml' which should be copied to
'config.xml' and configured appropriately.

This has been tested in conjunction with an MIT Kerberos 5 KDC running on
Linux. There needs to be a principal of the form "HTTP/www.example.org@REALM"
where: 
- www.example.org is the host name of the web server,
- REALM is the name of the Kerberos realm.