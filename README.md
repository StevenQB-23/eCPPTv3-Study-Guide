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

```
### ~ PowerShell for Pentesting

```bash

```

## 02 - Client-Side Attacks
## 03 - Web Application Penetration Testing
## 04 - Network Penetration Testing
## 05 - System Security & x86 Assembly Fundamentals
## 06 - Exploit Development: Buffer Overflows
## 07 - Privilege Escalation
## 08 - Lateral Movement & Pivoting
## 09 - Active Directory Penetration Testing
## 10 - Command & Control (C2/C&C)
