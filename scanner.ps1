# =======================================
# CONFIGURACIÓN MYSQL (XAMPP)
# =======================================
$mysqlExe  = "C:\xampp\mysql\bin\mysql.exe"
$mysqlHost = "localhost"
$mysqlPort = "3306"
$mysqlUser = "root"
$mysqlPass = ""
$mysqlDB   = "reporte_red2"

function Exec-SQL($query) {
    if ($mysqlPass -eq "") {
        & $mysqlExe -h $mysqlHost -P $mysqlPort -u $mysqlUser -D $mysqlDB -e $query
    } else {
        & $mysqlExe -h $mysqlHost -P $mysqlPort -u $mysqlUser -p$mysqlPass -D $mysqlDB -e $query
    }
}

# =======================================
# FUNCION DETECCIÓN DE SISTEMA OPERATIVO REMOTO
# =======================================
function Detectar-SO {
    param($ip)

    $puertosWin = @(135,139,445,3389)
    $puertosLinux = @(22,111)
    $puertosRouter = @(23,53,80,443,1900)

    $abiertos = @()

    foreach ($p in $puertosWin + $puertosLinux + $puertosRouter) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        if ($tcp.ConnectAsync($ip, $p).Wait(150)) { $abiertos += $p }
        $tcp.Dispose()
    }

    if ($abiertos -contains 445 -or $abiertos -contains 135) { return "Windows" }
    if ($abiertos -contains 22) { return "Linux" }
    if ($abiertos -contains 23 -or $abiertos -contains 1900) { return "Router / IoT" }

    return "Desconocido"
}

# =======================================
# SUBNET MANUAL
# =======================================
Write-Host "Ingresa la subred a escanear:"
$inputSubnet = Read-Host "Subnet"

if ($inputSubnet -match "^\d{1,3}\.\d{1,3}\.\d{1,3}$") {
    $segmento = $inputSubnet
} elseif ($inputSubnet -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/24$") {
    $segmento = ($inputSubnet -replace "\.0\/24","")
} else {
    Write-Host "❌ Formato de subnet inválido."
    exit
}

Write-Host "✔ Subred seleccionada: $segmento.0/24"
Write-Host "======================="

# =======================================
# INFORMACIÓN DEL EQUIPO LOCAL
# =======================================
$hostname = $env:COMPUTERNAME
$so = (Get-CimInstance Win32_OperatingSystem).Caption

$ipInfo = Get-NetIPAddress |
    Where-Object {
        $_.AddressFamily -eq "IPv4" -and
        $_.IPAddress -notmatch "^169\.254\." -and
        $_.IPAddress -ne "127.0.0.1" -and
        $_.InterfaceAlias -notmatch "VMware|Virtual|Hyper-V"
    } | Select-Object -First 1

$ipLocal = if ($ipInfo) { $ipInfo.IPAddress } else { "0.0.0.0" }

$mac = (Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).MacAddress
$mac = $mac -replace "-", ":"

$fechaScan = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# =======================================
# INSERT / UPDATE EQUIPO LOCAL
# =======================================
$queryEquipo = @"
INSERT INTO Gerardo_equipos (sistema_operativo, ip, mac, nombre_host, fecha_escaneo, fabricante_id)
SELECT '$so', '$ipLocal', '$mac', '$hostname', '$fechaScan', f.id
FROM Gerardo_fabricantes_mac f
WHERE '$mac' LIKE CONCAT(f.oui, '%')
UNION
SELECT '$so', '$ipLocal', '$mac', '$hostname', '$fechaScan', NULL
LIMIT 1

    sistema_operativo = VALUES(sistema_operativo),
    fecha_escaneo = VALUES(fecha_escaneo),
    fabricante_id = VALUES(fabricante_id);
"@

Exec-SQL $queryEquipo


# Obtener ID del equipo local
$equipoID = (Exec-SQL "SELECT id FROM Gerardo_equipos WHERE mac='$mac' ORDER BY id DESC LIMIT 1;" | Select-Object -Last 1).Trim()

Write-Host "🆔 ID del equipo local: $equipoID"

Write-Host "======================="


# =======================================
# ESCANEO DE PUERTOS DEL EQUIPO LOCAL

# =======================================
$puertos = @(20,21,22,23,25,53,80,110,135,139,143,161,162,389,636,137,138,514,443,445,3306,3389,8080,5900)


foreach ($puerto in $puertos) {

    $tcp = New-Object System.Net.Sockets.TcpClient

    try {
        $resultado = $tcp.ConnectAsync($ipLocal, $puerto).Wait(300)

        if ($resultado) {

            $fechaPuerto = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $queryPuerto = @"
INSERT INTO Gerardo_equipo_protocolo (equipo_id, protocolo_id, puerto, fecha_uso)

SELECT $equipoID, p.id, $puerto, '$fechaPuerto'

FROM Gerardo_protocolos p
WHERE p.numero = $puerto
LIMIT 1;
            Write-Host "🔘 Puerto $puerto cerrado"
        }
    } catch {
        Write-Host "🔘 Puerto $puerto cerrado"
    } finally { $tcp.Dispose() }
}
"@

# =======================================
# ESCANEO COMPLETO DE LA SUBNET
            Exec-SQL $queryPuerto
# =======================================
for ($i = 1; $i -le 100; $i++) {
    $ipActual = "$segmento.$i"
    Write-Host "🔎 Probando $ipActual ..." -NoNewline

            Write-Host "🟢 Puerto $puerto abierto"
    if (Test-Connection -Quiet -Count 1 -TimeoutSeconds 1 $ipActual) {
        Write-Host " ✔ Activo"

        try { $hostRemoto = (Resolve-DnsName $ipActual -ErrorAction Stop).NameHost } catch { $hostRemoto = "Desconocido" }

        $arp = arp -a $ipActual | Select-String $ipActual
        if ($arp) { 
            $macRemota = ($arp.ToString().Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries))[1] 
        } else {
            $macRemota = $macRemota -replace "-", ":"
        } else { 
            $macRemota = "00:00:00:00:00:00"
        }

        $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # =======================================
        # DETECTAR SISTEMA OPERATIVO REMOTO
        # =======================================
        $soRemoto = Detectar-SO $ipActual

        # =======================================
        # INSERT / UPDATE TODOS LOS EQUIPOS ACTIVOS
        # =======================================
        $query = @"
INSERT INTO Gerardo_equipos (sistema_operativo, ip, mac, nombre_host, fecha_escaneo, fabricante_id)
SELECT '$soRemoto', '$ipActual', '$macRemota', '$hostRemoto', '$fecha', f.id
FROM Gerardo_fabricantes_mac f
WHERE '$macRemota' LIKE CONCAT(f.oui, '%')
UNION
SELECT '$soRemoto', '$ipActual', '$macRemota', '$hostRemoto', '$fecha', NULL
LIMIT 1
ON DUPLICATE KEY UPDATE
    sistema_operativo = VALUES(sistema_operativo),
    nombre_host = VALUES(nombre_host),
    fecha_escaneo = VALUES(fecha_escaneo),
    fabricante_id = VALUES(fabricante_id);
"@
        Exec-SQL $query
    } else {
        Write-Host " N/S"
    }
}

Write-Host "✅ REPORTE COMPLETO GUARDADO EN MySQL (XAMPP)"

