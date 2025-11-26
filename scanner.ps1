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

    # -----------------------------
    # 1. Windows por SMB (445)
    # -----------------------------
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        if ($client.ConnectAsync($ip, 445).Wait(200)) {
            $stream = $client.GetStream()
            $buffer = New-Object Byte[] 1024
            $stream.ReadTimeout = 500

            # Paquete SMB mínimo
            $packet = [byte[]](0x00,0x00,0x00,0x54,0xFF,0x53,0x4D,0x42,0x72)
            $stream.Write($packet,0,$packet.Length)

            Start-Sleep -Milliseconds 200
            if ($stream.DataAvailable) {
                $read = $stream.Read($buffer,0,1024)
                $data = [System.Text.Encoding]::ASCII.GetString($buffer,0,$read)
                if ($data -match "Windows") {
                    return @{SO="Windows"; Metodo="SMB"}
                }
            }
        }
        $client.Dispose()
    } catch {}

    # -----------------------------
    # 2. Linux por SSH Banner (22)
    # -----------------------------
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        if ($client.ConnectAsync($ip, 22).Wait(200)) {
            $stream = $client.GetStream()
            $buffer = New-Object Byte[] 1024
            Start-Sleep -Milliseconds 200

            if ($stream.DataAvailable) {
                $read = $stream.Read($buffer,0,1024)
                $banner = [System.Text.Encoding]::ASCII.GetString($buffer,0,$read)

                if ($banner -match "OpenSSH|Debian|Ubuntu|CentOS|Fedora|RedHat|Linux") {
                    return @{SO="Linux"; Metodo="SSH Banner"}
                }
            }
        }
        $client.Dispose()
    } catch {}

    # -----------------------------
    # 3. NetBIOS (Windows)
    # -----------------------------
    try {
        $nb = nbtstat -A $ip 2>$null
        if ($nb -match "WINDOWS") {
            return @{SO="Windows"; Metodo="NetBIOS"}
        }
    } catch {}

    # -----------------------------
    # 4. SNMP (Switch/Router/Linux)
    # -----------------------------
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($ip), 161)

        $snmp = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6C,0x69,0x63,
                         0xA0,0x19,0x02,0x04,0x70,0x12,0x34,0x21,0x02,0x01,0x00,
                         0x02,0x01,0x00,0x30,0x0B,0x30,0x09,0x06,0x05,
                         0x2B,0x06,0x01,0x02,0x01,0x05,0x00)

        $udp.Send($snmp,$snmp.Length,$endpoint) | Out-Null
        Start-Sleep -Milliseconds 400

        if ($udp.Available -gt 0) {
            return @{SO="Router / Linux / Switch"; Metodo="SNMP"}
        }

        $udp.Close()
    } catch {}

    # -----------------------------
    # 5. HTTP/HTTPS Headers (Router)
    # -----------------------------
    foreach ($proto in @("http","https")) {
        try {
            $r = Invoke-WebRequest "$proto://$ip" -Method Head -TimeoutSec 1 -ErrorAction Stop
            if ($r.Headers.Server -match "MikroTik|Ubiquiti|Router|TP-Link|Cisco|D-Link") {
                return @{SO="Router / IoT"; Metodo="HTTP Header"}
            }
        } catch {}
    }

    # -----------------------------
    # 6. TTL fingerprint (respaldo)
    # -----------------------------
    try {
        $ping = Test-Connection -Count 1 -Quiet:$false -ComputerName $ip -ErrorAction Stop
        $ttl = $ping.IPv4Statistics.Ttl

        if ($ttl -ge 120)      { return @{SO="Windows (Probable)"; Metodo="TTL"} }
        elseif ($ttl -ge 60)  { return @{SO="Linux (Probable)"; Metodo="TTL"} }
    } catch {}

    # -----------------------------
    return @{SO="Desconocido"; Metodo="Ninguno"}
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
# INSERT / UPDATE LOCAL
# =======================================
$queryEquipo = @"
INSERT INTO Gerardo_equipos (sistema_operativo, ip, mac, nombre_host, fecha_escaneo, fabricante_id, metodo_detectado)
SELECT '$so', '$ipLocal', '$mac', '$hostname', '$fechaScan', f.id, 'Local'
FROM Gerardo_fabricantes_mac f
WHERE '$mac' LIKE CONCAT(f.oui, '%')
UNION
SELECT '$so', '$ipLocal', '$mac', '$hostname', '$fechaScan', NULL, 'Local'
LIMIT 1
ON DUPLICATE KEY UPDATE
    sistema_operativo = VALUES(sistema_operativo),
    fecha_escaneo = VALUES(fecha_escaneo),
    fabricante_id = VALUES(fabricante_id),
    metodo_detectado = VALUES(metodo_detectado);
"@
Exec-SQL $queryEquipo

# Obtener ID
$equipoID = (Exec-SQL "SELECT id FROM Gerardo_equipos WHERE mac='$mac' ORDER BY id DESC LIMIT 1;" | Select-Object -Last 1).Trim()
Write-Host "🆔 ID local: $equipoID"
Write-Host "======================="
# =======================================
# ESCANEO DE PUERTOS LOCAL
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
"@
            Write-Host "🟢 Puerto $puerto abierto"
        } else {
            Write-Host "🔘 Puerto $puerto cerrado"
        }
    } catch {
        Write-Host "🔘 Puerto $puerto cerrado"
    } finally { $tcp.Dispose() }
}

# =======================================
# ESCANEO COMPLETO DE LA SUBNET
# =======================================
for ($i = 1; $i -le 100; $i++) {
    $ipActual = "$segmento.$i"

    if (Test-Connection -Quiet -Count 1 -TimeoutSeconds 1 $ipActual) {
        Write-Host " ✔ Activo"

        try { $hostRemoto = (Resolve-DnsName $ipActual -ErrorAction Stop).NameHost } catch { $hostRemoto = "Desconocido" }

        $arp = arp -a $ipActual | Select-String $ipActual
        if ($arp) { 
            $macRemota = ($arp.ToString().Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries))[1] 
            $macRemota = $macRemota -replace "-", ":"
        } else { 
            $macRemota = "00:00:00:00:00:00"
        }

        $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # ======== DETECCION DE SO ========
        $det = Detectar-SO $ipActual
        $metodoSO = $det.Metodo

        # ======== INSERT / UPDATE ========
        $query = @"
INSERT INTO Gerardo_equipos (sistema_operativo, ip, mac, nombre_host, fecha_escaneo, fabricante_id, metodo_detectado)
SELECT '$soRemoto', '$ipActual', '$macRemota', '$hostRemoto', '$fecha', f.id, '$metodoSO'
FROM Gerardo_fabricantes_mac f
WHERE '$macRemota' LIKE CONCAT(f.oui, '%')
UNION
SELECT '$soRemoto', '$ipActual', '$macRemota', '$hostRemoto', '$fecha', NULL, '$metodoSO'
LIMIT 1
ON DUPLICATE KEY UPDATE
    sistema_operativo = VALUES(sistema_operativo),
    nombre_host = VALUES(nombre_host),
    fecha_escaneo = VALUES(fecha_escaneo),
    fabricante_id = VALUES(fabricante_id),
    metodo_detectado = VALUES(metodo_detectado);
"@
        Exec-SQL $query
    } else {
        Write-Host " N/S"
    }
}

Write-Host "✅ REPORTE COMPLETO GUARDADO EN MySQL (XAMPP)"
