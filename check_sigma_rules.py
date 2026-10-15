# ===== ДАННЫЕ =====
logs_bruteforce = [
    "2026-10-15 08:00:01 EventID:4625 User: admin IpAddress: 192.162.01.100",
    "2026-10-15 08:00:02 EventID:4625 User: admin IpAddress: 192.162.01.100",
    "2026-10-15 08:00:03 EventID:4625 User: admin IpAddress: 192.162.01.100",
    "2026-10-15 08:00:04 EventID:4625 User: admin IpAddress: 192.162.01.100",
    "2026-10-15 08:00:05 EventID:4625 User: admin IpAddress: 192.162.01.100",
    "2026-10-15 08:00:06 EventID:4625 User: admin IpAddress: 192.162.01.100",
]

logs_port_scan = [
    "2026-10-15 08:01:01 Connection attempt from 10.0.0.5 port 22",
    "2026-10-15 08:01:02 Connection attempt from 10.0.0.5 port 80",
    "2026-10-15 08:01:03 Connection attempt from 10.0.0.5 port 443",
    "2026-10-15 08:01:04 Connection attempt from 10.0.0.5 port 8080",
    "2026-10-15 08:01:05 Connection attempt from 10.0.0.5 port 3306",
    "2026-10-15 08:01:06 Connection attempt from 10.0.0.5 port 21",
]

logs_spraying = [
    "2026-10-15 08:02:01 EventID:4625 User: admin IpAddress: 203.0.113.5",
    "2026-10-15 08:02:02 EventID:4625 User: user1 IpAddress: 203.0.113.5",
    "2026-10-15 08:02:03 EventID:4625 User: guest IpAddress: 203.0.113.5",
    "2026-10-15 08:02:04 EventID:4625 User: root IpAddress: 203.0.113.5",
]

# ===== ФУНКЦИИ =====
def check_bruteforce(logs, threshold=4):
    count_by_ip = {}
    for line in logs:
        if "EventID:4625" in line and "IpAddress:" in line:
            ip = line.split("IpAddress:")[1].strip()
            count_by_ip[ip] = count_by_ip.get(ip, 0) + 1
    return [(ip, count) for ip, count in count_by_ip.items() if count > threshold]

def check_port_scan(logs, threshold=5):
    ports_by_ip = {}
    for line in logs:
        if "Connection attempt" in line:
            ip = line.split("from")[1].split()[0]
            port = int(line.split("port")[1].strip())
            if ip not in ports_by_ip:
                ports_by_ip[ip] = set()
            ports_by_ip[ip].add(port)
    return [(ip, len(ports)) for ip, ports in ports_by_ip.items() if len(ports) > threshold]

def check_password_spraying(logs, threshold=3):
    users_by_ip = {}
    for line in logs:
        if "EventID:4625" in line and "User:" in line and "IpAddress:" in line:
            ip = line.split("IpAddress:")[1].strip()
            user = line.split("User:")[1].split()[0]
            if ip not in users_by_ip:
                users_by_ip[ip] = set()
            users_by_ip[ip].add(user)
    return [(ip, len(users)) for ip, users in users_by_ip.items() if len(users) > threshold]

# ===== ЗАПУСК =====
if __name__ == "__main__":
    print("🔍 Брутфорс:", check_bruteforce(logs_bruteforce))
    print("🔍 Сканирование портов:", check_port_scan(logs_port_scan))
    print("🔍 Password Spraying:", check_password_spraying(logs_spraying))
