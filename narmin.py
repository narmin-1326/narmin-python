import re

log_data=""" 192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020 """
log_pattern=re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<date>.*?)\] "(?P<method>GET|POST|PUT|DELETE|PATCH) (?P<url>.*?) HTTP/1\.1" (?P<status>\d{3})')
#isdediymiz melumatlari regex ifadelerde yazmaq

matches = log_pattern.finditer(log_data) #log melumatini analiz etmek
log_entries = [] #neticeleri saxlamaq
for match in matches:
    log_entries.append(match.groupdict())

for entry in log_entries: #cixarilmis melumatlari cap etmek
        print(entry)

import json
from collections import Counter

# Uğursuz giriş cəhdlərini çıxarmaq (401 status kodu olanlar)
failed_attempts = [entry['ip'] for entry in log_entries if entry['status'] == '401']

# Hər bir IP üçün uğursuz girişlərin sayını hesablamaq
failed_attempts_count = Counter(failed_attempts)

# 5-dən çox uğursuz giriş edən IP-ləri seçmək
frequent_failed_logins = {ip: count for ip, count in failed_attempts_count.items() if count > 5}

# Nəticəni JSON formatında saxlamaq
with open('failed_logins.json', 'w') as json_file:
    json.dump(frequent_failed_logins, json_file, indent=4)

# Çıxarılan məlumatı ekrana çap edək
print("5-dən çox uğursuz giriş edən IP-lər:")
print(frequent_failed_logins)
print("Bütün uğursuz giriş cəhdlərinin sayları:")
print(failed_attempts_count)

# Təhlükəli IP-ləri tapmaq üçün şərt
threat_ips = {ip: count for ip, count in failed_attempts_count.items() if count > 3}

# Nəticəni threat_ips.json faylına yazmaq
with open('threat_ips.json', 'w') as json_file:
    json.dump(threat_ips, json_file, indent=4)

# Çıxarılan təhlükəli IP-ləri ekrana çap edək
print("Təhlükəli IP-lər (3-dən çox uğursuz giriş edənlər):")
print(threat_ips)

# İlk iki JSON faylını oxuyuruq
with open('failed_logins.json', 'r') as file:
    failed_logins_data = json.load(file)

with open('threat_ips.json', 'r') as file:
    threat_ips_data = json.load(file)

# İki məlumat bazasını birləşdiririk
combined_data = {}

# Uğursuz girişləri əlavə edirik
for ip, count in failed_logins_data.items():
    combined_data[ip] = {
        'failed_login_attempts': count,
        'is_threat': ip in threat_ips_data  # Təhlükəli IP-lər siyahısındadırsa True olacaq
    }

# Combined data-nı JSON faylına yazırıq
with open('combined_security_data.json', 'w') as file:
    json.dump(combined_data, file, indent=4)

# Çıxarılan məlumatı ekrana çap edirik
print("Birləşdirilmiş təhlükəsizlik məlumatları:")
print(combined_data)


import csv

# Combined_security_data.json faylını oxuyuruq
with open('combined_security_data.json', 'r') as file:
    combined_data = json.load(file)

# CSV faylına yazmaq üçün başlıq sütunlarını təyin edirik
csv_headers = ['IP Address', 'Failed Login Attempts', 'Is Threat']

# CSV faylına məlumatları yazırıq
with open('log_analysis.csv', 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(csv_headers)  # Başlıqları yazırıq

    # Combined məlumatını fayla yazırıq
    for ip, data in combined_data.items():
        writer.writerow([ip, data['failed_login_attempts'], data['is_threat']])

# Çıxarılan məlumatı ekrana yazırıq
print("CSV faylı uğurla yaradıldı: log_analysis.csv")





