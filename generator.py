from datetime import datetime, timedelta
from typing import Tuple, List

def generate_scenario_logs() -> Tuple[List[str], List[str], List[str]]:
    # Генерация учебных логов для трёх источников: web, proxy, vpn.Возвращает три списка строк.
    base_time = datetime(2025, 11, 10, 13, 55, 0)

    # Web
    web_lines = [
        # обычный пользователь
        '203.0.113.10 - - [{t1} +0100] "GET /login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'.format(
            t1=(base_time + timedelta(seconds=10)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
        '203.0.113.10 - john [{t2} +0100] "POST /login HTTP/1.1" 302 256 "-" "Mozilla/5.0"'.format(
            t2=(base_time + timedelta(seconds=20)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
        '203.0.113.10 - john [{t3} +0100] "GET /admin/panel HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'.format(
            t3=(base_time + timedelta(seconds=30)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
        # злоумышленник с перебором паролей
        '198.51.100.23 - - [{t4} +0100] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"'.format(
            t4=(base_time + timedelta(minutes=1)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
        '198.51.100.23 - - [{t5} +0100] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"'.format(
            t5=(base_time + timedelta(minutes=1, seconds=10)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
        '198.51.100.23 - alice [{t6} +0100] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"'.format(
            t6=(base_time + timedelta(minutes=1, seconds=20)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
        '198.51.100.23 - alice [{t7} +0100] "GET /secure/settings HTTP/1.1" 200 8192 "-" "Mozilla/5.0"'.format(
            t7=(base_time + timedelta(minutes=1, seconds=30)).strftime("%d/%b/%Y:%H:%M:%S")
        ),
    ]

    # Proxy
    proxy_lines = [
        "{ts} 192.168.0.10 GET http://example.com/ 200 1024".format(
            ts=(base_time + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")
        ),
        "{ts} 192.168.0.10 GET http://example.com/topsecret/data 200 2048".format(
            ts=(base_time + timedelta(minutes=2, seconds=10)).strftime("%Y-%m-%dT%H:%M:%S")
        ),
        "{ts} 192.168.0.11 GET http://files.example.com/archive.zip 200 250000".format(
            ts=(base_time + timedelta(minutes=2, seconds=20)).strftime("%Y-%m-%dT%H:%M:%S")
        ),
    ]

    # VPN
    vpn_lines = [
        "{ts} user=john ip=198.51.100.23 assigned=10.8.0.2 action=login result=success".format(
            ts=(base_time + timedelta(minutes=-5)).strftime("%Y-%m-%dT%H:%M:%S")
        ),
        "{ts} user=alice ip=198.51.100.23 assigned=10.8.0.3 action=login result=failure".format(
            ts=(base_time + timedelta(minutes=-4)).strftime("%Y-%m-%dT%H:%M:%S")
        ),
        "{ts} user=alice ip=198.51.100.23 assigned=10.8.0.3 action=login result=success".format(
            ts=(base_time + timedelta(minutes=-3, seconds=30)).strftime("%Y-%m-%dT%H:%M:%S")
        ),
    ]

    return web_lines, proxy_lines, vpn_lines