IRONGATE for Windows
====================

Windows 10 or 11, 64-bit. Nothing else to install: Python and every library are inside IronGate.exe.

START
  Double-click "Start IronGate.bat" (or IronGate.exe). The dashboard opens in the window.
  Open http://127.0.0.1/ in a browser (or http://127.0.0.1:8080/ if port 80 was taken).

  Windows Terminal shows the dashboard best. The first time, Windows SmartScreen may say it does not
  know the app (it is not signed yet): More info, then Run anyway. Windows Firewall asks whether to
  let it on your network: allow Private networks only, unless you mean to serve the internet.

YOUR SITE
  Put your files in the WWW folder beside IronGate.exe. index.html or index.php is the home page.
  WWW\.htaccess turns directory listings off and lists file names to refuse.

PHP (optional)
  IronGate runs .php files through php-cgi.exe. It looks, in order, for:
    - the IRONGATE_PHP_CGI setting (full path to php-cgi.exe)
    - php-cgi.exe on your PATH
    - a "php" folder beside IronGate.exe   (unzip PHP for Windows from windows.php.net there)
    - C:\php\php-cgi.exe
  Without PHP, .php pages answer with an error; everything else works.

OPTIONS
  IronGate.exe --port 8081       listen on another port
  IronGate.exe --headless        no dashboard, one line per request (for scripts or a service)
  set ABUSEIPDB_KEY=your-key     enables AbuseIPDB lookups (the "a" key in the dashboard)

DASHBOARD KEYS
  b ban the selected address   a AbuseIPDB lookup   s export evidence   Ctrl+C stop

FILES IT MAKES (beside IronGate.exe)
  logs.db     every request and ban (SQLite)
  evidence\   exported per-address evidence

WINDOWS-SPECIFIC PROTECTION
  Requests Windows would quietly treat as another file are refused: names ending in a dot or a space,
  "::$DATA" streams, device names (CON, NUL, COM1...), 8.3 short names (PROGRA~1), and any case of
  a blocked name or extension. INDEX.PHP runs as PHP, never as source.

More: https://github.com/krintoxi/IronGate-Web-Server
