# APIHawk Usage Guide

## JS Scraper — find backend URLs and secrets
```bash
python Apihawk.py -u https://target.com --js-only
```

## Subdomain recon — no API scanning
```bash
python Apihawk.py -u https://target.com --subdomain --no-subscan --js-only
```

## Subdomain + DNS brute force
```bash
python Apihawk.py -u https://target.com --subdomain --brute --no-subscan --js-only
```

## Full scan with WAF evasion
```bash
python Apihawk.py -u https://target.com --waf -t 30
```

## Full scan with subdomain recon
```bash
python Apihawk.py -u https://target.com --subdomain -t 30
```

## Verbose output — see all 404s and filtered results
```bash
python Apihawk.py -u https://target.com -v
```

## High concurrency for fast networks
```bash
python Apihawk.py -u https://target.com -c 100 -t 15
```

## Custom subdomain wordlist
```bash
python Apihawk.py -u https://target.com --subdomain --brute --subdomain-wordlist /path/to/wordlist.txt
```
