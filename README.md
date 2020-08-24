# Sec-lookup
Sec-lookup is a tool for security analysts to perform various domain base lookup during their investigation.

#### In version 1.0 is all about email security, and you can query single domain for:
- SPF
- DKIM
- DMARC
- DNS record types
    - A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, DS, DNSKEY, CDS, CDNSKEY
    



## Usage Example
```
lookup.py yourdomain.com
```
```
lookup.py yourdomain.com -s selector
```
### Options
>Use "-h" or "--help" tag to access the latest options

### Common DKIM selectors
>['dkim', 'default', 'selector', 'selector1', 'selector2', 'google', 'zoho']
## Requirement
- python v3 
- pydig

