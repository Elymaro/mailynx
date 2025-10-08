# Mailynx

## Usage

**Mailynx** is a command-line tool that checks whether a domain has an MX record, then verifies the presence and quality of its email spoofing protections through SPF, DKIM, and DMARC records.

It was designed for pentesters, cybersecurity professionals, and administrators who need to quickly assess how well a domain is protected against email spoofing attempts.

## Execution

From a single domain and an output in Markdown format:
```bash
./mailynx.sh -d example.com -o example.md
```

From a file and an output in HTML format:
```bash
./mailynx.sh -L domain_list.txt -o example.html -H
```


## How It Works
For each domain provided, the tool starts by checking if an MX record is present. If no mail server is found, the script either stops or moves on to the next domain.

If an MX is found, it proceeds to analyze the SPF configuration: it checks for the record, parses its content, and flags overly permissive setups (`+all`, `?all` or `~all`).

Next, it attempts to identify a DKIM key by testing common selectors (like `default`, `selector1`, `google`, etc.).
The selector is included in the email header and tells the receiving server where to find the public key in the sender’s DNS.
This mechanism allows organizations to manage multiple keys — for different services, environments, or for key rotation.
When a key is found, its structure and size (RSA 1024, 2048...) are verified to ensure it's valid and secure.

For DMARC, the tool ensures a policy is defined and sufficiently strict. Missing records or permissive policies like none are highlighted.

#### SPF

| Directive | Meaning              | Behavior if the **sending server's IP** is not listed in the SPF record                  |
|-----------|----------------------|------------------------------------------------------------------------------------------|
| `-all`    | Hard fail            | The email is **rejected**                                                                |
| `~all`    | Soft fail            | The email is **accepted but marked as suspicious** *(likely to be flagged as spam)*      |
| `?all`    | Neutral              | The email is **accepted without validation**                                             |
| `+all`    | Pass everything      | The email is **always accepted and considered SPF-compliant**, even for unauthorized IPs |

#### DKIM

Result interpretation (based on receiver and DMARC policy):

| Result     | Meaning                             | Behavior if the **DKIM signature** is invalid or missing                              |
|------------|--------------------------------------|--------------------------------------------------------------------------------------|
| `pass`     | Signature is valid                   | The email is considered **authentic** and passes DKIM checks.                        |
| `fail`     | Signature is invalid                 | The email **fails DKIM** and may be **marked as spam** or **rejected**, depending on the receiver’s or DMARC policy. |
| `none`     | No DKIM signature present            | The email is **not evaluated** by DKIM and may be treated as **less trustworthy**.   |

#### DMARC

| Policy         | Meaning                          | Behavior if the email **fails both SPF and DKIM checks, and proper alignment**        |
|----------------|----------------------------------|----------------------------------------------------------------------------------------|
| `p=reject`     | Reject policy                    | The email is **rejected outright**.                                                    |
| `p=quarantine` | Quarantine policy                | The email is **delivered to the spam/junk folder** or flagged as suspicious.           |
| `p=none`       | Monitoring only                  | The email is **delivered normally**, but failure reports are sent to the domain owner. |

## Output example
### CLI:
<img width="1055" height="531" alt="CLI_output_example" src="https://github.com/user-attachments/assets/2c104667-32d1-4103-a33e-08ab36b3334c" />

### HTML:
<img width="1211" height="799" alt="HTML_output_example" src="https://github.com/user-attachments/assets/767636a7-f6a1-4680-8181-8af5f6357bd9" />

## Contributors

As always, thanks to the amazing contributors!

- <a href="https://github.com/ExHo7" title="ExHo7"><img src="https://avatars.githubusercontent.com/u/112818894?v=4" width="36;" alt="ExHo7"/> ExHo7</a> : Integrated Markdown and HTML output; added several additional control checks.

## Disclaimer

Mailynx is intended exclusively for research, education, and authorized testing. Its purpose is to assist professionals and researchers in identifying vulnerabilities and enhancing system security.

Users must secure explicit, mutual consent from all parties involved before utilizing this tool on any system, network, or digital environment, as unauthorized activities can lead to serious legal consequences. Users are responsible for adhering to all applicable
laws and regulations related to cybersecurity and digital access.

The creator of Mailynx disclaims liability for any misuse or illicit use of the tool and is not responsible for any resulting damages or losses.
