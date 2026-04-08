# csirt-labs

Repositório de writeups e investigações de labs de segurança ofensiva e defensiva.

Documentação do processo completo de investigação — incluindo queries que falharam, hipóteses incorretas e lições aprendidas. O objetivo é registrar o raciocínio analítico, não apenas as respostas.

---

## Estrutura

```
csirt-labs/
├── tryhackme/       — Writeups de rooms do TryHackMe
├── cyberdefenders/  — Writeups de labs do CyberDefenders
└── hackthebox/      — Writeups de Sherlocks do HackTheBox
```

---

## Writeups

### TryHackMe

| Room | Dificuldade | Tema | Ferramentas |
|---|---|---|---|
| [Conti](tryhackme/conti-tryhackme-writeup.md) | Medium | Ransomware investigation | Splunk, Sysmon, IIS logs |

---

## Stack

- **SIEM:** Splunk (SPL)
- **Logs:** Sysmon, Windows Event Logs, IIS, EDR
- **Frameworks:** MITRE ATT&CK, Kill Chain
- **Plataformas:** TryHackMe, CyberDefenders, HackTheBox
