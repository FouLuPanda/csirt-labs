# Writeup — TryHackMe: Conti Ransomware
**Plataforma:** TryHackMe  
**Room:** Conti  
**Dificuldade:** Medium | 300 pontos  
**Data:** 2026-04-08  
**Analista:** felipehuneida4  

---

## Contexto do Cenário

Exchange Server (`WIN-AOQKG2AS2Q7.bellybear.local`) comprometido com ransomware Conti.  
ECP e OWA apresentavam erros de parser — sinal de que algo havia sido modificado no servidor.

**Credenciais Splunk do lab:**
- Username: `bellybear`
- Password: `password!!!`
- URL: `http://MACHINE_IP:8000`

---

## Fontes de Dados Disponíveis

```spl
index=* | stats count by index, sourcetype
```

| Sourcetype | Eventos | Relevância |
|---|---|---|
| WinEventLog:Security | 13.476 | Logon, privilege use, object access |
| WinEventLog:Application | 5.422 | Erros de app, serviços |
| WinEventLog:Microsoft-Windows-Sysmon/Operational | 2.664 | Principal fonte — processo, rede, arquivo |
| WinEventLog:System | 3.607 | Serviços, drivers |
| iis | 2.864 | Requisições HTTP ao Exchange |
| WinEventLog:Setup | 111 | Instalação de componentes |

> **Lição:** Sempre iniciar com um inventário de fontes. Sem isso, queries ficam cegas.  
> **Erro cometido:** Esquecemos de mudar o time range de "Last 24 hours" para "All Time" — retornou 0 eventos inicialmente.

---

## Investigação por Pergunta

### 1. Can you identify the location of the ransomware?

**Raciocínio:** Malware executa de paths onde o usuário tem permissão de escrita (AppData, Temp, Downloads, Documents). Binários legítimos ficam em `C:\Windows\` e `C:\Program Files\`.

**SPL tentada (abordagem positiva — filtrar paths suspeitos):**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, User, Image, CommandLine, ParentImage
| where match(Image, "(?i)(appdata|temp|downloads|public|desktop|recycle)")
| sort _time
```
> Resultado: Apenas DismHost.exe legítimo (chamado por cleanmgr.exe). Falso positivo.

**SPL corrigida (abordagem negativa — eliminar o legítimo):**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where NOT match(Image, "(?i)(C:\\\\Windows\\\\|C:\\\\Program Files|C:\\\\Program Files \(x86\))")
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```
> Resultado: `C:\Users\Administrator\Documents\cmd.exe` — **cmd.exe fora do System32 é imediatamente suspeito.**

**Confirmação via EventCode=11 (File Created):**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename, "(?i)administrator")
| table _time, User, Image, TargetFilename
| sort _time
```
> Resultado: `unsecapp.exe` criou `cmd.exe` em Documents. O `cmd.exe` falso criou `readme.txt` em Downloads — nota de resgate.

**Resposta:** `C:\Users\Administrator\Documents\cmd.exe`

---

### 2. Can you find the MD5 hash of the ransomware?

**Raciocínio:** EventCode=11 (File Created) não carrega hash. O hash está no EventCode=1 (Process Create), campo `Hashes`.

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="C:\\Users\\Administrator\\Documents\\cmd.exe"
| table _time, Image, CommandLine, Hashes, ParentImage
```

> O campo `Hashes` do Sysmon traz MD5, SHA256 e IMPHASH concatenados.

---

### 3. What file was saved to multiple folder locations?

**Já identificado na investigação anterior** — sem necessidade de nova query.

**Resposta:** `readme.txt` (nota de resgate do Conti)

Locais encontrados:
- `C:\Users\Administrator\Downloads\readme.txt`
- `C:\Users\Administrator.BELLYBEAR\Downloads\readme.txt`

---

### 4. What was the command the attacker used to add a new user?

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)net.*user")
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```

> Conti frequentemente cria usuários locais para garantir persistência caso as credenciais existentes sejam resetadas.

---

### 5. The attacker migrated the process. What is the migrated process image and the original?

**Raciocínio:** Process injection/migration aparece no **EventCode=8 (CreateRemoteThread)** — um processo criando thread dentro de outro.

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| table _time, User, SourceImage, TargetImage, StartAddress, StartModule
| sort _time
```

**Cadeia encontrada:**
```
powershell.exe → injeta em → unsecapp.exe → injeta em → lsass.exe
```

**Erro cometido:** Submetemos `lsass.exe` como "migrated" e `powershell.exe` como "original".  
**Resposta correta:** O CTF considera a **primeira migração** como o processo migrado.

- **Original:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Migrated:** `C:\Windows\System32\wbem\unsecapp.exe`

> **Lição:** Em CTFs, "migrated process" = primeiro destino da injeção, não o destino final.  
> `unsecapp.exe` (WMI event sink) foi escolhido estrategicamente por ser processo legítimo, sempre em execução, raramente monitorado.

---

### 6. What is the process image used for getting the system hashes?

**Resposta:** `lsass.exe` (Local Security Authority Subsystem Service)

- LSASS armazena hashes de credenciais em memória
- A injeção no lsass via CreateRemoteThread permite dump de hashes sem ferramentas externas
- **MITRE T1003.001** — LSASS Memory

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
| table _time, SourceImage, TargetImage, GrantedAccess
| sort _time
```

> EventCode=10 = Process Access — um processo abrindo handle em outro. Sinal clássico de credential dumping.

---

### 7. What is the web shell the exploit deployed to the system?

**Raciocínio:** Exchange comprometido → web shell dropado em path acessível pelo IIS.

**SPL Sysmon (não retornou resultado útil):**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename, "(?i)(inetpub|exchange|owa|ecp|aspx|asmx)")
| table _time, Image, TargetFilename
| sort _time
```

**SPL IIS (funcionou):**
```spl
index=main sourcetype="iis"
| where match(cs_uri_stem, "(?i)\.aspx") AND cs_method="POST"
| table _time, c_ip, cs_uri_stem, sc_status
| sort _time
```

**Resposta:** `i3gfPctK1c2x.aspx`

> Nome gerado aleatoriamente — padrão de web shells auto-deployados por exploit. Localização: `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\`

---

### 8. What was the command line that executed this web shell?

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(ParentImage, "(?i)w3wp") OR match(CommandLine, "(?i)i3gfPctK1c2x")
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```

**Resposta:**
```
attrib.exe  -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```

> `attrib -r` remove o atributo read-only. Acesso via UNC path (`\\server\C$\`) confirma privilégio administrativo remoto.

---

### 9. What three CVEs did this exploit leverage?

**Processo de investigação — múltiplos erros:**

| Tentativa | CVEs | Resultado |
|---|---|---|
| 1 | CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 (ProxyShell) | Incorreto |
| 2 | CVE-2021-26855, CVE-2021-26857, CVE-2021-27065 (ProxyLogon) | Incorreto |
| 3 | CVE-2021-26855, CVE-2021-26858, CVE-2021-27065 (ProxyLogon v2) | Incorreto |
| 4 | CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 (ProxyLogon v3) | Incorreto |
| 5 | Writeup externo consultado | **Correto** |

**Resposta:** `CVE-2018-13374,CVE-2018-13379,CVE-2020-0796`

| CVE | Produto | Impacto |
|---|---|---|
| CVE-2018-13379 | Fortinet FortiOS SSL VPN | Path traversal — leitura de arquivos sem autenticação |
| CVE-2018-13374 | Fortinet FortiOS | Exposição de informações sensíveis |
| CVE-2020-0796 | Windows SMBv3 (SMBGhost) | RCE via SMB |

> **Lição crítica:** O Exchange não foi o ponto de entrada. O ataque começou pela **VPN Fortinet** vulnerável — CVE-2018-13379 foi massivamente explorado pelo grupo Conti e está documentado no advisory CISA AA21-265A.  
> Focar só nos logs do Exchange teria levado à conclusão errada sobre o vetor inicial.

---

## Cadeia de Ataque Completa (Kill Chain)

```
[Acesso Inicial]
Fortinet SSL VPN vulnerável (CVE-2018-13379 / CVE-2018-13374)
    │
    ▼
[Movimento Lateral]
SMBGhost (CVE-2020-0796) — acesso ao Exchange interno
    │
    ▼
[Persistência Web]
Web shell dropado: owa\auth\i3gfPctK1c2x.aspx
attrib -r via UNC path para remover read-only
    │
    ▼
[Execução]
powershell.exe (acesso inicial ao sistema)
    │
    ▼
[Evasão / Migração de Processo]
Injeção em unsecapp.exe (WMI) via CreateRemoteThread
    │
    ├──▶ [Persistência] Criação de novo usuário local (net user)
    │
    ├──▶ [Drop do Ransomware]
    │    C:\Users\Administrator\Documents\cmd.exe
    │    (payload mascarado como binário do sistema)
    │
    └──▶ [Credential Dumping]
         Injeção em lsass.exe (T1003.001)
              │
              ▼
         [Impacto]
         Ransomware executa → readme.txt em múltiplos diretórios
```

---

## MITRE ATT&CK Mapping

| Tática | Técnica | Evidência |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | CVE-2018-13379 (Fortinet VPN) |
| Persistence | T1505.003 — Web Shell | i3gfPctK1c2x.aspx |
| Defense Evasion | T1036 — Masquerading | cmd.exe em Documents |
| Defense Evasion | T1055.002 — Process Injection (CreateRemoteThread) | powershell → unsecapp → lsass |
| Credential Access | T1003.001 — LSASS Memory | Injeção no lsass.exe |
| Persistence | T1136 — Create Account | net user command |
| Impact | T1486 — Data Encrypted for Impact | Conti ransomware + readme.txt |

---

## Lições Aprendidas

1. **Time range sempre em "All Time"** em labs com dados históricos — o padrão "Last 24h" retorna zero.

2. **Abordagem negativa > positiva** para localizar malware: eliminar o legítimo é mais eficaz do que procurar onde malware "costuma" estar.

3. **EventCode importa:** 
   - Hash do executável → EventCode=1 (Process Create)
   - Arquivo criado no disco → EventCode=11 (File Created)
   - Process injection → EventCode=8 (CreateRemoteThread)
   - Credential dumping → EventCode=10 (Process Access)

4. **Não assumir o vetor de entrada** só pelos logs disponíveis. Os logs do Exchange mostravam o impacto, não a causa raiz — que estava na VPN Fortinet.

5. **CVEs do Conti group:** CVE-2018-13379 (Fortinet) é assinatura do grupo, documentada pela CISA. Conhecer TTPs do adversário acelera a investigação.

6. **Formato importa em CTFs:** sem espaço após vírgula (`CVE-A,CVE-B,CVE-C`), ordem numérica ascendente.
