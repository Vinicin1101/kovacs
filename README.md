# Kovacs

**Kovacs** é uma ferramenta de análise estática e triagem rápida de malware desenvolvida em Rust. Projetada para extração de IOCs.

## Funcionalidades

* **Geração de Evidências:** Cria automaticamente um relatório `$HOME/.local/share/kovacs/evidences/HASH.evidence` contendo a Cadeia de Custódia (Hash SHA256) e os IOCs encontrados.
* **Extração de Rede:** Identificação e extração de IPs e URLs.
* **Desofuscação de Multiplas camadas:**
  * **Base64 Decoder:** Encontra e decodifica strings em base64.
  * **String Manipulation:** Detecta e reverte técnicas nativas como `StrReverse`.
  * **Stateful Tracking:** Rastrea variáveis na memória e resolve concatenações maliciosas em tempo de análise (ex: `A = "cmd" & ".exe"`).
  * **Array Math Decoder:** Quebra payloads escondidos em arrays hexadecimais e funções `Chr()`.

## IMPORTANTE!

Esse projeto foi desenvolvido **estritamente como objeto de estudo pessoal** na área de análise de malware e engenharia reversa. 

Por favor, saiba:
* **Isenção de Responsabilidade:** Eu nâo me responsabilizo por qualquer dano, infecção, perda de dados ou decisões de resposta a incidentes tomadas com base nas saídas desta ferramenta. **Use por sua própria conta e risco**.
* **Não é uma ferramenta corporativa:** O Kovacs não substitui motores de Antivírus, EDRs ou análises aprofundadas feitas por analistas.
* **Falsos Positivos e Negativos:** O regex e os métodos de análise podem falhar, gerar alertas falsos ou não detectar ofuscações mais avançadas.
* **Segurança:** Nunca manipule artefatos maliciosos fora de um ambiente controlado e isolado. 

## Instalação

```bash
git clone https://github.com/Vinicin1101/kovacs
cd kovacs
cargo build --release
```

## Como Usar

```bash
./target/release/kovacs <file_path>
```

### Exemplo de Saída (`.evidence`)

```text
--- [ KOVACS EVIDENCE REPORT ] ---
- Target: "payload_suspeito.vbs"
- SHA256: bd7ea3076938b8966952a99e5cb832b7dc19f9ad00...

--- [ PLAINTEXT THREAT SCAN ] ---
Plaintext IOC Detected: Set objShell = CreateObject("WScript.Shell")
Plaintext IOC Detected: schtasks /create /tn "EdgeUpdatehp" /tr "%USERPROFILE%\payload.exe"

--- [ NETWORK IOCs ] ---
URL: https://malicious-c2.com/drop.php

--- [ PLAINTEXT THREAT SCAN ] ---
Plaintext IOC Detected: Set objShell = CreateObject("WScript.Shell")
Plaintext IOC Detected: schtasks /create /tn "EdgeUpdatehp" /tr "%USERPROFILE%\payload.exe"

--- [ OBFUSCATION DETECTED (Array Math) ] ---
[!] Array Shift Decoded: script:hTtPS://malicious-c2.com/drop.php
[!] URL Detected: https://malicious-c2.com/drop.php
```
