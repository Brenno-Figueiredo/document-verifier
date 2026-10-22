# DocCheck

Apoio à **conferência de documentos** em Python, **sem dependências externas**: CNH, comprovante de endereço e
comprovante de renda (holerite). Ele valida o que dá para validar por regra, **cruza os documentos entre si** e
inspeciona os **metadados dos arquivos** (PDF, JPEG, PNG) em busca de sinais de edição. No fim, entrega um
**parecer** com cada ponto de atenção, a severidade e a ação sugerida.

> ⚠️ **O que ele NÃO faz.** O DocCheck **não prova que um documento é autêntico** e não substitui a fonte oficial.
> Ele aponta divergências para uma **pessoa revisar**. A confirmação de verdade vem do Detran (o QR Code da
> CNH Digital, pela Carteira Digital de Trânsito), da Receita Federal ou do próprio emissor do documento.

## Privacidade (LGPD)

CPF e CNH são dados pessoais. O projeto foi desenhado para tratá-los o mínimo possível:

- **Tudo roda no seu computador.** A interface escuta só em `127.0.0.1`; nada vai para a internet.
- **Nada é gravado**: sem banco de dados, sem logs, sem cache. Os arquivos são lidos na memória e descartados.
- **CPF e CNH aparecem mascarados** em todos os relatórios (`***.982.247-**`).
- **Os exemplos são 100% fictícios.** Nunca coloque documentos reais no repositório: o `.gitignore` bloqueia PDFs,
  imagens, fichas e pareceres (a única exceção é a pasta `samples/`).
- Use apenas dados que você tem **autorização e finalidade legítima** para tratar.

## Como rodar

Requisito: Python 3.9+. Nada para instalar.

```bash
python app.py samples                       # gera fichas e arquivos de exemplo (fictícios)
python app.py serve                         # interface web local (abre o navegador)
```

Na interface, clique em **Exemplo com problemas** para ver o parecer, ou preencha os campos e anexe os arquivos
(eles são lidos só no seu navegador e enviados apenas ao programa local). Pela linha de comando:

```bash
python app.py check samples/ficha_divergente.json --html parecer.html
python app.py forensics samples/holerite_editado.pdf samples/endereco_editado.jpg
python app.py validate cpf 529.982.247-25
python app.py validate cnpj 12ABC34501DE35          # aceita o CNPJ alfanumérico
```
O `check` termina com código `1` quando há ponto de severidade alta ou crítica, e `0` nos outros casos.

## O que é verificado

### Cada documento
| Documento | Regras |
|---|---|
| **CNH** | dígito verificador do número de registro¹ · CPF · categoria válida · datas em ordem (nascimento < 1ª habilitação < emissão < validade) · primeira habilitação aos 18 anos ou mais · CNH vencida · validade acima do prazo usual |
| **Comprovante de endereço** | data de emissão (futura, ou mais antiga que o prazo da política, 90 dias por padrão) · CEP · UF |
| **Comprovante de renda** | CNPJ do empregador (inclusive alfanumérico) · CPF · competência futura ou antiga · **bruto − descontos = líquido** (tolerância de R$ 0,05) · renda declarada maior que a comprovada |

¹ A regra de módulo 11 do número de registro da CNH circula publicamente, mas **não foi conferida com a norma
oficial**. Por isso a falha vira um aviso de severidade média pedindo conferência no documento.

### Cruzamentos entre os documentos
Nome (ignora acentos, maiúsculas e partículas como DE/DA, e aceita iniciais) · **CPF igual em todos** (crítico se
diferir) · data de nascimento da proposta × CNH (crítico) · CEP e número do endereço × comprovante · o **mesmo
arquivo enviado como dois documentos** · **arquivo criado antes da data de emissão** que o documento declara.

### Sinais nos arquivos (metadados)
| Sinal | Por que importa |
|---|---|
| Programa de edição nos metadados (Photoshop, Canva, iLovePDF...) | documentos emitidos por sistemas não costumam passar por editores |
| PDF com **revisões incrementais** (`%%EOF` repetido) | é como editores acrescentam alterações sem reescrever o original (PDF assinado é tratado como informativo) |
| Arquivo modificado depois de criado | a data de modificação não bate com a de criação |
| Data de criação/captura no futuro, ou anterior à emissão | o arquivo não pode existir antes do documento |
| JavaScript, ação de execução ou arquivo embutido no PDF | um comprovante não precisa executar código |
| EXIF de fotos: software, datas de captura e modificação | foto de documento costuma sair direto da câmera |
| Extensão que não confere com o conteúdo | um `.pdf` que na verdade é outro tipo de arquivo |

**Metadados são pistas, não provas.** Um documento legítimo pode ter sido reexportado, e quem edita bem consegue
limpar os rastros. Por isso cada sinal pede revisão humana, e a ausência de sinais não prova que o arquivo é íntegro.

## Parecer e nota

Cada ponto tem severidade (crítico 40 · alto 25 · médio 12 · baixo 5) e a **nota de atenção** é a soma, limitada
a 100. O veredito: qualquer ponto crítico = *"Divergências graves: não prosseguir sem revisão"*; nota ≥ 40 = *revisão
manual obrigatória*; ≥ 12 = *atenção*. O programa **nunca aprova nem reprova um cliente**: a decisão é sempre de uma pessoa.

## Formato da ficha (JSON)

```json
{
  "data_referencia": "2026-10-21",
  "proposta": {"nome": "...", "cpf": "...", "data_nascimento": "12/04/1991", "renda_declarada": 5200,
               "endereco": {"cep": "04000-000", "numero": "120"}},
  "documentos": {
    "cnh": {"nome": "...", "cpf": "...", "numero_registro": "...", "validade": "18/05/2032", "arquivo": "cnh.pdf"},
    "comprovante_endereco": {"nome": "...", "data_emissao": "28/09/2026", "cep": "04000-000", "arquivo": "conta.pdf"},
    "comprovante_renda": {"competencia": "09/2026", "cnpj_empregador": "...", "bruto": "5.200,00",
                          "descontos": "1.148,00", "liquido": "4.052,00", "arquivo": "holerite.pdf"}
  }
}
```
Veja `samples/ficha_ok.json` e `samples/ficha_divergente.json`. Os valores monetários aceitam `5.200,00`, `R$ 5.200,00`
ou `5200.00`. Os limites (prazo de 90 dias, tolerância, margem de renda) podem ser ajustados na chave `"configuracao"`.

## Segurança do próprio programa

- Servidor **somente local** (`127.0.0.1`) e com conferência do cabeçalho `Host` (contra *DNS rebinding*).
- Os `POST` exigem `application/json`, o que impede que um formulário de outro site envie dados ao programa.
- **O servidor nunca lê caminhos de arquivo** enviados pelo cliente, só conteúdo em base64. Caminhos valem apenas na
  linha de comando, onde quem roda é o dono do computador. Há teste para isso.
- Limite de tamanho (25 MB por requisição, 15 MB por arquivo), cabeçalhos de segurança (CSP, `nosniff`, `X-Frame-Options`).
- Relatórios HTML e interface escapam todo texto vindo dos documentos, e arquivos **nunca são executados**.

## Estrutura

```
app.py                  ponto de entrada
doccheck/
  validators.py         CPF, CNPJ (alfanumérico), CNH, CEP, datas, dinheiro, nomes, máscaras
  forensics.py          metadados de PDF, JPEG (EXIF) e PNG; sinais de edição
  rules.py              regras por documento + cruzamentos + nota e veredito
  findings.py           achado (severidade, explicação, ação sugerida)
  report.py             parecer em texto, JSON e HTML
  server.py             servidor local + API (/api/check, /api/validate)
  samples.py            gera fichas e arquivos fictícios de exemplo
  cli.py                linha de comando
static/index.html       interface web
samples/                fichas e arquivos de exemplo (fictícios)
tests/                  43 testes automatizados
```

## Testes

```bash
python -m unittest discover -s tests -v
```

## Limitações

- Não consulta nenhuma base oficial (Receita, Detran, bancos). É conferência por regras e por metadados.
- Não lê o conteúdo visual dos documentos (sem OCR): quem digita ou cola os campos é o operador.
- A análise de PDF usa leitura direta dos bytes e não enxerga metadados guardados em fluxos comprimidos.
- As regras de negócio (prazos, tolerâncias) são exemplos e devem seguir a política da sua instituição.

## Ideias para evoluir

- Leitura automática dos campos com OCR, e checagem do QR Code da CNH Digital
- Consulta oficial de situação cadastral (CPF e CNPJ) por API autorizada
- Integração com o Venator, gerando eventos de risco a partir dos pareceres

## Projetos da série

[network-scanner](https://github.com/Brenno-Figueiredo/network-scanner) ·
[logwatch](https://github.com/Brenno-Figueiredo/logwatch) ·
[loginguard](https://github.com/Brenno-Figueiredo/loginguard) ·
[web-vuln-scanner](https://github.com/Brenno-Figueiredo/web-vuln-scanner) ·
[ssh-honeypot](https://github.com/Brenno-Figueiredo/ssh-honeypot) ·
[security-event-correlator](https://github.com/Brenno-Figueiredo/security-event-correlator) ·
[malware-static-analyzer](https://github.com/Brenno-Figueiredo/malware-static-analyzer) ·
[phishguard](https://github.com/Brenno-Figueiredo/phishguard) ·
[phishguard-ui](https://github.com/Brenno-Figueiredo/phishguard-ui) ·
[threat-intel-enricher](https://github.com/Brenno-Figueiredo/threat-intel-enricher)
