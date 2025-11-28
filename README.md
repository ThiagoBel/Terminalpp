# Terminal++

![Downloads](https://img.shields.io/github/downloads/ThiagoBel/Terminalpp/total)
![Release](https://img.shields.io/badge/release-228115-orange)
![C++](https://img.shields.io/badge/language-C%2B%2B-blue)
![OS](https://img.shields.io/badge/os-Windows%2010%2F11-blue)
![Code Size](https://img.shields.io/github/languages/code-size/ThiagoBel/Terminalpp)

**Terminal++** (ou **T++**) é um terminal customizado escrito em C++11 para **Windows**, criado para oferecer uma experiência poderosa, com recursos avançados, comandos internos, verificação de sistema e personalização via terminal.

---

O Terminal++ possui diversos comandos internos, incluindo:

**Comandos básicos do sistema**
  - `exit` — Encerra o Terminal++.
  - `^> <comando>` — Executa comandos diretamente no sistema operacional.
  - `say <texto>` — Exibe texto no terminal.
  - `open <aplicativo>` — Abre programas no Windows.

**Informações do sistema**
  - `check_infos` ou `infos` — Mostra usuário, SO, CPU, extensões e arquitetura.
  - `check_info_ext <url>` ou `ext <url>` — Obtém informações externas de uma URL.

**Atualizações e versão**
  - `--version` — Mostra a versão atual.
  - `check_updates` ou `updates` — Verifica se há nova versão disponível.
  
**Gerenciamento de PATH**
  - `&path` — Adiciona o Terminal++ ao PATH do sistema (necessita de privilégios de administrador).
  - `&rpath` — Remove o Terminal++ do PATH do sistema.
  - `add_path <caminho>` — Adiciona outro caminho ao PATH (admin).
  - `del_path <caminho>` — Remove caminho do PATH (admin).

**Administração**
  - `check_admin` ou `adm` — Verifica se o terminal está rodando como administrador.
  
**Verificação e diagnóstico**
  - `verify_tpp` — Verifica se os diretórios e arquivos do Terminal++ estão corretos.
  - `check_size <arquivo>` — Mostra o tamanho de um arquivo.

**Extras**
  - `credits` — Mostra os créditos do Terminal++ e das bibliotecas utilizadas.
  - `all_errors` ou `errors` — Exibe todos os erros conhecidos.
  - `dir` — Lista arquivos e pastas no diretório atual.

---

## Instalação

1. Baixe a pasta do Terminal++
2. Descompacte a pasta em `C:\Program Files (x86)`
3. Execute o arquivo `Terminal++.exe` e pronto :) 

## Recomendação

- Inicie o Terminal++ com permissão de administrador e use o comando `&path`, isso faz que você possa usar comandos do tipo: "Terminal++ --version" em outros terminais :)
- Use o comando `docs` para ver todos os comandos do Terminal++