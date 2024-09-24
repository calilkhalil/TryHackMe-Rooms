# **U.A. High School**

**Author**: Hakal  
**Title**: U.A. High School Official v4  
**Level**: Easy  

---

## **1. Introduction**

U.A. High School began by discovering a `PHP` file on the web application and fuzzing to identify parameter names. Upon finding a parameter that allowed us to run commands, we utilized it to obtain a shell. While enumerating the file system within the shell, we discovered a passphrase and a corrupted image. Fixing the image by changing the magic bytes from `PNG` to `JPG` and using the passphrase to extract the hidden data from the image, provided us with user credentials. After getting a shell as this user using `SSH`, we were able to execute a script as the root user using sudo. The script contained an arbitrary file write vulnerability, which we exploited to gain a shell as the `root` user.

---

## **2. Initial Enumeration**

<-text->

### **Step 1: Network Mapper**

O primeiro passo foi executar um Network Scan para enumerar serviços. Com isso, conseguimos saber quais serviços estão disponíveis para ataque.

Executamos o seguinte comando:

```bash
nmap -T5 -Pn -sCV -p- $ip
```

**Saída:**

![Network Mapper Output](1.png)

As we can see, there are two ports open.

22/SSH
80/HTTP

---

### **Step 2: Content Discovery**

Depois de saber os serviços disponíveis, a próxima etapa foi encontrar recursos que podem ser utilizados como vetores de ataque. Para isso, utilizamos o [FeroxBuster](https://github.com/epi052/feroxbuster).

Utilizamos o seguinte comando:

```bash
feroxbuster -u http://$ip/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t150
```
A wordlist utilizada é essa: https://github.com/danielmiessler/SecLists

**Saída:**

![FeroxBuster Output](2.png)

**Análise:**

- Os status codes (404, 403, 200, 301) indicam as respostas do servidor para diferentes requisições:
  - **404 (Not Found):** indica que a página requisitada não existe.
  - **403 (Forbidden):** significa que o acesso ao recurso é proibido.
  - **200 (OK):** indica que a página ou recurso foi encontrado com sucesso.
  - **301 (Moved Permanently):** sugere que o recurso foi movido para outra URL.

- **Recursos descobertos**:
  - `/assets/`: parece ser um diretório com recursos estáticos (como imagens, CSS, etc.).
  - `/assets/index.php`: um possível arquivo `PHP` que pode ser alvo de análise mais profunda, já que pode conter vulnerabilidades de execução de código ou falhas em validação de entrada.
  - O servidor retorna muitos 404 e 403, que estão sendo filtrados automaticamente pela ferramenta.

- **Próximos passos sugeridos**:
  - Explorar os arquivos `PHP` encontrados, já que eles podem conter vulnerabilidades de inclusão de arquivo, execução de código remoto ou outras falhas.
  - Analisar os redirecionamentos 301 para verificar se há novos caminhos a serem explorados.
  - Verificar se há permissões incorretas em diretórios retornando 403.

---

## **4. File Exploitation**

### **Visiting the File:**

![Visiting the File](3.png?)

### **Análise**:

- A página acessada `http://10.10.35.53/assets/index.php` não exibe nenhum conteúdo visível, o que pode indicar várias possibilidades:

### 1. Conteúdo Condicional:
   - O arquivo `index.php` pode estar configurado para exibir conteúdo apenas sob certas condições, como parâmetros GET ou POST específicos.
   - Pode ser que a página esteja esperando:
     - **Parâmetros na URL**: Tente enviar variáveis adicionais na URL, por exemplo, `?id=1` ou outros valores, para verificar se o conteúdo é alterado dinamicamente.
     - **Autenticação**: É possível que o conteúdo só seja exibido após login ou envio de cookies específicos de sessão.
     - **Validação de Requisições**: Algumas páginas PHP processam dados com base em valores enviados via POST ou cabeçalhos HTTP personalizados.

### 2. Vulnerabilidades Potenciais:
   - Mesmo que a página não exiba conteúdo visível, o arquivo PHP pode conter vulnerabilidades que podem ser exploradas:
     - **Injeção SQL (SQLi)**: Se o `index.php` processa entradas de usuário (como parâmetros GET/POST), vale a pena testar por injeções SQL tentando incluir caracteres especiais (ex: `' OR '1'='1`).
     - **Inclusão de Arquivo Local/Remoto (LFI/RFI)**: O arquivo PHP pode estar vulnerável a inclusão de arquivos, permitindo acesso a outros arquivos no servidor. Tente enviar parâmetros como `?file=../../etc/passwd` ou `?page=login`.
     - **Execução Remota de Código (RCE)**: Se o arquivo permite inputs que são processados sem validação, pode haver uma possibilidade de executar comandos no servidor. Teste inputs que podem gerar execuções de código no sistema.
     - **Cross-Site Scripting (XSS)**: Se o arquivo PHP processa entradas sem sanitização, é possível injetar scripts JavaScript maliciosos que podem ser executados quando outros usuários acessarem a página.
   
### Próximos Passos:
- Usar ferramentas de *fuzzing* para testar diferentes inputs e identificar respostas ocultas do servidor.
- Verificar se há vulnerabilidades como injeção de SQL, LFI/RFI, RCE ou XSS.
- Testar parâmetros GET e POST para tentar interações e visualizar possíveis conteúdos dinâmicos.
- Analisar os headers HTTP e possíveis cookies de sessão para verificar dependência de autenticação ou tokens.
  
## **5. Fuzzing Parametrs**
Para fazer o fuzzing vamos unir duas wordlists pequenas em uma só e validar LFI e RCE de uma vez, uma das wordlists que vamos utilizar é:
[LFI](https://github.com/lutfumertceylan/top25-parameter?tab=readme-ov-file#top-25-remote-code-execution-rce-parameters-get-based)
E a outra é: [RCE](https://github.com/lutfumertceylan/top25-parameter?tab=readme-ov-file#top-25-local-file-inclusion-lfi-parameters)

Unindo ambas vmaos conseguir validar parameters de LFI e RCE ao mesmo tempo. Desta forma executamos o seguinte comando:

```bash
ffuf -u "http://$ip/assets/index.phpFUZZls" -w lfi-rce.txt -fs 0
```
Lembrando que a wordlist utilizada é a união das duas acimas, o nome pode ser qualquer um. Lembre-se de remover o `=` no final de cada palavra, para que facilite mais a sua visualização.

**Saída:**

![FFuF Output](4.png?)

### **Análise**:

- A ferramenta utilizada aqui é o *ffuf* (Fuzz Faster U Fool), que está sendo usada para testar possíveis parâmetros e valores no endpoint `http://10.10.35.53/assets/index.phpFUZZ=ls`. O objetivo é verificar se o arquivo `index.php` é vulnerável a Local File Inclusion (LFI) ou execução remota de código (RCE).

### 2. Resultados:
   - O fuzzing retornou um status **200 OK** para o parâmetro testado, sugerindo que a requisição foi processada com sucesso pelo servidor.
   - O tamanho da resposta foi **40 bytes**, mas contém apenas **1 palavra** e **1 linha**, o que pode indicar uma resposta mínima, possivelmente sem conteúdo significativo visível, ou apenas uma confirmação de execução sem retornar dados.

### 3. Possibilidades:
   - **Execução de Comandos Remotos (RCE)**: O `=ls` no final da URL indica uma tentativa de executar o comando `ls` (listar diretórios). Se a palavra `ls` foi de fato executada, pode haver uma vulnerabilidade de execução de código remoto (RCE), onde comandos arbitrários são executados no servidor.
   - **Resposta Curta**: O tamanho da resposta sugere que, mesmo que o comando tenha sido aceito, pode ser que o resultado não tenha sido exibido ou foi minimamente renderizado. Isso pode acontecer devido à filtragem de saída no código PHP ou outras limitações de visualização no frontend.

### Próximos Passos:
- **Analisar a resposta**: Embora o status seja 200, a resposta curta pode indicar que o servidor processou o comando, mas não exibiu a saída. Isso requer uma análise mais detalhada da resposta para entender o comportamento.
- **Testar outros comandos**: Pode ser útil testar comandos adicionais que possam retornar dados mais facilmente interpretáveis, como `cat /etc/passwd`, para verificar se a inclusão de arquivos ou execução remota de código é possível.

---

## **5. Exploiting RCE**

### **Requisitando o parâmetro:**

![Visiting the File](5.png?)

## Análise:

- A URL acessada foi `http://10.10.35.53/assets/index.php?cmd=ls`, e a resposta retornada foi a seguinte string codificada em Base64:
  
![Visiting the File + Output](6.png?)

### 1. Decodificação da Resposta:

- Para tentar decodificar essa string Base64, podemos Utilizamos o seguinte comando:

```bash
echo 'aW1hZ2VzCmluZGV4LnBocApzdHlsZXMuY3NzCg==' | base64 -d
```

**Saída:**

![Decode Output](7.png?)

### 2. Análise do Conteúdo Decodificado:

- O comando enviado (`cmd=ls`) foi processado pelo servidor, e o resultado da execução foi codificado em Base64 e retornado. A saída contém a lista de arquivos e diretórios presentes no diretório atual do servidor.

- Os itens retornados são:
- **images/**: Um diretório contendo, provavelmente, arquivos de imagem usados pelo site.
- **index.php**: O arquivo PHP que está sendo explorado.
- **styles.css**: Um arquivo de folha de estilo (CSS), usado para definir o layout da página.

### 3. Comportamento do Sistema:

- O fato de a saída ser codificada em Base64 sugere que o código PHP que processa o comando provavelmente está sanitizando ou modificando a saída antes de retorná-la. Isso pode ser uma medida para ocultar diretamente a saída do comando ou evitar caracteres especiais na resposta.

### 4. Próximos Passos:

- **Testar novos comandos**: Agora que a execução de comandos foi confirmada, podemos tentar obter uma reverse shell.

---
## **5. Reverse Shell as www-data**

Sabendo que nossos comandos são interpretados sem problema, apenas voltam encodados como base64, podemos tentar obter uma shell reversa. Para isso vamos utilizar a seguinte projeto.

![RevShells](8.png?)

A ferramenta é bem intuitiva, basta preencher seu ip da VPN do TryHackMe e a porta que vamos utilizar. Como o RCE é via Web, vamos encodar para URL encode.


---
