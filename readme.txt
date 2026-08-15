=== Dolutech Blacklist Protect ===
Contributors: Dolutech
Tags: security, blacklist, ip-block, geolocation, brute-force
Requires at least: 6.7
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 0.9.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Proteção avançada WordPress: blacklists automáticas, bloqueio por país (MaxMind), anti força bruta, reCAPTCHA e proteção XML-RPC.

== Description ==

O **Dolutech Blacklist Protect** é um sistema avançado de proteção que oferece múltiplas camadas de segurança para sites WordPress, com tecnologias modernas e interface intuitiva.

### Bloqueio por Geolocalização (NOVO!)
- **Integração MaxMind GeoIP2**: Bloqueie países inteiros automaticamente
- **Validação Automática**: Teste de credenciais ao salvar configurações
- **Cache Inteligente**: Reduz chamadas à API (24h de cache por IP)
- **Interface Intuitiva**: Lista de países comumente bloqueados para referência
- **Códigos ISO**: Use códigos de 2 letras (CN, RU, BR, etc.)

### Sistema de Blacklists Avançado
- **Blacklist Dolutech**: Atualizada automaticamente 2x ao dia
- **Blacklists de Terceiros**: Adicione URLs externas de listas .txt
- **Bloqueio Manual**: IPs específicos com gerenciamento completo
- **Whitelist Inteligente**: IPs fixos e domínios DDNS sempre permitidos

### Proteção Contra Força Bruta
- Bloqueio automático após X tentativas falhadas (configurável)
- **Bloqueio Temporário**: Configure duração em minutos, não horas
- **Bloqueio Permanente**: Para máxima segurança
- **Proteção XML-RPC**: Bloqueio completo ou parcial configurável

### Bloqueio por Usuários Específicos
- Configure usuários "armadilha" (admin, root, administrator)
- Bloqueio imediato do IP ao tentar login com usuários protegidos
- Validação automática: só bloqueia se o usuário NÃO existir

### Sistema de Desbloqueio Inteligente
- Solicitação via e-mail com token seguro (válido 24h)
- **Chave Secreta**: Camada extra de segurança opcional
- **Google reCAPTCHA v2**: Proteção contra bots nos formulários
- Interface responsiva com toggle para visualizar chaves

### Monitoramento Completo
- Dashboard com estatísticas detalhadas por fonte
- Lista de IPs com bloqueio temporário ativo (tempo restante)
- Tokens de desbloqueio pendentes
- Blacklists de terceiros com status e contadores

### Recursos Avançados
- **Interface Dinâmica**: JavaScript para mostrar/ocultar opções
- **Validações Robustas**: Nonces, sanitização e escaping
- **Logs Automáticos**: Registro de atividades e erros
- **Cron Jobs**: Limpeza automática de dados antigos

Ideal para **desenvolvedores**, **administradores** e **agências** que buscam segurança máxima sem comprometer usabilidade.

== Installation ==

1. **Upload**: Envie a pasta `dolutech-blacklist-protect` para `/wp-content/plugins/`
2. **Ativação**: Ative o plugin em **Plugins** → **Plugins Instalados**
3. **Configuração**: Acesse **Configurações** → **Dolutech Blacklist Protect**
4. **Requisitos**: PHP 8.2+ e WordPress 6.7+ (verificados automaticamente)
5. **Recomendações**: 
   - Configure sua whitelist ANTES de ativar bloqueios
   - Teste o sistema de e-mail para desbloqueios
   - Configure reCAPTCHA para máxima segurança

== Frequently Asked Questions ==

= Como funciona o bloqueio por geolocalização? =
Ao ativar o MaxMind GeoIP2, você insere suas credenciais da API e seleciona os países a bloquear usando códigos ISO (2 letras). Quando alguém de um país bloqueado tenta acessar, o plugin consulta a API MaxMind, identifica o país do IP e bloqueia automaticamente. Os resultados ficam em cache por 24 horas para otimizar performance.

= Onde consigo credenciais da MaxMind? =
Acesse https://www.maxmind.com/en/geolite2/signup e crie uma conta gratuita. Em "Manage License Keys", crie uma nova chave. Você receberá um Account ID e uma License Key. O plugin valida automaticamente ao salvar.

= Como as blacklists são atualizadas? =
As listas são atualizadas automaticamente 2x ao dia via cron do WordPress. Inclui a blacklist Dolutech oficial + todas as blacklists de terceiros configuradas.

= E se meu IP estiver bloqueado? =
Configure sua **whitelist** primeiro! Adicione IP fixo ou domínio DDNS em **Configurações** → **Whitelist**. IPs bloqueados manualmente podem solicitar desbloqueio.

= Como funciona o sistema de desbloqueio? =
1. IP bloqueado vê opção "Solicitar Desbloqueio"
2. Sistema envia token seguro por e-mail aos admins
3. Admin clica no link para desbloquear
4. Se configurado: reCAPTCHA + chave secreta obrigatórios

= Posso usar reCAPTCHA nos formulários? =
Sim! Configure suas chaves do Google reCAPTCHA v2 em **Configurações** → **reCAPTCHA**. Aparece automaticamente nos formulários de desbloqueio.

= Como proteger usuários específicos? =
Use **Bloqueio por Usuários Específicos**: adicione usernames como "admin", "root". Qualquer tentativa de login bloqueia o IP imediatamente.

= XML-RPC fica completamente desabilitado? =
Você escolhe: **Bloqueio Completo** (desabilita tudo) ou **Proteção Parcial** (remove métodos perigosos, monitora tentativas).

= Blacklists de terceiros são confiáveis? =
Você adiciona apenas URLs que confia. O plugin valida IPs antes de bloquear. Recomendamos fontes como SpamHaus, AbuseIPDB, etc.

= O plugin afeta performance? =
Mínima. Bloqueios são verificados apenas no início da requisição. Usa caching e limpeza automática de dados antigos.

= Posso contribuir? =
Sim! GitHub: [https://github.com/dolutech](https://github.com/dolutech) | Sugestões: suporte@dolutech.com

== Screenshots ==

1. Dashboard principal com estatísticas detalhadas de blacklists por fonte
2. Configuração MaxMind GeoIP2 com validação automática de credenciais
3. Interface de bloqueio por países com códigos ISO e países comuns
4. Configurações de proteção de login com bloqueio temporário
5. Interface de blacklists de terceiros com status e contadores
6. Sistema de desbloqueio com reCAPTCHA e chave secreta
7. Configuração de bloqueio por usuários específicos
8. Proteção XML-RPC com opções completas e parciais

== Changelog ==

= 0.9.0 =
* **Novo**: Registro de eventos de segurança com painel completo (filtros, paginação, limpeza)
* **Novo**: Bloqueio por faixa CIDR (IPv4 e IPv6) e por user-agent
* **Novo**: REST API para gestão de bloqueios, logs e atualização da blacklist (Application Passwords)
* **Novo**: Notificações via Telegram e Webhook para eventos de bloqueio
* **Melhoria**: Cron diário de manutenção com purga automática de logs antigos

= 0.8.0 =
* **Compatibilidade**: Testado até WordPress 7.1
* **Correção**: reCAPTCHA agora funciona nos formulários de desbloqueio (render inline)
* **Correção**: Página de admin não baixa mais a blacklist do GitHub a cada visita
* **Correção**: Mensagem de login genérica e traduzível (sem revelar o plugin)
* **Segurança**: Denúncia automática agora respeita o toggle "Relato Automático"
* **Segurança**: Rate-limit nas solicitações de desbloqueio (2/dia/IP) e chave secreta (5/15min/IP)
* **Segurança**: Chave secreta armazenada com hash; segredos não são mais exibidos no HTML
* **Segurança**: Suporte a IP real atrás de proxy/CDN (X-Forwarded-For configurável)
* **Performance**: Blacklist armazenada como string sem autoload; stats persistidas; cache negativo MaxMind; cache DNS da whitelist
* **Manutenção**: uninstall.php remove todos os dados; guards ABSPATH em todos os includes; i18n (Text Domain + .pot)
* **Docs**: FAQ corrigido (bloqueio aplica a usuários inexistentes)

= 0.7.0 =
* **Novo**: Integração com MaxMind GeoIP2 para bloqueio por geolocalização
* **Novo**: Validação automática de credenciais MaxMind ao salvar
* **Novo**: Campo para configurar Account ID e License Key
* **Novo**: Campo para bloquear países por código ISO (2 letras)
* **Novo**: Cache de geolocalização por 24 horas para otimizar performance
* **Novo**: Lista de países comumente bloqueados como referência
* **Novo**: Página de bloqueio personalizada para bloqueios geográficos
* **Novo**: Limpeza automática de cache de geolocalização expirado
* **Melhoria**: Toggle seguro para visualizar License Key da MaxMind (textContent)
* **Melhoria**: Interface condicional que aparece após validar credenciais
* **Docs**: Instruções completas para obter credenciais MaxMind
* **Segurança**: Validação de códigos de país com regex
* **Segurança**: Sanitização e escaping em todos os campos MaxMind

= 0.6.0 =
* **Novo**: Botão toggle para visualizar/ocultar chave secreta
* **Novo**: Bloqueio de IPs por usuários específicos (admin, root, etc)
* **Novo**: Validação automática de existência de usuários na lista
* **Melhoria**: Interface JavaScript dinâmica para mostrar/ocultar campos
* **Melhoria**: Hook wp_authenticate para interceptar logins maliciosos
* **Docs**: README.md completo com todas as funcionalidades

= 0.5.0 =
* **Novo**: Google reCAPTCHA v2 integrado aos formulários de desbloqueio
* **Novo**: Configuração completa de reCAPTCHA (Site Key + Secret Key)
* **Novo**: Validação server-side robusta do reCAPTCHA
* **Melhoria**: Formulários responsivos com design aprimorado
* **Melhoria**: Tratamento de erro elegante para reCAPTCHA
* **Segurança**: Timeout e validação de IP nas requisições reCAPTCHA

= 0.4.0 =
* **Novo**: Sistema de blacklists de terceiros (URLs externas)
* **Novo**: Interface completa para gerenciar listas externas
* **Novo**: Estatísticas detalhadas por fonte (Dolutech + terceiros)
* **Novo**: Status visual das blacklists (Ativa, Erro, Pendente)
* **Melhoria**: Atualização automática de múltiplas listas em paralelo
* **Melhoria**: Dashboard reorganizado com contadores por categoria

= 0.3.0 =
* **Novo**: Sistema de chave secreta para desbloqueio
* **Novo**: Bloqueio temporário em MINUTOS (não mais horas)
* **Novo**: Proteção XML-RPC configurável (completa ou parcial)
* **Novo**: Interface para mostrar tempo restante de bloqueios
* **Melhoria**: Páginas de bloqueio temporário personalizadas
* **Melhoria**: JavaScript para campos condicionais

= 0.2.0 =
* **Novo**: Sistema completo de solicitação de desbloqueio
* **Novo**: Tokens seguros por e-mail (válidos 24h)
* **Novo**: Configuração de tentativas máximas de login
* **Novo**: E-mails automáticos para administradores
* **Melhoria**: Interface de tokens pendentes no admin
* **Melhoria**: Limpeza automática de tokens expirados

= 0.1.0 =
* **Novo**: Proteção avançada contra força bruta
* **Novo**: Denúncia automática de IPs maliciosos
* **Novo**: Contadores de tentativas com transients
* **Melhoria**: Sistema de bloqueio mais eficiente
* **Segurança**: Validação aprimorada de IPs

= 0.0.1 =
* **Lançamento**: Versão inicial estável
* Blacklist automática da Dolutech (atualizada 2x/dia)
* Bloqueio e desbloqueio manual de IPs
* Sistema de denúncia manual para abuse@dolutech.com
* Whitelist com suporte a IPs fixos e domínios DDNS
* Interface administrativa completa
* Compatibilidade WordPress 6.7+ e PHP 8.2+


== External Services ==

Este plugin conecta-se a serviços externos para funcionalidade completa:

**Blacklist Dolutech (Obrigatório)**
- URL: https://raw.githubusercontent.com/dolutech/blacklist-dolutech/refs/heads/main/Black-list-semanal-dolutech.txt
- Descrição: Lista oficial de IPs maliciosos, atualizada automaticamente
- Termos: https://dolutech.com/termos-de-uso/
- Privacidade: https://dolutech.com/politica-de-privacidade/

**Sistema de E-mails (Opcional)**
- abuse@dolutech.com: Para denúncias automáticas de IPs
- Admins do site: Para notificações de desbloqueio
- Usa wp_mail() nativo do WordPress

**Google reCAPTCHA v2 (Opcional)**
- API: https://www.google.com/recaptcha/api/siteverify
- Descrição: Validação de formulários contra bots
- Configuração: Requer Site Key + Secret Key
- Termos: https://developers.google.com/recaptcha/docs/terms

**MaxMind GeoIP2 (Opcional)**
- API: https://geolite.info/geoip/v2.1/country/
- Descrição: Geolocalização de IPs para bloqueio por país
- Configuração: Requer Account ID + License Key
- Cadastro: https://www.maxmind.com/en/geolite2/signup
- Termos: https://www.maxmind.com/en/geolite2/eula
- Privacidade: Dados de IP consultados são cacheados localmente por 24h

**Blacklists de Terceiros (Opcional)**
- URLs definidas pelo usuário
- Validação automática de formato .txt
- Exemplos: SpamHaus, AbuseIPDB, etc.

== Upgrade Notice ==

= 0.9.0 =
Novas funcionalidades: painel de logs de eventos, bloqueio CIDR/user-agent, REST API e notificações Telegram/Webhook.

= 0.8.0 =
Correções de segurança e performance: reCAPTCHA corrigido, denúncias respeitam o toggle, rate-limits nos formulários, chave secreta hasheada, admin mais rápido e compatível com WordPress 7.1.

= 0.7.0 =
Bloqueio por geolocalização! Integração completa com MaxMind GeoIP2. Bloqueie países inteiros usando códigos ISO de 2 letras. Cache inteligente e validação automática.

= 0.6.0 =
Novos recursos: botão para visualizar chave secreta + bloqueio por usuários específicos. Interface aprimorada com JavaScript dinâmico.

= 0.5.0 =
Google reCAPTCHA v2 integrado! Adicione proteção contra bots nos formulários de desbloqueio. Configure suas chaves e ative.

= 0.4.0 =
Blacklists de terceiros! Adicione URLs externas de listas .txt para máxima proteção. Dashboard com estatísticas detalhadas.

= 0.3.0 =
Bloqueio em MINUTOS + chave secreta + proteção XML-RPC configurável. Sistema mais flexível e seguro.

= 0.2.0 =
Sistema de desbloqueio com tokens seguros por e-mail. IPs bloqueados podem solicitar revisão aos administradores.

= 0.1.0 =
Proteção contra força bruta com denúncia automática. Bloqueio inteligente após X tentativas configuráveis.

= 0.0.1 =
Primeira versão estável. Blacklist automática Dolutech + bloqueio manual + whitelist + denúncias.


== License ==

Este plugin está licenciado sob a GNU General Public License v2.0 ou posterior. Para mais informações, visite https://www.gnu.org/licenses/gpl-2.0.html.
