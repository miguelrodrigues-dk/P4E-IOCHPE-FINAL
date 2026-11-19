 # Integrantes:
 Miguel da Silva Rodriguês, Matheus e Nicolas Santos.2ºDS.

# Nome do Projeto:

# P4E - Agência de Eventos

# Portfólio:
 [Portfólio-IOCHPE](<Portfólio - Turma 2025 1 (2).pdf>)


## Atualizações desta versão

- A página `/` agora apresenta o P4E antes do cadastro.
- Fotos de perfil e capas de eventos são escolhidas do computador; formatos aceitos: PNG, JPG, WEBP e GIF, até 4 MB.
- Eventos têm horário de início e término (`HH:MM`).
- A área “Meus eventos” separa eventos criados e convites recebidos.
- Convites privados usam um token aleatório no link; a pessoa pode colar o link em “Meus eventos”.
- Senhas novas são armazenadas com `scrypt` e salt individual. Senhas antigas em texto puro são convertidas para hash no primeiro login bem-sucedido.
- Cookies de sessão usam `httpOnly` e `sameSite`; em produção também usam `secure`. Há cabeçalhos básicos de segurança e limitação temporária de tentativas de login.

### Configuração recomendada

Antes de publicar o projeto, defina as variáveis de ambiente `SESSION_SECRET` (uma chave longa e aleatória), `ADMIN_EMAIL` e `ADMIN_PASSWORD`. Não publique credenciais em repositórios. Em produção, substitua o armazenamento de sessão padrão por um armazenamento persistente e adicione proteção CSRF.

### Limitações que ainda existem

Os eventos, comentários e convites ainda são mantidos em memória pelo servidor, como já acontecia na versão anterior. Portanto, eles são perdidos quando o servidor reinicia, e os convites não são compartilhados entre instâncias diferentes. A próxima etapa importante é migrar eventos, comentários e convites para o SQLite. Esta versão melhora a proteção das contas, mas não deve ser considerada pronta para implantação pública sem essas etapas.
