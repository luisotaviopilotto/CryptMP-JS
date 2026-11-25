# Cryptmp — Node.js

Implementação em Node.js com `node:crypto` nativo (zero dependências).

Requer **Node 16+** (OpenSSL 1.1.1+, para `sha3-256` e `shake256`).

## Versão 2 (mudanças incompatíveis)

- O KDF agora é **scrypt**. O KDF da versão 1 não era memory-hard.
- Hashes `$th$1$` ainda verificam e `needsRehash` retorna `true` para eles.
- Hashes `$th$2$` ainda **não** são lidos pelas versões
  [**Go**](https://github.com/luisotaviopilotto/cryptmp-go) e
  [**Python**](https://github.com/luisotaviopilotto/cryptmp-py).
- `cost` agora é o log2 do `N` do scrypt: 14 a 20, padrão 17 (128 MiB).
- A opção `tolerance` foi removida; opções desconhecidas lançam erro.
- `computeHash` gera a versão 2 por padrão (passe `1` para a antiga).
- A CLI não aceita senha nem chave como argumento: a senha vem do stdin ou de
  um prompt oculto, a chave de `CRYPTMP_KEY`.
- Senhas com mais de 4096 caracteres são rejeitadas; `hash` rejeita senha vazia.
- Hashes só são aceitos na forma canônica (sem zeros à esquerda, hex minúsculo).
- `maxCost` (padrão: o maior entre `cost` e 17) limita o que um hash gravado
  pode exigir no `verify`. Ao **reduzir** o `cost`, informe o valor antigo em
  `maxCost`.
- `minVersion: 2` rejeita hashes da versão 1 depois da migração.
- Parâmetros inválidos, versão desconhecida e `keyring.add` com id repetido
  agora lançam erro.

## Instalação

```bash
npm install @luisotaviopilotto/cryptmp
```

> **A versão 2 descrita aqui ainda não foi publicada.** O comando acima e o
> repositório no GitHub entregam a versão 1, sem estas correções. Para usar a
> versão 2, instale a partir desta pasta, com o mesmo
> `require('@luisotaviopilotto/cryptmp')`:
>
> ```bash
> # a) direto da pasta do projeto
> npm install /caminho/para/cryptmp-js
>
> # b) via tarball (gera luisotaviopilotto-cryptmp-2.0.0.tgz)
> cd cryptmp-js && npm pack
> npm install /caminho/para/luisotaviopilotto-cryptmp-2.0.0.tgz
> ```

### Publicar no npm

```bash
cd cryptmp-js
npm login
npm publish --access public   # pacotes com escopo são privados por padrão
```

## Uso

```js
const th = require('@luisotaviopilotto/cryptmp'); // ou require('./cryptmp') local

// 1. Chave global de 32 bytes — de um segredo, nunca do banco.
const key = th.Key.fromHex(1, '…64 hex chars…'); // ou th.Key.generate(1)
const kr = new th.Keyring(key);

// 2. Hasher (calibre o custo).
const hasher = new th.Cryptmp(kr, { cost: 17 });

async function main() {
  // 3. Cadastro / login.
  const encoded = await hasher.hashAsync('minha_senha');        // grave no banco
  const ok = await hasher.verifyAsync('minha_senha', encoded);  // true

  // 4. Upgrade transparente.
  if (ok && hasher.needsRehash(encoded)) {
    // regrave await hasher.hashAsync('minha_senha')
  }
}
main();
```

> **Nunca remova o `await` de `verifyAsync`:** sem ele o retorno é uma
> `Promise`, sempre verdadeira num `if`, e qualquer senha passa.

Em servidor, use `hashAsync`/`verifyAsync`: `hash`/`verify` bloqueiam o event
loop (hashes da versão 1 bloqueiam mesmo na forma async).

**Limite a concorrência no seu app.** Cada operação usa `1 KiB * 2^cost` de
memória (128 MiB no padrão) e ocupa uma thread do pool do Node (4 por padrão,
dividido com `fs` e DNS). Com 16 logins simultâneos, medimos cerca de 512 MiB a
mais e um `fs.stat` esperando 1,2 s. Aplique rate limit no login e dimensione a
memória do servidor ou container.

### Rotação de chave

```js
const k1 = th.Key.fromHex(1, '…antiga…');
const k2 = th.Key.generate(2);
const kr = new th.Keyring(k2, k1);        // k2 ativa, k1 legada
const hasher = new th.Cryptmp(kr, { cost: 17 });
hasher.verify(pw, hashAntigo);            // acha k1 pelo keyid automaticamente
```

## CLI

```bash
export CRYPTMP_KEY=$(node bin/cryptmp.js gen-key)
IFS= read -rs SENHA   # sem histórico e sem aparar espaços
printf '%s' "$SENHA" | node bin/cryptmp.js hash --cost 17
printf '%s' "$SENHA" | node bin/cryptmp.js verify '$th$2$17$1$...'
```

Códigos de saída: `0` ok, `1` senha não confere, `2` erro.

Sem pipe, a CLI pede a senha num prompt oculto.

> **Windows PowerShell 5.1:** o pipe usa ASCII por padrão e troca acentos por
> `?`, fazendo senhas diferentes conferirem. Use o prompt (sem pipe) ou rode antes
> `$OutputEncoding = [Text.UTF8Encoding]::new($false)`.

Com o pacote instalado, o binário `cryptmp` fica disponível via `npx`:

```bash
npx cryptmp gen-key
```

## Testes

```bash
npm test        # ou: node test.js  (KAT + roundtrip)
```

Em `vectors.json`, `vectors` (versão 1) são idênticos aos das versões Go e
Python; `vectors_v2` são desta implementação.

## Modelo de segurança e limitações

- Só com o banco, sem a chave global, não há como testar senhas offline. Com o
  banco **e** a chave, cada tentativa custa um scrypt (versão 2).
- O hash não é ligado ao usuário: quem **escreve** no banco pode copiar o próprio
  hash para outra conta e entrar nela. Proteja a escrita.
- O campo `t` revela quando a senha foi definida (precisão de 30 s).
- `Keyring` não remove chaves. Para revogar uma chave vazada, crie outro
  `Keyring` sem ela e redefina as senhas de quem ainda não migrou.

> ⚠️ Construção educacional/de pesquisa, sem revisão de criptógrafo. Para
> produção prefira `argon2`/`scrypt`.
