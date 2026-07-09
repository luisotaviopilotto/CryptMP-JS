# Cryptmp — Node.js

Implementação em Node.js com `node:crypto` nativo (zero dependências).
Interoperável com as versões
[**Go**](https://github.com/luisotaviopilotto/cryptmp-go) e
[**Python**](https://github.com/luisotaviopilotto/cryptmp-py): um hash gerado
aqui verifica lá e vice-versa, com a mesma chave global.

Requer **Node 16+** (OpenSSL 1.1.1+, para `sha3-256` e `shake256`).

## Instalação

```bash
npm install @luisotaviopilotto/cryptmp
```

> O comando acima só funciona depois que o pacote estiver **publicado no npm**.
> Enquanto não publicar, dá para instalar do jeito local — mesmo nome, mesmo
> `require('@luisotaviopilotto/cryptmp')`:
>
> ```bash
> # a) direto da pasta do projeto
> npm install /caminho/para/cryptmp-js
>
> # b) via tarball (gera luisotaviopilotto-cryptmp-1.0.0.tgz)
> cd cryptmp-js && npm pack
> npm install /caminho/para/luisotaviopilotto-cryptmp-1.0.0.tgz
>
> # c) direto do GitHub
> npm install git+https://github.com/luisotaviopilotto/cryptmp-js.git
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
const hasher = new th.Cryptmp(kr, { cost: 12 });

// 3. Cadastro / login.
const encoded = hasher.hash('minha_senha');          // grave no banco
const ok = hasher.verify('minha_senha', encoded);    // true

// 4. Upgrade transparente.
if (ok && hasher.needsRehash(encoded)) {
  // regrave hasher.hash('minha_senha')
}
```

### Rotação de chave

```js
const k1 = th.Key.fromHex(1, '…antiga…');
const k2 = th.Key.generate(2);
const kr = new th.Keyring(k2, k1);        // k2 ativa, k1 legada
const hasher = new th.Cryptmp(kr, { cost: 12 });
hasher.verify(pw, hashAntigo);            // acha k1 pelo keyid automaticamente
```

## CLI

```bash
export CRYPTMP_KEY=$(node bin/cryptmp.js gen-key)
printf 'minha_senha' | node bin/cryptmp.js hash --cost 12
node bin/cryptmp.js verify '$th$1$12$1$...' 'minha_senha'
```

Com o pacote instalado, o binário `cryptmp` fica disponível via `npx`:

```bash
npx cryptmp gen-key
```

## Testes

```bash
npm test        # ou: node test.js  (KAT + roundtrip)
```

Os vetores em `vectors.json` são idênticos aos das versões Go e Python.

> ⚠️ Construção educacional/de pesquisa, não auditada. Para produção prefira
> `argon2`/`scrypt`. Modelo de segurança e limitações no
> [README do cryptmp-go](https://github.com/luisotaviopilotto/cryptmp-go#limitações-de-segurança).
