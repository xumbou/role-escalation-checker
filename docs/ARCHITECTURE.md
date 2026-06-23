# Architecture — Scanner BAC/IDOR réutilisable cross-mission

> Spec d'architecture d'un outil de test d'**access control** (BOLA/IDOR, BFLA, BOPLA,
> privilege escalation) **réutilisable d'une mission de pentest à l'autre**.
> `check_role_escalation.py` (racine de ce repo) en est le **premier plugin de confirmation**.
> Document de conception — fondé sur un état de l'art outils + bug bounty + recherche académique.

---

## 0. Positionnement (ne pas réinventer la roue)

| Outil | Modèle | Ce qu'on emprunte | Ce qui manque pour nous |
|---|---|---|---|
| **apidor** (bm402) | 1 YAML par cible, 10 types de tests (hp/lp/np, param pollution, method replacement, param wrapping/substitution, json-ext), variables `high`/`low` | le **modèle config-driven** + le catalogue de mutations | IDOR-centric, pas de confirmation d'impact, pas d'intégration framework |
| **Akto** (OSS) | **traffic-driven** (lit HAR/Burp/Postman → moins de FP que Swagger seul), 1000+ tests **déclaratifs**, tests custom | l'idée **traffic-driven** + **bibliothèque de tests déclaratifs extensible** | plateforme lourde (Mongo, dashboard), pas pensée pour s'intégrer à *ton* `findings_db` |
| **Burp Autorize / Auth Analyzer / AuthMatrix** | rejeu multi-session interactif | le **moteur différentiel** (concept) | GUI, non scriptable/CI |
| **arXiv — oracles d'autorisation** | 7 oracles automatiques sur les status codes (asymétrie, existence leakage…) | le **moteur de verdict anti-FP** | besoin d'un fuzzer en amont, pas standalone |

**Notre niche** : un outil **léger, CLI/CI, config-YAML par mission**, dont le différenciateur est la
**confirmation d'impact par plugins** (le scan *trouve*, le plugin *prouve*), et qui **s'intègre au
framework existant** (`access_matrix.py` statique → candidats, `har_extract`/`normalize` → ingestion,
`findings_db`/`gen_report` → sortie). On ne refait pas Akto ; on fait le **chaînon manquant** entre la
recon statique et la preuve active.

---

## 1. Pipeline

```
ingestion ─► normalisation ─► profils d'auth ─► moteur différentiel (rejeu N profils)
   ─► sondes (IDOR / BFLA / BOPLA / verb-tamper) ─► oracles de verdict (anti-FP)
   ─► confirmation d'impact (plugins) ─► findings_db + rapport
```

---

## 2. Modules

### 2.1 Ingestion
- **Entrées** : HAR, export proxy/Burp, OpenAPI/Swagger, Postman.
- **Sortie** : `requests.jsonl` normalisé `{method, url, path_template, query, headers, body, content_type}`.
- **Réutilise** : `har_extract.py`, `normalize.py`.
- **Leçon Akto** : privilégier le **trafic réel** à l'OpenAPI seul → capte la business logic, réduit les FP.

### 2.2 Profils d'auth — **cœur de la réutilisabilité** (1 YAML par engagement)
- Abstraction de N identités (`anon`, `low`, `victimA`, `admin`…), chacune avec token (+ refresh optionnel)
  et ses identifiants (`userId`, `orgId`).
- **Leçon apidor** : variables `high`/`low` — on généralise à N profils.

### 2.3 Moteur différentiel
- Rejoue chaque requête × chaque profil → **matrice d'accès** `requête × profil → {status, taille, hash_corps, similarité}`.
- Verdict primaire : *2xx sous un profil qui ne devrait pas*.

### 2.4 Sondes (probes) — extensibles
- **IDOR/BOLA** : extraction d'IDs (path/query/body/headers/**JWT claims**) ; substitution cross-profil +
  énumération. Types d'IDs à couvrir (cf. bug bounty réels) : **séquentiels** (PayPal/Zomato), **UUID leakés**
  (Uber bulk lookup), **MD5/hashés crackables**, **org/tenant id** (Shopify — *= le pattern de promotion de rôle*).
- **BFLA** : force-browse d'endpoints privilégiés (wordlist `admin|manage|internal|valid|approve` — réutiliser
  `PRIV_PAT` de `access_matrix.py`) + **verb tampering** (GET→POST/PUT/PATCH/DELETE).
- **BOPLA / mass-assignment** : injecter des champs sensibles (`role`, `isAdmin`, `tenantId`, `form=ADMINISTRATOR`)
  dans les corps.
- **Mutations apidor** : parameter pollution / wrapping / substitution / json-extension.

### 2.5 Oracles de verdict (emprunt arXiv) — **réduction des faux positifs**
- **Asymétrie de modification** : si 2 de `{DELETE,PUT,PATCH}` → 403 et la 3ᵉ → 2xx ⇒ très probable misconfig.
- **Existence leakage** : 403 vs 404 divergents pour le même endpoint.
- **Anonymous modification** : `DELETE/PUT/PATCH` → 2xx **sans** auth.
- **Ignore-anonymous** : l'endpoint marche avec **et** sans creds.
- **Validation multi-conditions** (3 préconditions) avant de lever un finding.
- **Contrôles systématiques** (repris de `check_role_escalation.py`) : no-auth → 401, bogus-id → 404.

### 2.6 Confirmation d'impact (plugins) — **le différenciateur**
- Le moteur produit des *candidats* ; un **plugin par classe** prouve l'effet métier réel.
- Interface : `confirm(candidate, profiles) -> {is_real, impact, severity, evidence}`.
- **1er plugin = role-escalation** (`check_role_escalation.py` refactoré).
- Deux formats de plugin :
  - **Python** pour la logique métier (vérif d'état, diff avant/après) ;
  - **YAML déclaratif** (`filter → execute → validate`, inspiré d'Akto) pour les cas simples sans code.

### 2.7 Sortie / reporting
- Findings JSON normalisés → `findings_db.py` (ingestion directe).
- Mapping automatique **CWE / OWASP-API-Top10 / WSTG-ATHZ**.
- Matrice d'accès Markdown + evidence horodatée (repris de `check_*.py`) + **anonymisation des tokens**.

### 2.8 OpSec (transverse)
Scope guard (`--allow-host` obligatoire), **non-destructif par défaut**, rollback auto, rate-limit, dry-run.

---

## 3. Schéma du YAML d'engagement (exemple)

```yaml
engagement: acme-2026-06
base_url: https://api.example.com
scope:
  allow_hosts: [api.example.com]          # garde-fou dur
auth:
  header: Authorization
  prefix: "Bearer "
profiles:                                  # N identités (abstraction = réutilisabilité)
  - name: anon
    token: null
  - name: low
    token: ${LOW_JWT}
    ids: { userId: u-1001, orgId: o-50 }
  - name: victim
    token: ${VICTIM_JWT}
    ids: { userId: u-2002, orgId: o-77 }
safety:
  destructive: false                       # promotion mutatrice => exige un flag explicite
  rollback: auto
  rate_limit_rps: 3
probes: [idor, bfla, bopla, verb_tamper]
impact_plugins: [role_escalation]
output:
  findings_db: ../findings/_incoming_dyn.json
  report_md: reports/ACCESS-MATRIX-DYN.md
```

## 4. Format de sonde déclarative (exemple BOPLA)

```yaml
probe: bopla-role-injection
applies_to: { methods: [POST, PUT, PATCH], body: json }
inject_fields: { role: ADMINISTRATOR, isAdmin: true }
run_as: [low]
flag_if: { status_in: [200, 201, 204], and_field_echoed: true }
severity: high
maps: { cwe: CWE-639, owasp_api: API3:2023 }
```

---

## 5. Intégration avec le framework existant

- **`access_matrix.py` (statique)** produit des candidats « garde client seulement / aucune garde » →
  le scanner dynamique les **teste en priorité** et les **confirme** : couplage statique→dynamique =
  priorisation + anti-FP (on confirme une hypothèse, on ne fuzz pas à l'aveugle).
- **`har_extract` / `normalize`** → module d'ingestion.
- **`findings_db` / `gen_report`** → sortie et reporting.

## 6. Roadmap

| Étape | Contenu | Statut |
|---|---|---|
| **MVP** | ingestion HAR + profils YAML + moteur différentiel + sonde IDOR + plugin role-escalation + sortie `findings_db` | ✅ livré |
| **v1** | BFLA (force-browse + verb-tamper/asymétrie) + BOPLA (mass-assignment) + oracle existence-leakage + ingestion OpenAPI | ✅ livré |
| **v2** | couplage `access_matrix` statique→dynamique (loader générique `static_link.py`) | ✅ livré |
| **v3** | **auth pluggable** (bearer/cookie/**OAuth refresh**/**CSRF**), **IDOR dynamique** (chaînage/harvest) + **séquentiel**, plugins de confirmation **déclaratifs YAML**, **GraphQL** (introspection + IDOR via variables) | ✅ livré |
| **v4 (backlog)** | IDs encodés/hashés crackables, GraphQL mutations/BFLA, gRPC, durcissement terrain (pagination / WAF / gros HAR / throttling) | à faire |

> **OpSec renforcé** : le moteur différentiel et la sonde IDOR ne rejouent **plus** les verbes mutateurs en mode non-destructif. Les sondes BFLA verb-tamper / BOPLA, le plugin role-escalation et les plugins déclaratifs marqués `requires.destructive` exigent `safety.destructive: true` (avec rollback). L'auth gère le **refresh de token sur 401** et l'injection **CSRF** sur les verbes mutateurs.

### Modules d'auth (`auth.py`)
`Authenticator` par profil, construit depuis le bloc `auth:` du YAML (ou `token:` legacy) :
`bearer` (header+prefix), `cookie` (cookies de session), `oauth` (refresh sur 401 via un
endpoint d'échange), et `csrf` (récupère un token depuis un cookie/endpoint et l'injecte sur
POST/PUT/PATCH/DELETE). C'est le levier qui débloque les cibles réelles.

## 7. Décisions ouvertes
1. **Maison léger** (recommandé : contrôle + intégration framework) **vs au-dessus d'Akto** (plus rapide mais lourd/couplé) ?
2. Plugins de confirmation **Python** vs **YAML déclaratif** (probablement les deux) ?
3. Langage : **Python** (cohérence avec le framework existant).

---

*Sources : apidor (bm402), Akto (akto-api-security), OWASP API1:2023 BOLA, recherche oracles REST (arXiv 2604.00702), top-25 IDOR bug bounty reports (PayPal/Uber/Shopify/Zomato/Ubiquiti).*
