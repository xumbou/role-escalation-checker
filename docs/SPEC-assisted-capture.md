# SPEC — Mode assisté : capture → suggest → watch

> Objectif : supprimer le travail manuel. Aujourd'hui l'opérateur écrit
> `engagement.yaml` à la main ET fournit le HAR à la main. Ce mode automatise
> la **récolte** (proxy → HAR live), l'**auto-détection** (JWT, paths, rôle admin
> → `engagement.yaml` généré) et le **scan continu** (watch en SAFE).
>
> Tout reste **non destructif** : `--exploit` n'existe que dans le checker
> standalone et reste 100 % manuel. Usage autorisé uniquement.

## Contraintes de sécurité — NON NÉGOCIABLES

1. **Scope guard préservé.** La capture ne dump QUE les hosts déclarés
   (`--allow-host`, répétable). Tout host hors scope est ignoré — jamais écrit
   dans le HAR, jamais une requête émise. Réutiliser la logique de
   `config.Config.host_allowed`.
2. **Jamais de mutation automatique.** `capture` et `watch` sont read-only /
   SAFE. `watch` force `safety.destructive = False` quoi que dise le YAML.
   Aucune des nouvelles commandes ne touche `--exploit`.
3. **Secrets / PII.** Le HAR brut contient tokens, cookies, mots de passe :
   - fichier HAR live créé en `0600` (os.open avec mode, ou os.chmod) ;
   - ajouter `*.har`, `engagement*.yaml`, `evidence_*.json` au `.gitignore` ;
   - réutiliser `redact.py` pour TOUTE sortie console/log (ne jamais afficher un
     token en clair) ;
   - en tête de l'`engagement.yaml` généré : commentaire « CONTIENT DES SECRETS —
     ne pas committer ».
4. **mitmproxy = dépendance optionnelle.** `import mitmproxy` UNIQUEMENT dans le
   module capture, derrière un try/except avec message d'install clair
   (`pipx inject role-escalation-checker mitmproxy` ou `pip install mitmproxy`).
   `scan` / `suggest` / `watch` doivent fonctionner SANS mitmproxy installé.

## Commande `capture`

`bacscan capture --allow-host H [--allow-host H2] [--port 8080] [--har-out traffic.har]`

- Lance mitmproxy programmatiquement. Implémenter un addon dans
  `bacscan/capture.py` exposant les hooks (`response(self, flow)`), monté via
  `mitmproxy.tools.dump.DumpMaster` (options `listen_port`, `mode`). Tourner
  l'event-loop asyncio jusqu'à Ctrl-C.
- Pour chaque flow dont `flow.request.host ∈ allow_hosts`, append une entrée
  **HAR 1.2** : `request` (method, url, headers, postData{mimeType,text}) ET
  `response` (status, headers, content{text,mimeType}). La réponse est
  indispensable pour détecter `list-path` et `admin-role`.
- Écriture incrémentale et **toujours valide** : maintenir un buffer d'entrées et
  réécrire atomiquement le wrapper `{"log":{"version":"1.2","creator":{...},
  "entries":[...]}}` à chaque flush (toutes les N entrées ou T secondes), via
  fichier temporaire + `os.replace`.
- Au démarrage, afficher : proxy à régler (`127.0.0.1:PORT`), et installer le CA
  (`http://mit.it` une fois le proxy actif). Rappeler le scope capté.

## Commande `suggest`

`bacscan suggest --har traffic.har [--out engagement.suggested.yaml] [--engagement NOM]`

Auto-détection (réutiliser `ingest.from_har` pour parser ; étendre si besoin pour
récupérer aussi la réponse — ajouter `from_har_full` qui garde status/response
body sans casser l'API existante) :

1. **JWT / user-id.** Scanner les headers `Authorization: Bearer <jwt>` (+ cookies
   de session). Pour chaque JWT distinct, décoder le payload (base64url du 2e
   segment, padding corrigé, SANS vérif de signature) et extraire les claims
   candidats : `sub`, `userId`, `user_id`, `uid`, `preferred_username`, `oid`,
   `upn`. Construire une liste de profils (1 par token distinct) : 1er = `attacker`.
2. **promote-path.** Candidats = method ∈ {POST,PUT,PATCH} ET path matchant
   `(?i)/(administrators?|admins?|roles?|members?|grants?|permissions?)(/|$)`.
   Scorer par spécificité (`administrators` > `grants` > `roles` > `members`).
   Templatiser : remplacer un segment id (uuid / entier / hex long) par
   `{user}` s'il suit un segment « user-like », sinon `{resource}` pour l'id de
   la collection ressource. Réutiliser les regex d'`ingest.py` / `harvest.py`.
3. **list-path.** GET dont le path matche `(?i)/(members|users|roles)(/|$)` et
   dont la réponse JSON est une liste d'objets porteurs d'un champ de rôle.
4. **role-field + admin-role.** Dans les réponses JSON, repérer les clés
   `(?i)^(role|roles|authority|authorities|type|level)$` et collecter leurs
   valeurs ; proposer comme `admin-role` les valeurs matchant
   `(?i)(admin|administrator|owner|superuser|root|manager)`. `role-field` = la clé
   qui les porte.
5. **Génération `engagement.yaml`** strictement conforme à `config.Config` :
   `engagement`, `base_url` (host le plus fréquent en scope), `scope.allow_hosts`,
   `profiles` (auth `bearer` + token + `ids.user_id`), `probes`
   (`idor, idor_dynamic, bfla, leakage`), `impact_plugins: [role_escalation]`,
   bloc `role_escalation` pré-rempli (`list_path`, `promote_path`, `admin_role`,
   `role_field` détectés), `output` (findings_db/report_md/triage_log/audit_log),
   `safety: {destructive: false}`. Charger le YAML généré avec
   `config.load_config` en fin de `suggest` pour garantir qu'il est valide.
6. **Sortie.** Écrire le YAML + afficher un récap (table) des détections avec un
   niveau de confiance (high/medium/low selon le score), et l'avertissement
   « VÉRIFIE `scope.allow_hosts` et les paths avant tout scan ». Insérer des
   commentaires `# TODO verifier` aux endroits incertains. **N'émet aucune
   requête réseau.**

## Commande `watch`

`bacscan watch --config engagement.yaml --har traffic.har [--interval 5] [--auto-suggest]`

- Surveille (mtime + taille) le HAR. À chaque changement (debounce `--interval`),
  re-parse, ne garde que les NOUVELLES requêtes (clé (method,url) déjà vues), et
  relance `cli.run()` en SAFE (`destructive` forcé à `False`) ; met à jour
  `findings_db` / `report_md`. Affiche un résumé incrémental (nouveaux confirmés).
- `--auto-suggest` : régénère aussi les suggestions quand de nouveaux endpoints /
  valeurs de rôle apparaissent. Ctrl-C propre.

## Intégration CLI

Passer `bacscan/cli.py` en **sous-commandes** argparse : `scan` (= comportement
actuel `--config/--har/--openapi/--access-matrix`), `capture`, `suggest`, `watch`.
Rétro-compat : si aucun sous-commande mais `--config` présent → agir comme `scan`.
Exposer le tout via `__main__.py`. Conserver `bacscan`, `python -m bacscan`,
`python -m bacscan.cli` équivalents.

## Tests (tests/)

- `test_suggest.py` : fixture HAR (JSON) avec un JWT **factice non-secret**, une
  réponse `members` contenant `role: ADMINISTRATOR`, et un
  `POST .../administrators/<id>` → asserte la détection de `promote_path`,
  `list_path`, `admin_role=ADMINISTRATOR`, `role_field=role`, `user_id` issu du
  JWT, et que le YAML généré est chargeable par `config.load_config`.
- `test_capture_har.py` : tester la fonction d'append/flush HAR en isolation (sans
  mitmproxy) avec des objets factices mimant un flow → HAR produit valide +
  filtrage de scope (host hors scope ignoré).
- `test_watch.py` : détection de changement + appel pipeline mocké (léger).
- Tous les tests doivent passer SANS mitmproxy installé (isoler l'addon ; tester
  la logique HAR pure). `pytest.importorskip("mitmproxy")` pour ce qui le requiert.
- Étendre `tests/run_checks.py` pour inclure les nouveaux tests.

## Dépendances / packaging

- `requirements.txt` : NE PAS ajouter mitmproxy en dur. Le documenter comme extra.
- `pyproject.toml` : extra `[capture] = mitmproxy`. Installer via
  `pipx inject role-escalation-checker mitmproxy`.

## Docs

- README : nouvelle section « Mode assisté » (capture → suggest → watch), les 3
  commandes, l'avertissement scope + secrets, l'install de l'extra capture.
- Mettre à jour `docs/ARCHITECTURE.md`.

## Anti-fuite (repo PUBLIC)

NE JAMAIS écrire dans ce repo le moindre nom d'hôte, d'organisation,
d'identifiant ou de donnée issus d'un engagement réel. Fixtures de test =
données synthétiques uniquement (`api.lab.local`, users factices, JWT bidon
signé `HS256` clé `test`). Grep des marqueurs d'engagement avant tout commit.
