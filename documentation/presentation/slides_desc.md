# Discours oral — Eviden KMS (16 diapositives)

> **Usage** : ce fichier est le script de présentation orale. Chaque section donne le fond à dire,
> pas la description de la diapositive. Les passages en **gras** sont les points à marteler.
> Durée cible : ~2 min par diapositive, soit ~32 min au total.

---

## Diapositive 1 — Titre

Bienvenue. Nous allons parler d'Eviden KMS — un système de gestion de clés qui fait partie
du portefeuille de cybersécurité d'Eviden, l'entité issue de la division sécurité d'Atos.

**Ce n'est pas un KMS de plus.** L'Eviden KMS a été conçu depuis le départ pour répondre à trois
besoins simultanément : gérer des clés, servir d'oracle de chiffrement à grande échelle, et faire
office d'autorité de certification (PKI) — y compris post-quantique.

Il est écrit entièrement en Rust, un language à mémoire sûre qui élimine par construction toute une
classe d'attaques (buffer overflow, use-after-free). C'est un argument de sécurité intrinsèque,
pas un argument marketing.

Le code source est disponible sure GitHub sous licence BSL 1.1 : n'importe quelle équipe sécurité
peut l'auditer. Et il est **100 % développé en Union européenne**, ce qui compte pour les marchés
publics et les exigences NIS2.

---

## Diapositive 2 — Qu'est-ce qu'Eviden KMS ?

Commençons par ce que fait réellement ce produit, parce que "KMS" recouvre des réalités très
différentes selon les éditeurs.

**Premier rôle : gestionnaire de cycle de vie des clés.** Toute clé — symétrique AES, paire
asymétrique RSA/EC, certificate X.509 — est créée, activée, révoquée et détruite dans le KMS.
Le cycle de vie KMIP (Pre-Active → Active → Deactivated → Destroyed) garantit qu'une clé ne peut
pas être utilisée hors de sa fenêtre d'authorisation.

**Deuxième rôle : hub d'interopérabilité.** KMIP 1.0 à 2.1 en binaire et JSON, intégrations
cloud natives (AWS XKS, Azure EKM/DKE, Google CSE/CMEK), et chiffrement transparent de bases
de données (Oracle, PostgreSQL/EDB/IRIS, MongoDB, MySQL via TDE ou CSFLE). Quel que soit votre
écosystème — Synology, FortiGate, VMware, AWS, Azure, GCP — il y a un connecteur natif.
Une seule instance KMS couvre tous les fournisseurs, tous les protocols, toutes les bases.

**Troisième rôle : point HSM.** Toutes les clés applicatives sont enveloppées par des clés
maîtres qui ne quittent jamais le matériel — Proteccio, Crypt2Pay, Utimaco, Nitrokey. Au
runtime, le KMS désenveloppe à la demande via PKCS#11 ; le HSM n'est jamais exposé
directement aux applications.

La documentation officielle est disponible sure docs.cosmian.com. Le protocole de transport est
KMIP en binaire sure le port 5696, ou JSON sure le port 9998 via REST — ce qui simplifie
l'intégration dans des architectures existent.

---

## Diapositive 3 — Pourquoi Eviden KMS ?

Il existe d'autres KMS sure le marché. Voilà pourquoi celui-ci se distingue.

**La performance d'abord.** Rust donne un avantage réel : pas de garbage collector, zéro copie
inutile en sérialisation, modèle async non-bloquant. Le KMS peut paralléliser les opérations
sure tous les cœurs disponibles et traiter des milliers de requêtes concurrentes sans dégrader
la latence. C'est critique pour les cas où le KMS est dans le chemin critique de chaque requête
applicative.

**La conformité FIPS 140-3 par défaut.** Ce n'est pas une option activable après coup. C'est le
mode de compilation par défaut. Le provider OpenSSL FIPS est chargé au démarrage via un
`OnceLock` pour garantir une initialisation atomique. Pour les environments non-FIPS
(algorithms post-quantiques, FPE, ChaCha20), on compile avec `--features non-fips`.

**L'interopérabilité.** KMIP 1.0 à 2.1 en binaire et JSON, module PKCS#11 natif, client WASM,
OpenAPI 3.1 avec Swagger UI. Quel que soit votre écosystème — Oracle, MongoDB, Synology,
FortiGate — il y a un connecteur.

**L'architecture HSM-first.** Les clés applicatives sont enveloppées par des clés maîtres qui
ne quittent jamais le HSM. Au runtime, le KMS désenveloppe à la demande, absorbe la charge
concurrente, et le HSM n'est jamais exposé directement.

---

## Diapositive 4 — Architecture système

Ce diagramme montre le chemin complete d'une requête KMIP depuis le réseau jusqu'aux primitives
cryptographiques.

**L'entrée** : HTTP/TLS sure Actix-web, le framework Rust le plus performant du marché. La
désérialisation TTLV (le format binaire KMIP) est faite à zéro copie. Un dispatcher associe
le tag KMIP à la function Rust correspondante.

**Le cœur** : la struct `KMS` concentre trois resources — la base de données, les oracles
cryptographiques, et les connexions HSM. C'est délibérément stateless : aucun état par session,
aucun verrou global. Chaque nœud peut traiter n'importe quelle requête.

**La base de données** : SQLite pour le développement, PostgreSQL ou MySQL/Percona en production,
Redis-findex pour le chiffrement full-index en mode non-FIPS. La base stocke les clés chiffrées
(enveloppées), jamais en clair.

**Les primitives crypto** : le crate `cosmian_kms_crypto` construit OpenSSL 3.6.2 depuis les
sources à la compilation, avec SHA-256 vérifié. Pas de dépendance à une OpenSSL système
qui pourrait être compromise ou mal configurée.

**Les HSM** : connexion via PKCS#11 standardisé. Le KMS charge le module du vendeur (Utimaco,
Proteccio, Nitrokey…) au démarrage et l'utilise pour envelopper/désenvelopper les clés maîtres.

---

## Diapositive 5 — Algorithms supportés

Deux univers coexistent dans l'Eviden KMS.

**Le monde FIPS** est ce que vous déployez par défaut en production. AES-GCM est le cheval de
bataille : 128, 192 ou 256 bits, nonce aléatoire de 12 octets, tag d'authentication de 16
octets. Parfait pour la grande majorité des besoins. AES-XTS est réservé au chiffrement de
disque (secteurs de taille fixe). L'enveloppement de clés suit la RFC 3394 (AES-KW) et la
RFC 5649 (AES-KWP avec padding), recommandées par le NIST SP 800-38F.

**Le monde post-quantique** est accessible en mode non-FIPS. Trois familles issues des standards
NIST 2024 :

- **ML-KEM** (FIPS 203) : encapsulation de clés. Remplace ECDH dans les protocols
  d'établissement de session.
- **ML-DSA** (FIPS 204) : signatures. Remplace ECDSA et RSA pour les certificates et les
  JWTs à long terme.
- **SLH-DSA** (FIPS 205) : signatures sans état, à base de hash. Très conservateur, utile
  pour signer des artefacts à durée de vie très longue (10-30 ans).

**La stratégie hybride** est recommandée pendant la transition : ML-KEM-768 + X25519 combine
la sécurité quantique de ML-KEM avec la sécurité éprouvée de X25519. Si l'un est cassé,
l'autre protège encore.

---

## Diapositive 6 — Support du protocole KMIP

KMIP est le standard OASIS pour l'interopérabilité entre KMS et applications. Son objectif est
d'éliminer les intégrations propriétaires redondantes : un seul protocole pour Oracle, MongoDB,
Synology, VMware, FortiGate, etc.

**L'Eviden KMS supporte toutes les versions de KMIP de 1.0 à 2.1.** Concrètement, cela signifie
que vous pouvez connecter un Synology DSM (KMIP 1.2) et un Snowflake (KMIP 2.1) au même KMS,
sans configuration particulière. Le serveur détecte automatiquement la version du client.

**Le profil Baseline Server est entièrement conforme** : les 9 opérations obligatoires
(Create, Register, Get, Locate, Destroy, Activate, Revoke, Query, Discover Versions)
plus les 18 opérations optionnelles recommandées — tout est implémenté.

**Deux encodages sont disponibles :**

- TTLV binaire sure le port 5696 (TLS, authentication par certificate client) — pour les
  performances maximales et les clients industries.
- JSON sure le port 9998 via REST — pour les développeurs, les tests, et les intégrations
  légères. Le Swagger UI à `/swagger-ui` permet d'explorer l'API interactivement.

Toutes les communications internes utilisent KMIP 2.1 : le serveur traduit à la volée vers la
version demandée par le client. Cela garantit la pérennité : on peut migrer vers KMIP 2.1
progressivement, client par client.

---

## Diapositive 7 — Cycle de vie des clés

Le cycle de vie KMIP est la colonne vertébrale de la gouvernance des clés. Comprendre ce
diagramme, c'est comprendre comment l'Eviden KMS enforce les politiques de sécurité.

**Pre-Active** : la clé existe en base (chiffrée), mais aucune opération cryptographique n'est
autorisée. Utile pour préparer une rotation : on crée la nouvelle clé avant de basculer, sans
risque d'utilisation prématurée.

**Active** : toutes les opérations sont premises. C'est l'état normal de production.

**Deactivated** : on peut encore déchiffrer des données chiffrées avec cette clé (pour la
rétro-compatibilité), mais on ne peut plus l'utiliser pour chiffrer de nouvelles données.
C'est l'état intermédiaire de rotation : la nouvelle clé est Active, l'ancienne est Deactivated.

**Compromised** : la clé est considérée comme potentiellement exposée. On peut encore tenter de
déchiffrer des données pour une analyse forensique, mais aucune nouvelle opération n'est premise.
C'est un état d'urgence qui déclenche normalement une procédure d'incident.

**Destroyed** : la matière clé est zéroïsée. L'identifiant est conservé en base pour la piste
d'audit — on peut savoir qu'une clé a existé et quand elle a été détruite, sans en connaître
le contenu.

Le contrôle d'accès est granulaire : chaque object a un propriétaire, et les permissions
(lire, utiliser, gérer) peuvent être déléguées par utilisateur ou par groupe. La multi-tenancy
est enforced au niveau base de données : un tenant ne peut jamais voir les objects d'un autre.

---

## Diapositive 8 — Intégrations cloud

Voici la question que posent tous les RSSI : *si mes données sont dans le cloud, qui contrôle
vraiment les clés ?*

Il existe plusieurs modèles de réponse, et l'Eviden KMS les implémente tous.

**Le modèle live proxy (XKS, EKM, CSE, DKE)** est le plus fort. La clé ne quitte JAMAIS
le périmètre du KMS. AWS, Google ou Microsoft doivent appeler votre KMS pour chaque opération
de chiffrement ou déchiffrement. Si vous coupez l'accès au KMS, les données dans le cloud
deviennent immédiatement inaccessibles — même pour le fournisseur cloud.

**Le modèle BYOK** est moins fort : vous générez la clé dans votre KMS, vous l'importez dans
le cloud, le cloud en garde une copie. Vous avez le contrôle du processus de génération, mais
pas la guarantee que votre clé n'est pas utilisée à votre insu.

**La puissance du XKS et de l'EKM** tient dans leur universalité : une seule intégration KMS
couvre automatiquement tous les services AWS ou GCP compatibles. Vous activez XKS une fois,
et S3, EBS, RDS, DynamoDB, Secrets Manager — tout passe par votre KMS sans configuration
supplémentaire par service.

Pour les cas de souveraineté numérique et de conformité réglementaire stricte (NIS2 critiques,
secret défense, données de santé), le modèle live proxy est la seule option viable.

---

## Diapositive 9 — AWS XKS et Azure DKE

Approfondissons deux intégrations particulièrement importantes.

**AWS XKS** : quand un service AWS a besoin de chiffrer ou déchiffrer une donnée, AWS KMS
reçoit la demande, puis la délègue à votre Eviden KMS via l'API XKS Proxy. AWS KMS agit comme
un relais — il ne peut rien faire sans la réponse de votre KMS. La clé de chiffrement ne
réside jamais dans l'infrastructure AWS. Résultat pratique : une ordonnance judiciaire américaine
(subpoena) visant AWS ne peut pas forcer la divulgation de vos données, puisqu'AWS ne détient
pas les clés.

**Azure DKE (Double Key Encryption)** fonctionne différemment. Microsoft 365 chiffre les
documents avec deux clés : une clé Microsoft (stockée dans Azure Key Vault), et votre clé
Eviden KMS. Pour déchiffrer, les DEUX clés sont nécessaires. C'est un vrai contrôle dual :
ni Microsoft seul, ni vous seul ne pouvez déchiffrer un document. C'est particulièrement
adapté aux données ultra-sensibles — propriété intellectuelle, données de dirigeants, documents
juridiques sous NDA.

Un point important : DKE est disponible uniquement dans les licences Microsoft 365 E5 ou les
modules de conformité avancés. C'est une fonctionnalité enterprise, pas grand public.

---

## Diapositive 10 — Intégrations bases de données

La protection des données à la source — c'est-à-dire directement dans les bases de données —
est une exigence croissante des réglementations (PCI-DSS niveau 1, HIPAA, RGPD article 32).

**Le chiffrement transparent (TDE)** est le mécanisme le plus courant. La base de données
chiffre ses fichiers de données en utilisant une clé stockée dans un KMS externe. Si quelqu'un
vole le disque ou la sauvegarde, sans accès au KMS les données sont illisibles.

**L'intégration Oracle** utilise le module PKCS#11 de l'Eviden KMS. Oracle TDE appelle le
module comme un HSM logiciel. La clé maître de chiffrement Oracle (TDE Master Key) est
enveloppée et stockée dans l'Eviden KMS, jamais en clair dans le wallet Oracle.

**MongoDB CSFLE (Client-Side Field Level Encryption)** va plus loin : le chiffrement est fait
côté application avant d'envoyer les données à MongoDB. L'Eviden KMS fournit les clés via KMIP
1.0. Même l'administrateur MongoDB ne peut pas lire les champs chiffrés — y compris les
champs interrogeables grâce au Queryable Encryption.

**EDB Postgres Advanced Server TDE** (versions 15.2+ et 17.x) s'intègre via KMIP 2.1 en mTLS.
EDB utilise un script Python embarqué (`edb_tde_kmip_client.py`) invoqué par les variables
`PGDATAKEYWRAPCMD` et `PGDATAKEYUNWRAPCMD`. À l'`initdb`, Postgres génère un DEK aléatoire,
l'envoie au KMS via KMIP Encrypt (AES-256-CBC), et stocke le DEK enveloppé. À chaque démarrage,
le KMS désenveloppe le DEK à la demande. L'intégration fonctionne en mode **non-FIPS** (la
librairie PyKMIP d'EDB utilise `ssl.wrap_socket` non certifié FIPS).

**InterSystems IRIS** supporte le chiffrement de base de données via KMIP 2.0 en mTLS. IRIS
se connected à l'Eviden KMS sure le port 5696 pour créer, récupérer et gérer des clés symétriques
utilisées pour chiffrer les fichiers de base de données sure disque. La configuration côté IRIS
se fait via `^SECURITY` (gestionnaire de sécurité IRIS) ou `^EncryptionKey`. Comme pour EDB,
cette intégration fonctionne en mode **non-FIPS**.

**La séparation des rôles** est le bénéfice architectural majeur : les DBAs administrent les
données, les équipes sécurité administrent les clés dans le KMS. Ces deux périmètres sont
étanches, ce que les auditeurs de conformité apprécient particulièrement.

---

## Diapositive 11 — Stockage et chiffrement disque

Les usages de chiffrement ne se limitent pas aux bases de données. Le module PKCS#11 de
l'Eviden KMS ouvre l'accès à un écosystème beaucoup plus large.

**VeraCrypt et LUKS** utilisent le module PKCS#11 pour stocker leurs clés de chiffrement de
volume dans le KMS plutôt que sure le disque lui-même. La clé n'est jamais présente localement —
le volume ne peut être monté que si le KMS est accessible. C'est un contrôle d'accès
décentralisé appliqué au chiffrement de disque.

**VMware vCenter** avec le Trust Key Provider (KMIP 1.1) permet de chiffrer les VMDKs (disques
de machines virtuelles) avec des clés gérées par le KMS. En cas de saisie physique d'un
hyperviseur, les VMs sont illisibles sans accès au KMS.

**Veeam Backup** chiffre ses sauvegardes avec des clés KMIP 1.4 stockées dans l'Eviden KMS.
C'est critique : une sauvegarde non chiffrée est souvent le vecteur de fuite le plus négligé.
Avec cette intégration, une sauvegarde volée n'est d'aucune utilité sans le KMS.

**FortiGate** se connected au KMS via KMIP 1.0–1.4 pour gérer ses clés de chiffrement réseau.
C'est un example d'intégration avec une appliance réseau physique — le KMS n'est pas réservé
aux architectures cloud.

---

## Diapositive 12 — Support HSM

Les HSM (Hardware Security Modules) offrent la plus haute guarantee de sécurité matérielle pour
les clés. L'Eviden KMS les intègre d'une manière qui préserve leurs bénéfices tout en
contournant leur principale limitation : la performance.

**Le problème des HSM seuls** : un HSM de milieu de gamme fait 2 000 à 10 000 opérations RSA
par second. Pour une application qui traite des milliers de requêtes concurrentes, le HSM
devient un goulot d'étranglement catastrophique.

**La solution** : le KMS stocke les clés applicatives chiffrées (enveloppées) dans sa base.
Au démarrage ou au premier accès, le KMS déchiffre chaque clé applicative en demandant au HSM
de désenvelopper la clé maître. La clé applicative est alors en mémoire RAM du KMS,
disponible pour les milliers de requêtes suivantes — sans retourner au HSM.

**Résultat** : la sécurité du HSM "à la création" et "au repos", la performance du KMS "à
l'exécution". C'est le meilleur des deux mondes, documenté explicitement dans l'architecture
d'Eviden.

Les HSM supportés couvrent les principaux vendeurs du marché européen : Trustway Proteccio et
Crypt2Pay (groupe Atos/Eviden), Utimaco, Nitrokey HSM 2 / SmartCard-HSM. SoftHSM2 est
disponible pour les environments de développement et les tests CI/CD.

---

## Diapositive 13 — Infrastructure à clé publique (PKI)

L'Eviden KMS est une PKI complète. Ce n'est pas une fonctionnalité secondaire — c'est un
cas d'usage de premier plan documenté en détail dans la documentation officielle.

**Ce que ça veut dire concrètement :** vous pouvez utiliser l'Eviden KMS pour remplacer
une PKI basée sure OpenSSL + scripts, ou comme PKI interne d'enterprise, avec une interface
Web, une API KMIP, et une gestion des certificates intégrée à la gestion des clés.

**Les certificates post-quantiques** sont le point différenciant majeur. L'Eviden KMS est l'un
des rares KMS à implémenter nativement les RFCs IETF pour les certificates PQC :

- RFC 9881 pour ML-DSA dans X.509 (FIPS 204)
- RFC 9909 pour SLH-DSA dans X.509 (FIPS 205)
- RFC 9935 pour ML-KEM dans X.509 (FIPS 203)

**La PKI inter-algorithms** permet de construire des chaînes de certification hybrids :
une CA racine RSA 4096 peut émettre des certificates ML-DSA-44 pour les feuilles post-quantiques.
Ou inversement, une CA ML-DSA peut émettre des certificates RSA pour la rétro-compatibilité.
C'est exactement le scénario de migration recommandé par le NIST.

**Attention au cas ML-KEM** : ML-KEM est un mécanisme d'encapsulation de clés (KEM), pas
une signature. Un certificate ML-KEM ne peut pas être auto-signé — il doit toujours être
émis par une CA de signature (RSA, EC, ML-DSA). Le KMS enforce cette contrainte automatiquement.

---

## Diapositive 14 — Anonymisation et chiffrement préservant le format

Cette fonctionnalité répond à un besoin précis : comment utiliser des données sensibles pour
des analyses, des tests ou du développement, sans exposer les vraies valeurs ?

**Le chiffrement préservant le format (FPE FF1)** est la réponse pour les données structurées.
Un numéro de carte bancaire à 16 chiffres est chiffré en un autre nombre à 16 chiffres.
La structure est préservée, le type de colonne SQL reste `VARCHAR(16)`, les requêtes
applicatives fonctionnent à l'identique. C'est une migration vers le chiffrement qui ne
nécessite aucun changement de schéma.

**Le hachage** (SHA-2, SHA-3, Argon2) est pour les identifiants à sens unique : vous stockez
le hash d'un numéro de sécurité sociale pour faire des jointures sans jamais stocker le vrai
numéro. Argon2 est spécifiquement conçu pour résister aux attaques par dictionnaire sure
des valeurs à faible entropie.

**Le bruit différentiel** (Laplace, Gaussien) est la technique recommandée pour publier des
statistiques sure des données sensibles. On ajoute un bruit calibré qui préserve la distribution
statistique mais rend impossible la reconstruction de valeurs individuelles. C'est le fondement
de la *differential privacy*, utilisée par Apple, Google et le recensement américain.

**La tokenisation** remplace une valeur par un token opaque. Contrairement au chiffrement,
le token n'a aucune relation mathématique avec la valeur originale — l'attaquant qui obtient
le token n'apprend rien, même s'il connaît l'algorithm.

---

## Diapositive 15 — Haute disponibilité

L'Eviden KMS est conçu pour être stateless. C'est le choix architectural fondamental qui rend
la haute disponibilité triviale à opérer.

**Pourquoi stateless ?** Parce que l'état (les clés, les attributes, les politiques d'accès)
est dans la base de données partagée. Un nœud KMS peut être redémarré, remplacé, ou ajouté
à tout moment sans coordination entre nœuds. Il n'y a pas de leader election, pas de
synchronisation de session, pas de "sticky session" côté load balancer.

**L'architecture de référence** utilise HAProxy en TCP passthrough (le TLS est déchiffré par
les nœuds KMS, pas par le load balancer — ce qui préserve l'authentication mTLS bout en bout)
et Keepalived pour la VIP VRRP entre deux load balancers.

**Les temps de basculement** sont importants à connaître pour les SLAs :

- Perte d'un nœud KMS : ~9 secondes (cycle de health check HAProxy)
- Perte du load balancer actif : ~2 secondes (VRRP bascule la VIP)
- Ajout d'un nouveau nœud : 0 second côté client (il suffit d'ajouter le nœud dans la
  config HAProxy, les clients ne voient rien)

**La base de données est le seul état partagé.** C'est donc le seul point critique de la
haute disponibilité. Les recommendations opérationnelles sont claires : PostgreSQL en mode
primary/replica avec streaming replication, ou une solution cloud managée (RDS, Cloud SQL,
Azure Database for PostgreSQL). Les sauvegardes régulières et les tests de restoration
sont obligatoires.

---

## Diapositive 16 — Démarrer avec Eviden KMS

Conclure par l'action : comment passer de cette présentation à un premier test en moins de
cinq minutes ?

**Docker est le chemin le plus rapide.** Une seule commande lance un KMS opérationnel en mode
SQLite, avec l'interface Web accessible immédiatement sure `http://localhost:9998/ui`. C'est
suffisant pour explorer les fonctionnalités, tester les intégrations, écrire les premiers
appels KMIP.

**Pour la production**, les paquets Debian/RPM sont disponibles sure `package.cosmian.com/kms/`
pour les déploiements on-premise. Les images Marketplace sont disponibles sure AWS, Azure et GCP
pour les déploiements cloud — pre-configurées avec les bonnes politiques de sécurité réseau.

**Le CLI `ckms`** est le couteau suisse de l'Eviden KMS. Il couvre toutes les opérations :
gestion des clés, chiffrement, déchiffrement, PKI, anonymisation, gestion des accès. Il est
installable via `cargo install ckms` ou téléchargeable directement depuis le site.

**L'API Swagger** à `/swagger-ui` est le meilleur point d'entrée pour les développeurs : elle
permet d'explorer et tester toutes les opérations KMIP directement dans le navigateur,
sans écrire une ligne de code.

Pour aller plus loin : `docs.cosmian.com/key_management_system/` contient la documentation
complète, les guides d'intégration par produit, et les tutorials. Le code source sure
`github.com/Cosmian/kms` permet d'ouvrir des issues, de suivre les roadmaps et de contribute.
