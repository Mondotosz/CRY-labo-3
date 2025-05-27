#import "@preview/ilm:1.4.1": *
#import "@preview/gentle-clues:1.2.0": *
#import "@preview/codly:1.3.0": *
#import "@preview/codly-languages:0.1.8": *

#show: ilm.with(
  title: [Rapport Labo 3],
  author: "Kenan Augsburger",
  date: datetime.today(),
)

#codly(
  languages: (
    pseudocode: (
      name: "pseudocode",
      icon: text(font: "JetBrainsMono NFP", "ⓟ "),
      color: rgb("#89caff")
    )
  )
)

#show: codly-init.with()
#codly(languages: codly-languages)

#show link: underline
#show raw: set text(font: "JetBrainsMono NFP")

#let red(x) = text(
  fill: color.red,
  $#x$
)

= CRY: Labo 03

== "Encryption"

=== Schema

#task([
  fill
])

=== Description mathématique

==== Chiffrement

On pose:
- $p,q in ZZ$ deux nombres premiers de 1024 bits tel que $p equiv.not 3 (mod 4)$ et $q equiv.not 3 (mod 4)$
- $n = p dot q$ 
- $lambda = 128$ le nombre de bytes aléatoires
- $r in {0,1}^(8 dot lambda)$ 128 bytes aléatoires
- $l = floor((log_2(n))/8) - lambda$ la longueur du message en bytes
- $"pad"$ un padding utilisant la norme iso7816

Ce qui nous permet de calculer le cipher avec:
$
c &= (((m || "pad") xor "mgf"(r,l)) || r)^2 space (mod n)
$

==== Déchiffrement

Pour déchiffrer, on connait initialement $p,q,c, lambda$. On peut facilement $n$
et $l$ 

Pour la première étape, on cherche à enlever le carré. $n$ est bien trop grand
pour que l'on puisse calculer les racines, mais on est tout de même capable de
les trouver en passant par le théorème des restes chinois.

On pose:

$
ZZ^*_n &-> ZZ^*_p times ZZ^*_q\
c mod n &=> cases(
  c = alpha^2 mod p,
  c = beta^2 mod q
)\
X &= {plus.minus alpha(q^(-1) mod p)q plus.minus beta(p^(-1) mod q)p space (mod n)}
$

On va obtenir trouver 4 racines et on sait que:
$
  ((m || "pad") xor "mgf"(r,l)) || r space (mod n) in X
$

Donc pour chaque valeur dans $X$, on va tester les étapes suivantes:

1. on split la racine en deux avec la partie gauche de taille $l$ et la partie
  droite de taille $lambda$
  $
  x &in X\
  ((m || "pad") xor "mgf"(r,l), r) &= "split"(x,l)
  $
2. On connait $r$ et $l$, on arrive donc à calculer $"mgf"(r,l)$
  $
  m || "pad" &= ((m || "pad") xor "mgf"(r,l)) xor "mgf"(r,l)
  $
3. Vu que le message contient un padding aux normes iso7816, on peut utiliser la
  fonction unpad pour récupérer le message ou faire remonter une erreur si le
  padding est incorrect. (Le padding sera incorrect si l'on utilise la mauvaise
  racine. Donc on va itérer sur nos racines jusqu'à trouver la bonne ou les
  exhauster.)
  $
  m &= "unpad"(m || "pad")
  $

On peut représenter le déchiffrement par la formule suivante:

$
m equiv ((sqrt(c) - r) xor "mgf"(r,l)) - "pad" space (mod n)
$

#info(title: "Note", [
  En représentant un une seule formule, on perd la notion des 4 racines à tester
  ainsi que le "split" et "unpad" qui sont représentés par un simple $minus$ 
  indiquant l'extraction de ces valeurs
])

=== Test de l'implémentation du déchiffrement

Pour tester l'implémentation, on chiffre un message avec une clé que l'on génère
puis on vérifie que la fonction de déchiffrement nous donne bien le message
original.

On est obligés de connaitre les valeurs $p$ et $q$ pour déchiffrer sinon on ne
peut pas trouver nos racines.

```py
def main():
    (p, q, n) = keyGen()
    m = b"Your heart's been aching but you're too shy to say it."
    c = encrypt(m, n)
    res = decrypt(c, p, q)
    if m == res:
        print("success")
        print(res)
    else:
        print(f"found : {res}")
```

=== Cassage grace aux racines

Dans cette attaque, on connait:
- $n$: le modulo
- $(m,c)$: un message et son cipher
- $x_1, x_2, x_3, x_4$: les quatre racines carrées du text chiffré.

$
cases(
c &equiv x_1^2 space (mod n) & -> cases(
    x_1 &= plus lambda_p space (mod p)\
    x_1 &= plus lambda_q space (mod q)
  )\
c &equiv x_2^2 space (mod n) & -> cases(
    x_2 &= plus lambda_p space (mod p)\
    x_2 &= minus lambda_q space (mod q)
  )\
c &equiv x_3^2 space (mod n) & -> cases(
    x_3 &= minus lambda_p space (mod p)\
    x_3 &= plus lambda_q space (mod q)
  )\
c &equiv x_4^2 space (mod n) & -> cases(
    x_4 &= minus lambda_p space (mod p)\
    x_4 &= minus lambda_q space (mod q)
  )
)
$

On sait que dans nos $4$ racines, on a des paires $(x_i, x_j)$ où $x_i equiv -x_j space (mod n)$

Cependant, on a besoins d'une paire qui ne respecte pas cette condition car notre
but est de pouvoir isoler $p$ ou $q$.

$
x_1 space (mod n) &equiv (+lambda_p space (mod p), +lambda_q space (mod q))\
x_2 space (mod n) &equiv (+lambda_p space (mod p), -lambda_q space (mod q))\
x_1 plus x_2 space (mod n) &equiv (2 lambda_p space (mod p), 0 space (mod q))
$

On arrive a avoir une composante a $0$ et si l'on utilise le théorème des restes
chinois on trouve que $x_1 + x_2$ est divisible par $q$

$
x_1 plus x_2 &equiv 2lambda_p (q^(-1) mod p) dot q + 0(p^(-1) mod q) dot p space (mod n)\
  &equiv 2lambda_p (q^(-1) mod p) dot q space (mod n)
$

#info([
  En pratique, on ne sait pas quelle racine correspond à quel $x_i$, on ne saura
  pas quelle valeur sera $q$ et quelle valeur sera $p$ mais elles sont
  interchangeables donc cela ne pose pas de problème.

  De plus, on peut utiliser $x_1 plus.minus x_2$ car les deux cas nous permettent
  d'isoler une composante.
])

Vu que $2lambda_p$ est divisible par q, on peut utiliser le plus grand diviseur
commun entre $2lambda_p$ et $n$ pour retrouver $q$

$
q = "gcd"(2lambda_p, n)
p = n / q
$

Pour être sûr d'avoir trouvé les bonnes valeurs, on peut vérifier que $p$ et $q$
sont bien premiers ainsi que de les utiliser pour déchiffrer le cipher connu pour
s'assurer que l'on obtient bien notre text clair correspondant.

Une fois que l'on a vérifié $p$ et $q$, on peut les utiliser pour déchiffrer le
challenge.

#goal(title: "Flag", [
  Le message est: `Ni! Ni! Ni! We want a celebrity`
])


=== Sur quel problème est basé la construction ?

La factorisation. Il s'agit d'un chiffrement style RSA.

=== A quoi sert la redondance ?

A priori, la norme iso7816 pour le padding ne définit pas de taille nécessaire.
Le padding fonctionne en ajoutant un Byte `0x80` suivi de Bytes `0x0` jusqu'à
avoir la bonne taille. Il est possible qu'une racine nous donne un résultat
conforme au padding (on a $1/256$ chance que le dernier byte soit `0x80`) qui
serait un faux positif. Il faut donc verifier que notre padding fait au minimum
`REDUNDANCY` Bytes pour considérer le résultat comme valide.

== Courbes Elliptiques

=== Schema

#task([
  todo
])

=== Description mathématique

Pour toute la partie mathématiques, nous avons les constantes publiques suivantes:
- $n$: nombre premier
- $E$: courbe elliptique
- $G$: un point sur la courbe elliptique $E$

==== Chiffrement

Lors du chiffrement, on génère la paire de clés $(a,A)$ avec $a$ la clé privée
choisie aléatoirement et $A$ la clé publique correspondante.

$
a &in ZZ_n\
A &= a dot G
$

On tire un nombre aléatoire $r$ qui sera utilisé pour ce message $M$ uniquement.

$
r &in ZZ_n
$

On initialise une clé $k$ AES à partir de $r$ et $A$

$
k &= "HKDF"(r dot A)
$

On utilise AES en mode GCM pour générer le ciphertext et son tag. (On récupère
aussi le nonce utilisé)

$
("nonce", "ciphertext", "tag") &= "AES_GCM"_k (M)
$

Et finalement on calcule $r G$ qui sera nécessaire pour déchiffrer le ciphertext.

$
r G &= r dot G
$

Si on combine tout, on a la formule suivante:

$
("c_0", ("nonce", "ciphertext", "tag")) &= (r dot G, "AES_GCM"_("HKDF"(r dot A))(M))
$

==== Déchiffrement

Pour le déchiffrement, on part du principe que l'on connait toutes les valeurs
en sortie du chiffrement ainsi que nos clés $(a, A)$.

On a besoins de retrouver la clé $k$ qui est le résultat de $"HKDF"(r dot A)$.
On ne connait pas $r$ directement mais on connait $r dot G$

$
A &= a dot G\
r dot A &= r dot a dot G\
r dot G &= r dot G\
$

En l'occurence la multiplication ici est commutative donc on peut simplement poser:

$
r dot G dot a = r dot A
$

Donc on peut trouver la clé $k$ pour AES_GCM et déchiffrer notre ciphertext.

$
m = "AES_GCM"^(-1)_("HKDF"("c_0" dot a))("nonce", "ciphertext", "tag")
$


=== Implémentation du déchiffrement et test

Pour tester le déchiffrement, on peut simplement chiffrer un message, le
déchiffrer et comparer le résultat obtenu. La fonction de chiffrement n'a pas
été modifiée donc un résultat identique confirme que l'on a utilisé la bonne clé
pour le déchiffrement.

```py
def main_decrypt():
    (G, E, n) = params()
    (a, A) = keyGen(G, n)
    M = b"hello world!"
    (c_0, (nonce, ciphertext, tag)) = encrypt(A, M, G, n)
    m = decrypt(a, E, c_0, nonce, ciphertext, tag)
    if m == M:
        print(f"successfully decrypted: {m}")
    else:
        print("decrypted result doesn't match expected value.")
        print(f"expected: {M}")
        print(f"actual  : {m}")
```

=== Problème de l'algorithme

L'algorithme de chiffrement ne semble pas être problématique. Le problème est
dans les paramètres constants qui contiennent des valeurs trop faibles. La
construction est basée sur le problème du logarithme discret sauf qu'avec les
valeurs que l'on a, on peut assez rapidement calculer le logarithme discret.

En particulier, on remarque que $n$ est un nombre premier de 42 bits et $n$
correspond à l'ordre de $G$. En comparaison, le $n$ de ed25519 fait $253$ bits.

=== Cassage de la construction

On a les equations suivantes avec les parties en rouge que l'on connait

$
red(A) &= a dot red(G)\
red(r G) &= r dot red(G)\
$

On sait que la construction s'appuie sur la difficulté du logarithme discret.
Donc avec de bonnes constantes on ne devrait pas être capables de calculer le
logarithme dans une durée raisonnable.

$
a &= log_red(G)(red(A))\
r &= log_red(G)(red(r G))
$

En l'occurrence, calculer $a$ par logarithme discret prend $approx 12s$ et
calculer $r$ $approx 2s$ ce qui n'est clairement pas suffisant.

En trouvant $r$, on est capables de déchiffrer cipher lié et en connaissant $a$
on peut déchiffrer n'importe quel cipher qui utilise cette clé.

#goal(title: "Flag", [
 `Nobody expects the spanish inquisition ! Our chief weapon is outcrops`
])

#info([
  Pour être sûr que le problème est lié aux paramètres plutôt qu'une mauvaise
  clé, j'ai utilisé chatGPT pour benchmark le temps médian nécessaire pour
  retrouver une clé aléatoire utilisant les paramètres.

  - Médiane: 12.767188s
  - Min: 3.049034s
  - Max: 34.658409s

  En l'occurrence, on peut partir du principe que l'on aura pas besoins de chance
  pour casser l'algorithme.
])

=== Correction de l'erreur

A moins d'avoir raté un détail dans la fonction `encrypt`, la faiblesse de
l'algorithme est dans les paramètres constants que l'on définit. Donc plutôt que
de s'amuser à trouver une courbe elliptique qui nous parait correcte, on aura
meilleurs temps d'utiliser une courbe connue comme suffisamment complexe.

Du coup, pour fix le problème, j'ai implémenté la fonction `fixed_params` avec
la même signature que `params` qui utilise la courbe ed25519. #link("https://neuromancer.sk/std/other/Ed25519", [J'ai récupéré le code pour les paramètres de ed25519]) et
il manquait juste la valeur de $n$ qui est simplement l'ordre de $G$.

== RSA

=== Implémentation du déchiffrement et test

Le déchiffrement de RSA ici est simple, la fonction est identique au chiffrement
à l'exception que l'on utilise la méthode decrypt.

Pour vérifier que cette fonction est correcte, on utilise la même approche que
précédemment où on chiffre un message connu et on compare l'original avec le
message déchiffré.

```py
def main_decrypt():
    key = keygen()
    M = b"Hello world!"
    c = encrypt(M, key)
    m = decrypt(c, key)
    if m == M:
        print(f"successfully decrypted: {m}")
    else:
        print("decrypted result doesn't match expected value.")
        print(f"expected: {M}")
        print(f"actual  : {m}")
```

=== Cassage de la construction

Il y a deux parties à considérer. Le chiffrement/déchiffrement ainsi que la
génération de la clé.

Pour le chiffrement/déchiffrement de la clé, on utilise le module `PKCS1_OAEP`
de `pycryptodome`. Dans la documentation, on apprend que l'on a besoins de la
clé privée pour déchiffrer et que les messages chiffrables doivent faire quelques
centaines de bytes de moins que le modulo RSA.

En cherchant un peu en ligne, on peut voir que PKCS\#1 OAEP est considéré comme
cassé. La piste est intéressante mais avant de se lancer dessus, la génération
de la clé peut être intéressante.

Quand on regarde la documentation du module RSA de pycryptodome, la première
chose que l'on remarque est que l'on peut facilement créer une clé avec:

```py
key = RSA.generate(3072)
```

La fonction `keygen` que l'on utilise est suspicieuse, les chances que
l'implémentation custom soit problématique semble assez élevée.

- $e = 65537$ pas de problème jusqu'ici, il s'agit d'une valeur standard.
- $n = p dot q$ normal pour RSA.
- $phi = (p-1)dot(q-1)$ normal pour RSA.
- $2 < p <= 2^(1024)$, $p$ est premier. En l'occurrence, la fonction random_prime
  nous garanti d'avoir un nombre premier proche du nombre de bits voulu.
- $q$ est le prochain nombre premier après $p + r$ avec $r$ un nombre aléatoire
  de $0$ à $15$ bits. Entre autre, on sait que $p < q$ et que $p$ et $q$ sont
  relativement proches.

A priori, le fait que $p$ et $q$ soient deux nombres premiers proches peut être
problématique. Pour éviter que $p$ et $q$ se suivent directement dans l'ensemble
des nombres premiers, on ajoute un offset entre $0$ et $2^(15)$. On sait que
$p$ est une valeur de $approx 1024$ bits. La distribution des nombres premiers
est dense en s'approchant de $0$ et s'espace en s'approchant de $infinity$.

En l'occurrence, Il y a beaucoup de chances que $p$ et $q$ partagent un grands
nombre de bits de poids fort.

En partant du principe que l'on peut attaquer notre construction de manière
similaire au challenge sur les courbes elliptiques, on cherche à attaquer le
problème sur lequel se base la construction. On veut donc essayer de factoriser
$n$. Le problème est que $n$ trop grand pour qu'on puisse simplement utiliser
la fonction de factorisation de sage, il faut donc se baser sur le fait que
p et q soient proches l'un de l'autre.

En cherchant #link("https://www.google.com/search?q=RSA+factorization+attack", ["RSA factorization attack"])
sur google, on trouve des pistes. Surtout avec #link("https://websites.nku.edu/~christensen/Mathematical%20attack%20on%20RSA.pdf",[un papier qui propose plusieurs algorithmes mathématiques pour attaquer RSA.])
L'algorithme de factorisation de Fermat en particulier permet de factoriser la
différence entre deux carrés. Le fait que $p$ et $q$ soient relativement proches
est avantageux pour cette approche.

On peut trouver un pseudocode de la factorisation de Fermat sur Wikipedia et
l'implémenter en sage. En testant avec la clé publique fournie, on arrive a
rapidement factoriser $n$ et donc recréer la clé privée.

#goal(title: "Flag", [
`What is your quest? To seek the holy grail. What is your favorite color? departmental`
])
