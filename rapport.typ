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

#goal([
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
