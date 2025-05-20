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
