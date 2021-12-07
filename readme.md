# Network Protocol Analyzer

## What is this ?

Here is a program of network protocol analyzers.
The program takes as input a formatted text file.
The file must contain hexadecimal characters describing one or more Ethernet frames.
- Each byte is encoded by two hexadecimal digits.
- Each byte is delimited by a space.
- Each line begins with the offset of the first byte located in succession on the same line. The offset describes the position of that byte in the trace.
- Each new frame starts with an offset of 0 and the offset is separated by one space from the captured bytes located after it.
- The offset is coded over more than two hexadecimal digits.
- Hexadecimal characters can be upper or lower case.
- There is no limit on the length or the number of bytes present on each line.
- If text values are given at the end of the line, they should be ignored, even if these values ​​are hexadecimal digits.
- Lines of text between traces or interlaced between captured byte lines should be ignored.
- Byte lines that do not start a valid offset are ignored.
- Any incomplete line is identified and raises an error indicating the position of the line in error.

## Programmers

- Ben Kabongo Buzangu (kabongo.ben025@gmail.com)
- Souleymane Mbaye

L3 computer science, Sorbonne University.

## Supported protocols

The program supports the following protocols:
- Ethernet
- ARP
- IPv4
- IPv6
- ICMP
- TCP
- UDP
- DHCP
- DNS

## How to start the program ?

- Go to the "dist" directory
- Execute : java -jar NetworkProtocolAnalyzer.jar

# Analyseur de protcoles réseaux

## Qu'est-ce que c'est ?

Il s'agit d'un programme d'analyse de protocoles réseaux.
Le programme prend en entrée un fichier texte formaté.
Le fichier doit contenir des caractères hexadécimaux décrivant une ou plusieurs trames Ethernet.
- Chaque octet est codé par deux chiffres hexadécimaux.
- Chaque octet est délimité par un espace.
- Chaque ligne commence par l’offset du premier octet situé à la suite sur la même ligne. L’offset décrit la positon de cet octet dans la trace.
- Chaque nouvelle trame commence avec un offset de 0 et l’offset est séparé d’un espace des octets capturés situés à la suite.
- L’offset est codé sur plus de deux chiffres hexadécimaux.
- Les caractères hexadécimaux peuvent être des majuscules ou minuscules.
- Il n’y a pas de limite concernant la longueur ou le nombre d’octets présents sur chaque ligne.
- Si des valeurs textuelles sont données en fin de ligne, elles doivent être ignorées, y compris si ces valeurs sont des chiffres hexadécimaux.
- Les lignes de texte situées entre les traces ou entrelacées entre les lignes d’octets capturés doivent être ignorées.
- Les lignes d’octets qui ne débutent pas un offset valide sont ignorées.
- Toute ligne incomplète est identifiée et soulève une erreur indiquant la position de la ligne en erreur.

## Conecpteurs

- Ben Kabongo Buzangu (kabongo.ben025@gmail.com)
- Souleymane Mbaye

L3 informatique, Sorbonne Université.

## Protocoles pris en charge

Le programme prend en charge les protocoles suivants:
- Ethernet
- ARP
- IPv4
- ICMP
- TCP
- UDP
- DHCP
- DNS

## Comment lancer le programme ?
