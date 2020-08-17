#------------------------------------------------------------------------------+
# Name:        RSA_all_in_one.py
# Desc:        Cryptage RSA et crack de la cle privee
# Author:      Laurent FERHI
#
# Created:     07/10/2019
#------------------------------------------------------------------------------+

from random import randrange
from random import randint
import sys

# Verification que nb est un nombre premier (test statistique pour n grand)
def miller_rabin(n, k):
    if n == 2: return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(0,k):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1: continue
        for _ in range(0,r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

# pgcd etendu avec les 2 coefficients de bezout-bachet u et v
# sorties : r = pgcd(a,b) et u, v entiers tels que a*u + b*v = r
def pgcde(a, b):
	r, rp = a, b
	u, up = 1, 0
	v, vp = 0, 1
	while rp != 0:
		q = r//rp
		rs, us, vs = r, u, v
		r, u, v = rp, up, vp
		rp, up, vp = (rs - q*rp), (us - q*up), (vs - q*vp)
	return (r, u, v)

# Creation des cles de chiffrement
def keys():
	borne_inf = 1
	borne_sup = 1000
	p = randint(borne_inf,borne_sup)
	q = randint(borne_inf,borne_sup)
	while miller_rabin(p,100000) is False:
		p = randint(borne_inf,borne_sup)
	while miller_rabin(q,100000) is False:
		q = randint(borne_inf,borne_sup)
	# calcul de n (module de chiffrement) et m (indicatrice d'Euler en n -> phi(n) = (p-1)*(q-1))
	n = p*q
	m = (p-1)*(q-1)
	# recherche de c (exposant de chiffrement) premier de m (c'est a dire tel que pgcd(m,c)=1 )
    # recherche de d (exposant de dechiffrement).
    # d est l'inverse de c modulo m : c*d = 1 mod m. autrement dit : d = pgcde(m,c) tel que 2 < d < m
	r = 10
	d = 0
	while r != 1 or d <= 2 or d >= m:
		c = randint(borne_inf,borne_sup) # c est choisi au hasard et doit verifier (c premier avec m)
		r, d, v = pgcde(c,m)    # r, d, v prennent les valeurs du tuple resultat de pgcde(c,m)
	n = int(n)   # module de chiffrement
	c = int(c)   # exposant de chiffrement
	d = int(d)   # exposant de dechiffrement
	return {"cle_publique":(n,c), "cle_privee":(n,d)}

# Chiffrement du message
def chiffre(n, c, msg):
	# conversion du message en codes ascii
	asc = [str(ord(j)) for j in msg]
	# ajout de 0 pour avoir une longueur fixe (3) de chaque code ascii
	for i, k in enumerate(asc):
		if len(k) < 3:
			while len(k) < 3:
				k = '0' + k
			asc[i] = k
	# formation de blocs de taille inferieure a n (ici blocs de 4)
	ascg = ''.join(asc)
	d = 0
	f = 4
	while len(ascg)%f != 0: # on rajoute eventuellement des 0 a la fin de ascg pour que len(ascg) soit un multiple de f
		ascg = ascg + '0'
	l = []
	while f <= len(ascg):
		l.append(ascg[d:f])
		d = f
		f = f + 4
	# chiffrement des groupes
    # reste de la division de chaque bloc a l'exposant c par n
	crypt = [str(((int(i))**c)%n) for i in l]
	return crypt

# Dechiffrement du message
def dechiffre(n, d, crypt):
	# dechiffrement des blocs
    # reste de la division de chaque bloc a l'exposant d par n
	resultat = [str((int(i)**d)%n) for i in crypt]
	# on rajoute les 0 en debut de blocs pour refaire des blocs de 4
	for i, s in enumerate(resultat):
		if len(s) < 4:
			while len(s) < 4:
				s = '0' + s
			resultat[i] = s
	# on refait des groupes de 3 et on les convertie directement en ascii
	g = ''.join(resultat)
	asci = ''
	d = 0
	f = 3
	while f < len(g):
		asci = asci + chr(int(g[d:f])) # conversion ascii
		d = f
		f = f + 3
	return asci

# Liste des nombres premiers jusqu'a n
def liste_prem(n):
    l_prem = [2]
    i = 3
    while i < n:
        verif = 1
        for j in l_prem:
            if (i % j) == 0:
                verif = 0
                break
        if verif == 1:
            l_prem.append(i)
        i = i + 1
    return l_prem

# Trouve d pour que (c*d -1) modulo phin-n = 0
def find_d(c,n,phi_n):
    for d in range(1,n):
        reste = (c*d - 1) % phi_n
        if reste == 0:
            return d
    return False

# Trouve la cle privee en fonction de la cle publique
# n = p*q avec p et q premiers puis find_d avec c et phi_n = (p-1)*(q-1)
def crack(n, c):
    l_prem_n = liste_prem(n)
    for p in l_prem_n:
        for q in l_prem_n:
            if p*q == n:
                phi_n = (p-1)*(q-1)
                d = find_d(c, n, phi_n)
                if d != False:
                    return d
    return False

def Generation_cles():
    print("*** GENERATION DES CLES DE CRYPTAGE ***\n")
    message_test = "Message test ! 12345."
    test = False

    while test == False:
        cles_cryptage = keys()
        n = (cles_cryptage.get("cle_publique"))[0]
        d = (cles_cryptage.get("cle_privee"))[1]
        c = (cles_cryptage.get("cle_publique"))[1]

        # Chiffrement avec la cle publique
        print("Message_test : ",message_test)
        print ("Chiffrement du message test avec la cle publique:",cles_cryptage.get("cle_publique"))
        msg_crypt = chiffre(n,c,message_test)
        print (msg_crypt)

        # Dechiffrement avec la cle privee
        print ("\nVerification : dechiffrement du message test avec la cle privee:",cles_cryptage.get("cle_privee"))
        decryptage = dechiffre(n,d,msg_crypt)
        print (decryptage)
        if decryptage == message_test:
            test = True
            print ("\nChiffrement reussi ! \nCle privee et cle publique:",cles_cryptage)
        else:
            print("\nEchec du chiffrement, nouvelle tentative...")

    file_out = open("Cle_publique.dat","w")
    file_out.write(str(n)+"\t"+str(c))
    file_out.close()

    file_out = open("Cle_privee.dat","w")
    file_out.write(str(n)+"\t"+str(d))
    file_out.close()

    return True

def Chiffrement_msg(Nom_fichier_in, Nomfichier_out, Nom_cle_publique):
    print("\n*** CHIFFREMENT DU MESSAGE ***\n")

    file_in = open(Nom_fichier_in,"r")
    message = file_in.read()
    file_in.close()

    file_in = open(Nom_cle_publique,"r")
    data = (file_in.read()).split("\t")
    file_in.close()

    cle_publique = tuple([int(i) for i in data])

    # Chiffrement avec la cle publique
    n = (cle_publique)[0]
    c = (cle_publique)[1]
    print ("Chiffrement du message avec la cle publique:")
    msg_crypt = chiffre(n,c,message)
    print (msg_crypt)

    file_out = open(Nomfichier_out,"w")
    for elt in msg_crypt:
        file_out.write(str(elt)+"\t")
    file_out.close()

    return True

def Dechiffrement_msg(Nom_fichier_in, Nom_cle_privee):
    print("\n*** DECHIFFREMENT DU MESSAGE ***\n")

    file_in = open(Nom_fichier_in,"r")
    msg_crypt = (file_in.read()).split("\t")
    del msg_crypt[-1]
    file_in.close()

    file_in = open(Nom_cle_privee,"r")
    data = (file_in.read()).split("\t")
    file_in.close()

    cle_privee = tuple([int(i) for i in data])

    # Chiffrement avec la cle publique
    n = (cle_privee)[0]
    d = (cle_privee)[1]
    print ("Dechiffrement du message avec la cle privee:")
    decryptage = dechiffre(n,d,msg_crypt)
    print (decryptage)

    file_out = open("Msg_dechiffre.txt","w")
    file_out.write(str(decryptage))
    file_out.close()

    return True

def Crack_cle_privee(Nom_fichier_in, Nom_cle_publique):
    print("\n*** CRACK DE LA CLE PRIVEE ***\n")

    file_in = open(Nom_fichier_in,"r")
    msg_crypt = (file_in.read()).split("\t")
    del msg_crypt[-1]
    file_in.close()

    file_in = open(Nom_cle_publique,"r")
    data = (file_in.read()).split("\t")
    file_in.close()
    cle_publique = tuple([int(i) for i in data])

    n = (cle_publique)[0]
    c = (cle_publique)[1]

    d = crack(n,c)
    if d == False:
        print("Le crack a echoue...")
        sys.exit()
    print("Cle privee trouvee :",(n,d))

    print ("\nDechiffrement du message avec la cle privee:")
    decryptage = dechiffre(n,d,msg_crypt)
    print (decryptage)

    file_out = open("Msg_cracked.txt","w")
    file_out.write(str(decryptage))
    file_out.close()

    return True

# --- MAIN --------------------------------------------------------------------+

Generation_cles()
Chiffrement_msg("Message_initial.txt", "Msg_chiffre.txt","Cle_publique.dat")
Dechiffrement_msg("Msg_chiffre.txt", "Cle_privee.dat")
Crack_cle_privee("Msg_chiffre.txt", "Cle_publique.dat")

################################################################################