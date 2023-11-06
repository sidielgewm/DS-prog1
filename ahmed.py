import maskpass
import string
import hashlib
import bcrypt

def Introduire_email():
    while True:
        email = input("Entrez votre adresse e-mail : ")
        if "@" in email and "." in email and "gmail" in email and "com" in email:
            return email
        else:
            print("SVP, entrez une adresse e-mail valide.")

def Introduire_pwd():
    while True:
        p = maskpass.askpass()
        if len(p) == 8:
            if any(c.isdigit() for c in p):
                if any(c.isupper() for c in p):
                    if any(c.islower() for c in p):
                        if any(c in string.punctuation for c in p):
                            p_hashed = hashlib.sha256(p.encode()).hexdigest()
                            return p_hashed
                        else:
                            print("SVP, au moins un caractère spécial.")
                    else:
                        print("SVP, au moins un caractère minuscule.")
                else:
                    print("SVP, au moins un caractère majuscule.")
            else:
                print("SVP, au moins un chiffre.")
        else:
            print("SVP, le mot de passe doit avoir 8 caractères.")

def Authentification():
    email = Introduire_email()
    p_hashed = Introduire_pwd()

    with open("enregistrement.txt", "r") as file:
        cyber = file.read()
        if f"Email: {email}\n" in cyber and f"Pwd: {p_hashed}\n" in cyber:
            print("Authentification réussie.")
            Menu()
        else:
            print("Les identifiants sont incorrects. Veuillez vous enregistrer.")
            enregistrer_utilisateur()

def enregistrer_utilisateur():
    print("Enregistrement d'un nouvel utilisateur :")
    email = Introduire_email()
    p_hashed = Introduire_pwd()

    with open("enregistrement.txt", "a") as file:
        file.write(f"Email: {email}\nPwd: {p_hashed}\n")

    print("Utilisateur enregistré avec succès.")
    Authentification()

def verif():
    print("Bienvenu dans l'application")
    print("/n : taper 1 pour authentification")
    print("/n : taper 2 pour enregistrement")
    email = Introduire_email()
    p_hashed = Introduire_pwd()
    with open("enregistrement.txt", "r") as file:
        cyber = file.read()
    if f"Email: {email}\n" in cyber and f"Pwd: {p_hashed}\n" in cyber:
        print("Vous êtes déjà enregistré. Veuillez vous authentifier.")
        Authentification()
    else:
        print("Veuillez vous enregistrer.")
        enregistrer_utilisateur()

def Menu():
    while True:
        print("Menu :")
        print("a- Haché le mot par sha256")
        print("b- Haché le mot en générant un salt (bcrypt)")
        print("c- Attaquer par dictionnaire le mot inséré")
        choix = input("Choisissez une option (a/b/c) ou 'q' pour quitter : ")
        if choix == 'a':
            mot_a_hasher = maskpass.askpass("Entrez le mot à hacher : ")
            sha256_hash = hashlib.sha256(mot_a_hasher.encode()).hexdigest()
            print(f"Hachage SHA-256 : {sha256_hash}")
        elif choix == 'b':
            mot_a_hasher = maskpass.askpass("Entrez le mot à hacher : ")
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(mot_a_hasher.encode(), salt)
            print(f"Hachage bcrypt : {hashed_password}")
        elif choix == 'c':
            mot_a_attaquer = maskpass.askpass("Entrez le mot à attaquer : ")
            if dictionary_attack(mot_a_attaquer):
                print("Mot de passe trouvé dans le dictionnaire.")
            else:
                print("Le mot de passe n'a pas été trouvé dans le dictionnaire.")
        elif choix == 'q':
            break
        else:
            print("Option invalide. Veuillez réessayer.")

def dictionary_attack(target_password):
    with open("enregistrement.txt", "r") as file:
        for line in file:
            word = line.strip()  # Lire un mot du dictionnaire
            hashed_word = hashlib.sha256(word.encode()).hexdigest()
            if hashed_word == target_password:
                print(f"Mot de passe trouvé dans le dictionnaire : {word}")
                return True
    return False



