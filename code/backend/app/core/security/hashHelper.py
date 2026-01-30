from bcrypt import checkpw, gensalt, hashpw


class HashHelper(object):
    """
    Outils pour gerer les mots de passe.
    On stocke un hash (pas le mot de passe en clair) et on peut comparer.
    """

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str):
        """
        Compare un mot de passe en clair avec son hash stocke.
        Renvoie True si c'est le meme, sinon False.
        """
        return checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

    @staticmethod
    def get_password_hash(plain_password: str):
        """
        Transforme un mot de passe en clair en hash pour le stocker en base.
        """
        return hashpw(plain_password.encode("utf-8"), gensalt()).decode("utf-8")
