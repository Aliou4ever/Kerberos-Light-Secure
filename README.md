# Kerberos-Light-Secure
Version allégée du protocole Kerberos

Lien vidéo pour la démonstration  : https://www.youtube.com/watch?v=0eMCEiwxDrM

Cette Application implémente une version allégée du protocole Kerberos dans un réseau local.
Les entités : des Serveurs de Services (SS), des Clients et un Serveur de Certificats (SC).

Le SC unique permet à tout les clients/SS identifiés de se faire authentifier leurs clés 
publiques générée avec un algorithme RSA.
Les Clients peuvent demander des services aux SS et la demande se fait par l'intermédiaire 
du protocole Needham Shroeder. Les Nonces de ce protocole sont utilisées pour créer une clé
de session partagée entre client/SS utilisable une seule fois.

Serveur de Certificats : 
  1) génère une paire de clés - crée un certificat auto-signé - enregistre sa clé publique dans
     un fichier - ouvre une connexion sur un port et attend l'arrivée de Client/SS. 
  2) Si il reçoit une demande de certification de clé publique (Protocle demande de CSR) alors
     vérifie l'identité (login, mot de passe) du demandeur dans la table "users" puis il crée un 
     certificat pour cette clé, l'enregistre dans la table "certificat" et envoie ce certificat au
     Client/SS demandeur.
  3) Si il reçoit une demande de certificat d'un SS dans le réseau (Protocole demande de certificat)
     il vérifie les identités demandeur/démandé et s'il possède le certificat démandé dans la base,
     il l'envoie au démandeur.

Clients et Serveurs de Services : 
  1) se connecte sur le réseau - génère une paire de clés - construit une demande de CSR - récupère
     la clé publique du SC dans un fichier - crypte le CSR avec la clé du SC et l'envoie au serveur.
     Si il réçoit le certificat il l'enregistre dans un KeyStore (magasin de clés) protégé par mot de passe.
  2) demande au SC le certificat d'un SS - il récoit ce certificat par le SC et l'ajoute dans son KeyStore.
  2)-a) SS : lance les services sur un port défini - si un client arrive, un challenge protocole Needham Shroeder 
             avec lui - si challenge OK, le SS crée une clé de session (AES) qu'il échange avec le client - ensuite
             il réçoit et traite les demandes de services, envoie un acquittement au client (tout ces mesages sont 
             cryptées et décryptées avec la clé de session).
  2)-b) Client : se connecte au SS - initie un échange Needham Shroeder - récoit une clé de session par le SS -
                 demande un service (Protocole demande de service) - obtient un acquittement du service démandé au SS.
    

