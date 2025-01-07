#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include "client.h" // API Macrohard pour sndmsg

#define SERVER_PORT 8080
#define CLIENT_PORT 9090
#define AES_KEY_SIZE 32  // 256 bits
#define AES_BLOCK_SIZE 16

unsigned char aes_key[AES_KEY_SIZE]; // Clé symétrique AES

// Génération de la clé AES
void generate_aes_key() {
    if (!RAND_bytes(aes_key, AES_KEY_SIZE)) {
        fprintf(stderr, "Erreur : Impossible de générer la clé AES.\n");
        exit(EXIT_FAILURE);
    }
    printf("Clé AES générée avec succès.\n");
}

// Fonction pour gérer le chiffrement RSA
int rsa_encrypt(const char *pub_key_path, const unsigned char *data, size_t data_len, unsigned char *encrypted) {
    FILE *pub_key_file = fopen(pub_key_path, "r");
    RSA *rsa_pub_key = NULL;
    int encrypted_len = -1;

    if (!pub_key_file) {
        fprintf(stderr, "Erreur : Impossible de charger la clé publique.\n");
        return -1;
    }

    rsa_pub_key = PEM_read_RSA_PUBKEY(pub_key_file, NULL, NULL, NULL);
    if (!rsa_pub_key) {
        fprintf(stderr, "Erreur de chargement de la clé publique : %s\n", ERR_error_string(ERR_get_error(), NULL));
        fclose(pub_key_file);
        return -1;
    }

    encrypted_len = RSA_public_encrypt(data_len, data, encrypted, rsa_pub_key, RSA_PKCS1_PADDING);

    RSA_free(rsa_pub_key);
    fclose(pub_key_file);
    return encrypted_len;
}

// Authentification utilisateur
void login_user(const char *username, const char *password) {
    char auth_request[1024];
    snprintf(auth_request, sizeof(auth_request), "-login %s %s", username, password);

    if (sndmsg(auth_request, SERVER_PORT) == 0) {
        printf("Requête d'authentification envoyée avec succès.\n");
    } else {
        fprintf(stderr, "Erreur lors de l'envoi de la requête d'authentification.\n");
    }
}

// Fonction pour envoyer un fichier au serveur
void upload_file(const char *file_path, const char *pub_key_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier %s.\n", file_path);
        return;
    }

    unsigned char buffer[1024];
    unsigned char encrypted[1024 + AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    size_t bytes_read;

    // Générer un IV aléatoire
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Erreur : Impossible de générer l'IV.\n");
        fclose(file);
        return;
    }

    // Notifier le serveur du fichier à uploader
    char header[1024];
    snprintf(header, sizeof(header), "-up %s", file_path);
    if (sndmsg(header, SERVER_PORT) < 0) {
        fprintf(stderr, "Erreur : Impossible d'envoyer la requête au serveur.\n");
        fclose(file);
        return;
    }

    // Envoyer l'IV au serveur
    if (sndmsg((char *)iv, SERVER_PORT) < 0) {
        fprintf(stderr, "Erreur : Impossible d'envoyer l'IV au serveur.\n");
        fclose(file);
        return;
    }

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 256, &enc_key);

    // Lire et chiffrer le fichier par morceaux
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        AES_cbc_encrypt(buffer, encrypted, bytes_read, &enc_key, iv, AES_ENCRYPT);
        sndmsg((char *)encrypted, SERVER_PORT);
    }

    printf("Fichier %s envoyé avec succès.\n", file_path);
    fclose(file);
}

// Fonction pour télécharger un fichier depuis le serveur
void download_file(const char *file_name) {
    char request[1024];
    snprintf(request, sizeof(request), "-down %s", file_name);
    sndmsg(request, SERVER_PORT);

    // Ouvrir un fichier local pour écrire les données déchiffrées
    FILE *file = fopen(file_name, "wb");
    if (!file) {
        fprintf(stderr, "Erreur : Impossible de créer le fichier local %s.\n", file_name);
        return;
    }

    unsigned char buffer[1024];
    unsigned char decrypted[1024];
    unsigned char iv[AES_BLOCK_SIZE];
    int bytes_received;

    // Recevoir l'IV en premier
    if ((bytes_received = getmsg((char *)iv)) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Erreur : Taille de l'IV incorrecte.\n");
        fclose(file);
        return;
    }

    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, 256, &dec_key);

    // Recevoir et déchiffrer le fichier
    while ((bytes_received = getmsg((char *)buffer)) > 0) {
        AES_cbc_encrypt(buffer, decrypted, bytes_received, &dec_key, iv, AES_DECRYPT);
        fwrite(decrypted, 1, bytes_received, file);
    }

    printf("Fichier %s téléchargé avec succès.\n", file_name);
    fclose(file);
}

// Liste des fichiers
void list_files() {
    char request[1024];
    snprintf(request, sizeof(request), "-list");
    if (sndmsg(request, SERVER_PORT) == 0) {
        char response[1024];
        while (getmsg(response) > 0) {
            printf("Fichier : %s\n", response);
        }
    } else {
        fprintf(stderr, "Erreur lors de la requête de liste des fichiers.\n");
    }
}

int main(int argc, char *argv[]) {
    // Générer une clé AES au démarrage
    generate_aes_key();

    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s -login <username> <password>\n", argv[0]);
        printf("  %s -up <file>\n", argv[0]);
        printf("  %s -down <file>\n", argv[0]);
        printf("  %s -list\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-login") == 0 && argc == 4) {
        login_user(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-up") == 0 && argc == 4) {
        upload_file(argv[2], argv[3]); // Nécessite le chemin de la clé publique
    } else if (strcmp(argv[1], "-down") == 0 && argc == 3) {
        download_file(argv[2]);
    } else if (strcmp(argv[1], "-list") == 0) {
        list_files();
    } else {
        printf("Commande inconnue ou arguments manquants.\n");
    }

    return 0;
}
