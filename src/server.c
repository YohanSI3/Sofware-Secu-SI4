#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <errno.h>
#include "server.h"

#define MAX_MSG_SIZE 1024
#define DB_FILE "users.db"
#define STORAGE_PATH "./users"
#define SALT "random_salt" // Sel utilisé pour le hachage des mots de passe

// Hacher un mot de passe avec SHA256 et un sel
void hash_password(const char *password, char *hashed_password) { 
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    char salted_password[256];
    snprintf(salted_password, sizeof(salted_password), "%s%s", SALT, password);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salted_password, strlen(salted_password));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hashed_password[i * 2], "%02x", hash[i]);
    }
    hashed_password[hash_len * 2] = '\0';
}

// Vérifier si un utilisateur existe
int user_exists(const char *username) {
    FILE *db = fopen(DB_FILE, "r");
    if (!db) return 0;

    char line[256];
    while (fgets(line, sizeof(line), db)) {
        char stored_username[128];
        sscanf(line, "%127[^:]", stored_username);
        if (strcmp(username, stored_username) == 0) {
            fclose(db);
            return 1;
        }
    }

    fclose(db);
    return 0;
}

// Créer le dossier utilisateur pour le stockage des fichiers
void create_user_directory(const char *username) {
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", STORAGE_PATH, username);

    if (mkdir(STORAGE_PATH, 0755) == -1 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier de stockage");
        exit(EXIT_FAILURE);
    }

    if (mkdir(user_dir, 0755) == -1 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier utilisateur");
        exit(EXIT_FAILURE);
    }
}

// Créer un nouvel utilisateur
int create_user(const char *username, const char *password) {
    if (user_exists(username)) {
        printf("Erreur : L'utilisateur '%s' existe déjà.\n", username);
        return 0;
    }

    char hashed_password[65];
    hash_password(password, hashed_password);

    FILE *db = fopen(DB_FILE, "a");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    fprintf(db, "%s:%s\n", username, hashed_password);
    fclose(db);

    create_user_directory(username);
    printf("Utilisateur '%s' créé avec succès.\n", username);
    return 1;
}

// Connecter un utilisateur
int login_user(const char *username, const char *password) {
    if (!user_exists(username)) {
        printf("Erreur : L'utilisateur '%s' n'existe pas.\n", username);
        return 0;
    }

    char hashed_password[65];
    hash_password(password, hashed_password);

    FILE *db = fopen(DB_FILE, "r");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), db)) {
        char stored_username[128], stored_password[65];
        sscanf(line, "%127[^:]:%64s", stored_username, stored_password);

        if (strcmp(username, stored_username) == 0) {
            fclose(db);
            if (strcmp(hashed_password, stored_password) == 0) {
                printf("Connexion réussie pour '%s'.\n", username);
                return 1;
            } else {
                printf("Erreur : Mot de passe incorrect.\n");
                return 0;
            }
        }
    }

    fclose(db);
    return 0;
}

// Gérer les requêtes envoyées par le client
void handle_request(const char *msg) {
    char command[MAX_MSG_SIZE], username[MAX_MSG_SIZE], password[MAX_MSG_SIZE];
    char buffer[MAX_MSG_SIZE];

    sscanf(msg, "%[^:]:%[^:]:%s", command, username, password);

    if (strcmp(command, "LOGIN") == 0) {
        if (login_user(username, password)) {
            snprintf(buffer, MAX_MSG_SIZE, "SUCCESS");
        } else {
            snprintf(buffer, MAX_MSG_SIZE, "ERREUR : Mot de passe incorrect.");
        }
    } else if (strncmp(msg, "UPLOAD:", 7) == 0) {
        // Traitement de la commande UPLOAD
        const char *filename = msg + 7;
        const char *filedata = strchr(filename, ':') + 1;
        char file[MAX_MSG_SIZE];

        sscanf(filename, "%[^:]", file);

        // Ouvrir un fichier pour le stockage
        FILE *f = fopen(file, "wb");
        if (!f) {
            perror("Erreur lors de l'écriture du fichier");
            return;
        }

        fwrite(filedata, 1, strlen(filedata), f);
        fclose(f);
        printf("Fichier %s reçu et enregistré.\n", file);
    } else if (strcmp(msg, "LIST") == 0) {
        // Liste des fichiers
        system("ls > files.txt");
        printf("Liste des fichiers envoyée.\n");
    } else if (strncmp(msg, "DOWNLOAD:", 9) == 0) {
        // Télécharger un fichier
        const char *filename = msg + 9;
        FILE *file = fopen(filename, "rb");
        if (!file) {
            perror("Fichier introuvable");
            return;
        }

        char buffer[MAX_MSG_SIZE];
        fread(buffer, 1, MAX_MSG_SIZE, file);
        fclose(file);

        printf("Fichier %s préparé pour le téléchargement.\n", filename);
    } else {
        printf("Commande inconnue : %s\n", msg);
    }
}

int main() {
    char buffer[MAX_MSG_SIZE];
    startserver(8080); // Démarre le serveur sur le port 8080
    printf("Serveur en écoute sur le port 8080...\n");

    while (1) {
        if (getmsg(buffer) > 0) {
            handle_request(buffer); // Traite chaque requête du client
        }
    }

    stopserver(); // Arrêt du serveur
    return 0;
}
