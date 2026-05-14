#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <gtk/gtk.h>
#include <qrencode.h>

#define ENC_KEY "MdNaimNIDSystem2026SecureKey!!"

#define MAX_NAME 100
#define MAX_ADDRESS 200
#define SALT_LEN 32
#define ITERATIONS 10000

typedef enum { ADMIN } Role;

sqlite3 *db;
char *DB_NAME = "national_id.db";

//   DATA MODELS  
typedef struct {
    char nid[20];
    char name[MAX_NAME];
    char dob[11];
    char gender[10];
    char address[MAX_ADDRESS];
    char father_name[MAX_NAME];
    char mother_name[MAX_NAME];
    char blood_group[4];
    int is_active;
    time_t created_at;
    time_t last_modified;
} Citizen;

typedef struct {
    char username[50];
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    unsigned char salt[SALT_LEN];
    Role role;
    int failed_attempts;
    time_t last_login;
} SystemUser;

// Global GTK widgets
GtkWidget *login_window;
GtkWidget *dashboard_window;
GtkWidget *status_bar;

//   DATABASE FUNCTIONS  
int init_db() {
    int rc = sqlite3_open(DB_NAME, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    const char *sql = 
        "CREATE TABLE IF NOT EXISTS citizens ("
        "nid TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "dob TEXT NOT NULL,"
        "gender TEXT NOT NULL,"
        "address TEXT NOT NULL,"
        "father_name TEXT NOT NULL,"
        "mother_name TEXT NOT NULL,"
        "blood_group TEXT NOT NULL,"
        "is_active INTEGER,"
        "created_at INTEGER,"
        "last_modified INTEGER"
        ");"

        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"
        "password_hash BLOB NOT NULL,"
        "salt BLOB NOT NULL,"
        "role INTEGER NOT NULL,"
        "failed_attempts INTEGER,"
        "last_login INTEGER"
        ");"

        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "nid TEXT NOT NULL,"
        "timestamp INTEGER NOT NULL,"
        "activity_type TEXT NOT NULL"
        ");";

    char *err_msg = 0;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    return 1;
}

//   UTILITY FUNCTIONS  
int validate_date(const char *date) {
    int day, month, year;
    return (sscanf(date, "%d-%d-%d", &day, &month, &year) == 3) && 
           (year >= 1900 && year <= 2007) && 
           (month >= 1 && month <= 12) && 
           (day >= 1 && day <= 31);
}

void generate_unique_nid(char *nid) {
    srand(time(NULL));
    snprintf(nid, 11, "%010d", rand() % 1000000000);
}

//   CRYPTO FUNCTIONS  
void generate_salt(unsigned char *salt) {
    if (!RAND_bytes(salt, SALT_LEN)) {
        perror("Error generating salt");
        exit(EXIT_FAILURE);
    }
}

void derive_key(const char *pass, const unsigned char *salt, unsigned char *key) {
    if (!PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, SALT_LEN, ITERATIONS, EVP_sha256(), SHA256_DIGEST_LENGTH, key)) {
        perror("Error deriving key");
        exit(EXIT_FAILURE);
    }
}

//   CITIZEN OPERATIONS  
int save_citizen(Citizen *citizen) {
    char *sql = "INSERT INTO citizens VALUES (?,?,?,?,?,?,?,?,?,?,?);";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, citizen->nid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, citizen->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, citizen->dob, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, citizen->gender, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, citizen->address, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, citizen->father_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, citizen->mother_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, citizen->blood_group, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, citizen->is_active);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)citizen->created_at);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)citizen->last_modified);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if(rc != SQLITE_DONE) {
        return 0;
    }
    return 1;
}

int update_citizen_db(Citizen *updated, const char *original_nid) {
    char *update_sql = "UPDATE citizens SET "
                      "name = ?, dob = ?, gender = ?, address = ?, "
                      "father_name = ?, mother_name = ?, blood_group = ?, "
                      "is_active = ?, last_modified = ? "
                      "WHERE nid = ?;";
    sqlite3_stmt *update_stmt;

    if (sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(update_stmt, 1, updated->name, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 2, updated->dob, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 3, updated->gender, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 4, updated->address, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 5, updated->father_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 6, updated->mother_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 7, updated->blood_group, -1, SQLITE_STATIC);
        sqlite3_bind_int(update_stmt, 8, updated->is_active);
        sqlite3_bind_int64(update_stmt, 9, (sqlite3_int64)updated->last_modified);
        sqlite3_bind_text(update_stmt, 10, original_nid, -1, SQLITE_STATIC);

        int rc = sqlite3_step(update_stmt);
        sqlite3_finalize(update_stmt);
        return (rc == SQLITE_DONE);
    }
    return 0;
}

int delete_citizen_db(const char *nid) {
    char *delete_sql = "DELETE FROM citizens WHERE nid = ?;";
    sqlite3_stmt *delete_stmt;
    
    if(sqlite3_prepare_v2(db, delete_sql, -1, &delete_stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(delete_stmt, 1, nid, -1, SQLITE_STATIC);
        int rc = sqlite3_step(delete_stmt);
        sqlite3_finalize(delete_stmt);
        return (rc == SQLITE_DONE);
    }
    return 0;
}

//  USER AUTHENTICATION 
int authenticate_user(const char *username, const char *password) {
    char *sql = "SELECT password_hash, salt FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;

    if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    if(sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return 0;
    }
    int rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW) {
        const unsigned char *db_hash = sqlite3_column_blob(stmt, 0);
        const unsigned char *salt = sqlite3_column_blob(stmt, 1);
        if(sqlite3_column_bytes(stmt, 0) != SHA256_DIGEST_LENGTH || 
           sqlite3_column_bytes(stmt, 1) != SALT_LEN) {
            sqlite3_finalize(stmt);
            return 0;
        }
        unsigned char derived_key[SHA256_DIGEST_LENGTH];
        derive_key(password, salt, derived_key);
        int result = (memcmp(db_hash, derived_key, SHA256_DIGEST_LENGTH) == 0);
        sqlite3_finalize(stmt);
        return result;
    }
    sqlite3_finalize(stmt);
    return 0;
}

void log_activity(const char *nid, const char *activity) {
    char *log_sql = "INSERT INTO audit_logs (nid, timestamp, activity_type) VALUES (?,?,?);";
    sqlite3_stmt *log_stmt;
    if(sqlite3_prepare_v2(db, log_sql, -1, &log_stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(log_stmt, 1, nid, -1, SQLITE_STATIC);
        sqlite3_bind_int64(log_stmt, 2, (sqlite3_int64)time(NULL));
        sqlite3_bind_text(log_stmt, 3, activity, -1, SQLITE_STATIC);
        sqlite3_step(log_stmt);
        sqlite3_finalize(log_stmt);
    }
}

void apply_css() {
    GtkCssProvider *provider = gtk_css_provider_new();

    const char *css =
        /* Main window */
        "window {"
        "  background: linear-gradient(135deg, #006a4e, #009b77, #f42a41);"
        "}"

        /* Labels */
        "label {"
        "  color: white;"
        "  font-size: 14px;"
        "  font-weight: bold;"
        "}"

        /* Title labels */
        "label.title {"
        "  font-size: 24px;"
        "  color: #ffffff;"
        "}"

        /* Frames / cards */
        "frame {"
        "  background: rgba(255,255,255,0.12);"
        "  border-radius: 18px;"
        "  border: 2px solid rgba(255,255,255,0.20);"
        "  padding: 15px;"
        "}"

        /* Entry boxes */
        "entry {"
        "  background: rgba(255,255,255,0.95);"
        "  color: #111111;"
        "  border-radius: 10px;"
        "  padding: 10px;"
        "  border: 2px solid #dddddd;"
        "}"

        "entry:focus {"
        "  border: 2px solid #f42a41;"
        "}"

        /* Buttons */
        "button {"
        "  background: linear-gradient(to right, #006a4e, #009b77);"
        "  color: white;"
        "  border-radius: 12px;"
        "  border: none;"
        "  padding: 12px;"
        "  font-size: 14px;"
        "  font-weight: bold;"
        "}"

        /* Hover effect */
        "button:hover {"
        "  background: linear-gradient(to right, #f42a41, #ff5e6c);"
        "}"

        /* Press effect */
        "button:active {"
        "  background: #c91d32;"
        "}";

    gtk_css_provider_load_from_data(provider, css, -1, NULL);

    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_USER
    );

    g_object_unref(provider);
}

// GTK UTILITY FUNCTIONS
void show_message(GtkWidget *parent, const char *title, const char *message, GtkMessageType type) {
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(parent),
                                               GTK_DIALOG_DESTROY_WITH_PARENT,
                                               type,
                                               GTK_BUTTONS_OK,
                                               "%s", message);
    gtk_window_set_title(GTK_WINDOW(dialog), title);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// LOGIN WINDOW 
static void on_login_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget **entries = (GtkWidget **)data;
    const char *username = gtk_entry_get_text(GTK_ENTRY(entries[0]));
    const char *password = gtk_entry_get_text(GTK_ENTRY(entries[1]));

    if(authenticate_user(username, password)) {
        gtk_widget_hide(login_window);
        gtk_widget_show_all(dashboard_window);
    } else {
        show_message(login_window, "Login Failed", "Invalid username or password!", GTK_MESSAGE_ERROR);
    }
}

static void on_exit_clicked(GtkWidget *widget, gpointer data) {
    gtk_main_quit();
}

GtkWidget* create_login_window() {
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "National ID Management System - Login");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER(window), 20);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Title
    GtkWidget *title = gtk_label_new("National ID Management System");

    GtkStyleContext *context =
        gtk_widget_get_style_context(title);

    gtk_style_context_add_class(context, "title");
    gtk_box_pack_start(GTK_BOX(vbox), title, FALSE, FALSE, 10);

    GtkWidget *subtitle = gtk_label_new("Secure Government Database");
    gtk_box_pack_start(GTK_BOX(vbox), subtitle, FALSE, FALSE, 5);

    // Frame for login
    GtkWidget *frame = gtk_frame_new("Admin Login");
    gtk_box_pack_start(GTK_BOX(vbox), frame, TRUE, TRUE, 10);

    GtkWidget *frame_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(frame_box), 15);
    gtk_container_add(GTK_CONTAINER(frame), frame_box);

    // Username
    GtkWidget *hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(frame_box), hbox1, FALSE, FALSE, 0);
    GtkWidget *user_label = gtk_label_new("Username:");
    gtk_widget_set_size_request(user_label, 100, -1);
    gtk_box_pack_start(GTK_BOX(hbox1), user_label, FALSE, FALSE, 0);
    GtkWidget *user_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(user_entry), "Enter username");
    gtk_box_pack_start(GTK_BOX(hbox1), user_entry, TRUE, TRUE, 0);

    // Password
    GtkWidget *hbox2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(frame_box), hbox2, FALSE, FALSE, 0);
    GtkWidget *pass_label = gtk_label_new("Password:");
    gtk_widget_set_size_request(pass_label, 100, -1);
    gtk_box_pack_start(GTK_BOX(hbox2), pass_label, FALSE, FALSE, 0);
    GtkWidget *pass_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(pass_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(pass_entry), "Enter password");
    gtk_box_pack_start(GTK_BOX(hbox2), pass_entry, TRUE, TRUE, 0);

    // Buttons
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(frame_box), btn_box, FALSE, FALSE, 10);
    
    GtkWidget *login_btn = gtk_button_new_with_label("Login");
    GtkWidget *exit_btn = gtk_button_new_with_label("Exit");
    gtk_widget_set_size_request(login_btn, 100, 40);
    gtk_widget_set_size_request(exit_btn, 100, 40);
    
    gtk_box_pack_start(GTK_BOX(btn_box), login_btn, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), exit_btn, TRUE, TRUE, 0);

    static GtkWidget *entries[2];
    entries[0] = user_entry;
    entries[1] = pass_entry;
    
    g_signal_connect(login_btn, "clicked", G_CALLBACK(on_login_clicked), entries);
    g_signal_connect(exit_btn, "clicked", G_CALLBACK(on_exit_clicked), NULL);

    // Footer
    GtkWidget *footer = gtk_label_new("© Government of Bangladesh | Linux Secure Edition");
    gtk_box_pack_end(GTK_BOX(vbox), footer, FALSE, FALSE, 10);

    return window;
}

//   DASHBOARD WINDOW  
static void on_logout_clicked(GtkWidget *widget, gpointer data) {
    gtk_widget_hide(dashboard_window);
    gtk_widget_show_all(login_window);
}

static void on_register_clicked(GtkWidget *widget, gpointer data);
static void on_view_clicked(GtkWidget *widget, gpointer data);
static void on_search_clicked(GtkWidget *widget, gpointer data);
static void on_update_clicked(GtkWidget *widget, gpointer data);
static void on_delete_clicked(GtkWidget *widget, gpointer data);
static void on_audit_clicked(GtkWidget *widget, gpointer data);
static void on_nid_guide_clicked(GtkWidget *widget, gpointer data);
static void on_qr_verify_clicked(GtkWidget *widget, gpointer data);

GtkWidget* create_dashboard_window() {
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Admin Dashboard - NID System");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 500);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER(window), 20);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Header
    GtkWidget *header = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(header), 
        "<span font='16' weight='bold'>Admin Control Panel</span>");
    gtk_box_pack_start(GTK_BOX(vbox), header, FALSE, FALSE, 10);

    GtkWidget *desc = gtk_label_new("National ID Database Management");
    gtk_box_pack_start(GTK_BOX(vbox), desc, FALSE, FALSE, 5);

    // Grid of buttons
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), grid, TRUE, TRUE, 10);

    GtkWidget *btn_register = gtk_button_new_with_label("Register Citizen");
    GtkWidget *btn_view = gtk_button_new_with_label("View All Citizens");
    GtkWidget *btn_search = gtk_button_new_with_label("Search Citizen");
    GtkWidget *btn_update = gtk_button_new_with_label("Update Citizen");
    GtkWidget *btn_delete = gtk_button_new_with_label("Delete Citizen");
    GtkWidget *btn_audit = gtk_button_new_with_label("View Audit Logs");
    GtkWidget *btn_nid_guide = gtk_button_new_with_label("NID Application Guide");
    GtkWidget *btn_qr_verify = gtk_button_new_with_label("QR Verification");
    GtkWidget *btn_logout = gtk_button_new_with_label("Logout");

    gtk_widget_set_size_request(btn_register, 150, 60);
    gtk_widget_set_size_request(btn_view, 150, 60);
    gtk_widget_set_size_request(btn_search, 150, 60);
    gtk_widget_set_size_request(btn_update, 150, 60);
    gtk_widget_set_size_request(btn_delete, 150, 60);
    gtk_widget_set_size_request(btn_audit, 150, 60);
    gtk_widget_set_size_request(btn_nid_guide, 150, 60);
    gtk_widget_set_size_request(btn_qr_verify, 150, 60);
    gtk_widget_set_size_request(btn_logout, 150, 60);

    gtk_grid_attach(GTK_GRID(grid), btn_register, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_view, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_search, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_update, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_delete, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_audit, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_register, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_view, 1, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), btn_search, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_update, 1, 1, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), btn_delete, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_audit, 1, 2, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), btn_nid_guide, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_qr_verify, 1, 3, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), btn_logout, 0, 4, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), btn_logout, 0, 3, 2, 1);

    g_signal_connect(btn_register, "clicked", G_CALLBACK(on_register_clicked), window);
    g_signal_connect(btn_view, "clicked", G_CALLBACK(on_view_clicked), window);
    g_signal_connect(btn_search, "clicked", G_CALLBACK(on_search_clicked), window);
    g_signal_connect(btn_update, "clicked", G_CALLBACK(on_update_clicked), window);
    g_signal_connect(btn_delete, "clicked", G_CALLBACK(on_delete_clicked), window);
    g_signal_connect(btn_audit, "clicked", G_CALLBACK(on_audit_clicked), window);
    g_signal_connect(btn_nid_guide, "clicked", G_CALLBACK(on_nid_guide_clicked), window);
    g_signal_connect(btn_qr_verify, "clicked", G_CALLBACK(on_qr_verify_clicked), window);
    g_signal_connect(btn_logout, "clicked", G_CALLBACK(on_logout_clicked), NULL);

    return window;
}

//   REGISTER CITIZEN DIALOG  
static void on_register_save(GtkWidget *widget, gpointer data) {
    GtkWidget **entries = (GtkWidget **)data;
    
    Citizen citizen;
    memset(&citizen, 0, sizeof(Citizen));
    
    strncpy(citizen.name, gtk_entry_get_text(GTK_ENTRY(entries[0])), MAX_NAME-1);
    strncpy(citizen.dob, gtk_entry_get_text(GTK_ENTRY(entries[1])), 10);
    strncpy(citizen.gender, gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(entries[2])), 9);
    strncpy(citizen.address, gtk_entry_get_text(GTK_ENTRY(entries[3])), MAX_ADDRESS-1);
    strncpy(citizen.father_name, gtk_entry_get_text(GTK_ENTRY(entries[4])), MAX_NAME-1);
    strncpy(citizen.mother_name, gtk_entry_get_text(GTK_ENTRY(entries[5])), MAX_NAME-1);
    strncpy(citizen.blood_group, gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(entries[6])), 3);
    
    if(strlen(citizen.name) == 0 || strlen(citizen.dob) == 0 || strlen(citizen.address) == 0) {
        show_message(GTK_WIDGET(gtk_widget_get_toplevel(widget)), "Error", "Please fill all required fields!", GTK_MESSAGE_ERROR);
        return;
    }
    
    if(!validate_date(citizen.dob)) {
        show_message(GTK_WIDGET(gtk_widget_get_toplevel(widget)), "Error", "Invalid DOB! Use DD-MM-YYYY format (1900-2007).", GTK_MESSAGE_ERROR);
        return;
    }
    
    generate_unique_nid(citizen.nid);
    citizen.is_active = 1;
    citizen.created_at = time(NULL);
    citizen.last_modified = time(NULL);
    
    if(save_citizen(&citizen)) {
        log_activity(citizen.nid, "REGISTERED");
        char msg[256];
        snprintf(msg, sizeof(msg), "Citizen registered successfully!\nGenerated NID: %s", citizen.nid);
        show_message(GTK_WIDGET(gtk_widget_get_toplevel(widget)), "Success", msg, GTK_MESSAGE_INFO);
        
        // Clear entries
        for(int i = 0; i < 6; i++) {
            if(i != 2 && i != 6) gtk_entry_set_text(GTK_ENTRY(entries[i]), "");
        }
    } else {
        show_message(GTK_WIDGET(gtk_widget_get_toplevel(widget)), "Error", "Failed to register citizen!", GTK_MESSAGE_ERROR);
    }
}

static void on_register_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Register New Citizen",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 450, 500);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);
    
    const char *labels[] = {"Full Name:", "DOB (DD-MM-YYYY):", "Gender:", "Address:", 
                           "Father Name:", "Mother Name:", "Blood Group:"};
    GtkWidget *entries[7];
    
    for(int i = 0; i < 7; i++) {
        GtkWidget *label = gtk_label_new(labels[i]);
        gtk_widget_set_halign(label, GTK_ALIGN_START);
        gtk_grid_attach(GTK_GRID(grid), label, 0, i, 1, 1);
        
        if(i == 2) { // Gender combo
            entries[i] = gtk_combo_box_text_new();
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(entries[i]), "Male");
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(entries[i]), "Female");
            gtk_combo_box_set_active(GTK_COMBO_BOX(entries[i]), 0);
        } else if(i == 6) { // Blood group combo
            entries[i] = gtk_combo_box_text_new();
            const char *bgs[] = {"A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-", NULL};
            for(int j = 0; bgs[j]; j++) {
                gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(entries[i]), bgs[j]);
            }
            gtk_combo_box_set_active(GTK_COMBO_BOX(entries[i]), 0);
        } else {
            entries[i] = gtk_entry_new();
        }
        gtk_grid_attach(GTK_GRID(grid), entries[i], 1, i, 1, 1);
        gtk_widget_set_hexpand(entries[i], TRUE);
    }
    
    GtkWidget *save_btn = gtk_button_new_with_label("Save Citizen");
    gtk_widget_set_margin_top(save_btn, 15);
    gtk_grid_attach(GTK_GRID(grid), save_btn, 0, 7, 2, 1);
    
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_register_save), entries);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

//   VIEW CITIZENS  
static void on_view_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("All Registered Citizens",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 900, 500);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    // TreeView setup
    GtkListStore *store = gtk_list_store_new(10, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                              G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                              G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    
    GtkWidget *treeview = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    g_object_unref(store);
    
    const char *titles[] = {"NID", "Name", "DOB", "Gender", "Address", "Father", "Mother", "Blood", "Status", "Created"};
    for(int i = 0; i < 10; i++) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(titles[i], renderer, "text", i, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
    }
    
    // Fetch data
    char *sql = "SELECT * FROM citizens;";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        while(sqlite3_step(stmt) == SQLITE_ROW) {
            GtkTreeIter iter;
            gtk_list_store_append(store, &iter);
            const char *status = sqlite3_column_int(stmt, 8) ? "Active" : "Inactive";
            time_t created = (time_t)sqlite3_column_int64(stmt, 9);
            char created_str[26];
            strncpy(created_str, ctime(&created), 25);
            created_str[24] = '\0';
            
            gtk_list_store_set(store, &iter,
                0, sqlite3_column_text(stmt, 0),
                1, sqlite3_column_text(stmt, 1),
                2, sqlite3_column_text(stmt, 2),
                3, sqlite3_column_text(stmt, 3),
                4, sqlite3_column_text(stmt, 4),
                5, sqlite3_column_text(stmt, 5),
                6, sqlite3_column_text(stmt, 6),
                7, sqlite3_column_text(stmt, 7),
                8, status,
                9, created_str,
                -1);
        }
        sqlite3_finalize(stmt);
    }
    
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), treeview);
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 0);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

//   SEARCH CITIZEN  
static void on_search_execute(GtkWidget *widget, gpointer data) {
    GtkWidget *entry = GTK_WIDGET(data);
    const char *nid = gtk_entry_get_text(GTK_ENTRY(entry));
    
    char *sql = "SELECT * FROM citizens WHERE nid = ?;";
    sqlite3_stmt *stmt;
    
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, nid, -1, SQLITE_STATIC);
        
        if(sqlite3_step(stmt) == SQLITE_ROW) {
            Citizen c;
            strncpy(c.nid, (const char*)sqlite3_column_text(stmt, 0), 20);
            strncpy(c.name, (const char*)sqlite3_column_text(stmt, 1), MAX_NAME);
            strncpy(c.dob, (const char*)sqlite3_column_text(stmt, 2), 11);
            strncpy(c.gender, (const char*)sqlite3_column_text(stmt, 3), 10);
            strncpy(c.address, (const char*)sqlite3_column_text(stmt, 4), MAX_ADDRESS);
            strncpy(c.father_name, (const char*)sqlite3_column_text(stmt, 5), MAX_NAME);
            strncpy(c.mother_name, (const char*)sqlite3_column_text(stmt, 6), MAX_NAME);
            strncpy(c.blood_group, (const char*)sqlite3_column_text(stmt, 7), 4);
            c.is_active = sqlite3_column_int(stmt, 8);
            
            char msg[512];
            snprintf(msg, sizeof(msg), 
                "NID: %s\nName: %s\nDOB: %s\nGender: %s\nAddress: %s\nFather: %s\nMother: %s\nBlood: %s\nStatus: %s",
                c.nid, c.name, c.dob, c.gender, c.address, c.father_name, c.mother_name, c.blood_group,
                c.is_active ? "Active" : "Inactive");
            
            show_message(GTK_WIDGET(gtk_widget_get_toplevel(widget)), "Citizen Found", msg, GTK_MESSAGE_INFO);
            log_activity(nid, "SEARCHED");
        } else {
            show_message(GTK_WIDGET(gtk_widget_get_toplevel(widget)), "Not Found", "Citizen with this NID not found!", GTK_MESSAGE_WARNING);
        }
        sqlite3_finalize(stmt);
    }
}

static void on_search_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Search Citizen",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 150);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(content), hbox, TRUE, TRUE, 0);
    
    GtkWidget *label = gtk_label_new("Enter NID:");
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
    
    GtkWidget *search_btn = gtk_button_new_with_label("Search");
    gtk_box_pack_start(GTK_BOX(hbox), search_btn, FALSE, FALSE, 0);
    
    g_signal_connect(search_btn, "clicked", G_CALLBACK(on_search_execute), entry);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

//   UPDATE CITIZEN  
static void on_update_fetch(GtkWidget *widget, gpointer data);
static void on_update_save(GtkWidget *widget, gpointer data);

typedef struct {
    GtkWidget *dialog;
    GtkWidget *entries[10];
    char original_nid[20];
    int found;
} UpdateWidgets;

static void on_update_fetch(GtkWidget *widget, gpointer data) {
    UpdateWidgets *uw = (UpdateWidgets *)data;
    const char *nid = gtk_entry_get_text(GTK_ENTRY(uw->entries[0]));
    
    char *sql = "SELECT * FROM citizens WHERE nid = ?;";
    sqlite3_stmt *stmt;
    
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, nid, -1, SQLITE_STATIC);
        
        if(sqlite3_step(stmt) == SQLITE_ROW) {
            gtk_entry_set_text(GTK_ENTRY(uw->entries[1]), (const char*)sqlite3_column_text(stmt, 1));
            gtk_entry_set_text(GTK_ENTRY(uw->entries[2]), (const char*)sqlite3_column_text(stmt, 2));
            
            const char *gender = (const char*)sqlite3_column_text(stmt, 3);
            if(strcmp(gender, "Male") == 0) gtk_combo_box_set_active(GTK_COMBO_BOX(uw->entries[3]), 0);
            else gtk_combo_box_set_active(GTK_COMBO_BOX(uw->entries[3]), 1);
            
            gtk_entry_set_text(GTK_ENTRY(uw->entries[4]), (const char*)sqlite3_column_text(stmt, 4));
            gtk_entry_set_text(GTK_ENTRY(uw->entries[5]), (const char*)sqlite3_column_text(stmt, 5));
            gtk_entry_set_text(GTK_ENTRY(uw->entries[6]), (const char*)sqlite3_column_text(stmt, 6));
            
            const char *bg = (const char*)sqlite3_column_text(stmt, 7);
            const char *bgs[] = {"A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"};
            for(int i = 0; i < 8; i++) {
                if(strcmp(bg, bgs[i]) == 0) {
                    gtk_combo_box_set_active(GTK_COMBO_BOX(uw->entries[7]), i);
                    break;
                }
            }
            
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(uw->entries[8]), sqlite3_column_int(stmt, 8));
            
            strncpy(uw->original_nid, nid, 19);
            uw->found = 1;
            
            // Enable save button
            gtk_widget_set_sensitive(uw->entries[9], TRUE);
        } else {
            show_message(uw->dialog, "Not Found", "Citizen not found!", GTK_MESSAGE_WARNING);
            uw->found = 0;
        }
        sqlite3_finalize(stmt);
    }
}

static void on_update_save(GtkWidget *widget, gpointer data) {
    UpdateWidgets *uw = (UpdateWidgets *)data;
    
    if(!uw->found) {
        show_message(uw->dialog, "Error", "Please search for a valid citizen first!", GTK_MESSAGE_ERROR);
        return;
    }
    
    Citizen updated;
    memset(&updated, 0, sizeof(Citizen));
    
    strncpy(updated.name, gtk_entry_get_text(GTK_ENTRY(uw->entries[1])), MAX_NAME-1);
    strncpy(updated.dob, gtk_entry_get_text(GTK_ENTRY(uw->entries[2])), 10);
    strncpy(updated.gender, gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(uw->entries[3])), 9);
    strncpy(updated.address, gtk_entry_get_text(GTK_ENTRY(uw->entries[4])), MAX_ADDRESS-1);
    strncpy(updated.father_name, gtk_entry_get_text(GTK_ENTRY(uw->entries[5])), MAX_NAME-1);
    strncpy(updated.mother_name, gtk_entry_get_text(GTK_ENTRY(uw->entries[6])), MAX_NAME-1);
    strncpy(updated.blood_group, gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(uw->entries[7])), 3);
    updated.is_active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(uw->entries[8])) ? 1 : 0;
    updated.last_modified = time(NULL);
    
    if(update_citizen_db(&updated, uw->original_nid)) {
        show_message(uw->dialog, "Success", "Citizen updated successfully!", GTK_MESSAGE_INFO);
        log_activity(uw->original_nid, "UPDATED");
    } else {
        show_message(uw->dialog, "Error", "Failed to update citizen!", GTK_MESSAGE_ERROR);
    }
}

static void on_update_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Update Citizen",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 450, 550);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);
    
    UpdateWidgets *uw = g_malloc0(sizeof(UpdateWidgets));
    uw->dialog = dialog;
    uw->found = 0;
    
    // NID search row
    GtkWidget *nid_label = gtk_label_new("NID:");
    gtk_grid_attach(GTK_GRID(grid), nid_label, 0, 0, 1, 1);
    uw->entries[0] = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), uw->entries[0], 1, 0, 1, 1);
    GtkWidget *fetch_btn = gtk_button_new_with_label("Fetch");
    gtk_grid_attach(GTK_GRID(grid), fetch_btn, 2, 0, 1, 1);
    
    const char *labels[] = {"Full Name:", "DOB:", "Gender:", "Address:", 
                           "Father Name:", "Mother Name:", "Blood Group:", "Active:"};
    
    for(int i = 0; i < 8; i++) {
        GtkWidget *label = gtk_label_new(labels[i]);
        gtk_widget_set_halign(label, GTK_ALIGN_START);
        gtk_grid_attach(GTK_GRID(grid), label, 0, i+1, 1, 1);
        
        if(i == 2) { // Gender
            uw->entries[i+1] = gtk_combo_box_text_new();
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(uw->entries[i+1]), "Male");
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(uw->entries[i+1]), "Female");
            gtk_combo_box_set_active(GTK_COMBO_BOX(uw->entries[i+1]), 0);
        } else if(i == 6) { // Blood
            uw->entries[i+1] = gtk_combo_box_text_new();
            const char *bgs[] = {"A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-", NULL};
            for(int j = 0; bgs[j]; j++) {
                gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(uw->entries[i+1]), bgs[j]);
            }
            gtk_combo_box_set_active(GTK_COMBO_BOX(uw->entries[i+1]), 0);
        } else if(i == 7) { // Active checkbox
            uw->entries[i+1] = gtk_check_button_new_with_label("Citizen is active");
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(uw->entries[i+1]), TRUE);
        } else {
            uw->entries[i+1] = gtk_entry_new();
        }
        gtk_grid_attach(GTK_GRID(grid), uw->entries[i+1], 1, i+1, 2, 1);
    }
    
    GtkWidget *save_btn = gtk_button_new_with_label("Update Citizen");
    gtk_widget_set_sensitive(save_btn, FALSE);
    gtk_widget_set_margin_top(save_btn, 15);
    gtk_grid_attach(GTK_GRID(grid), save_btn, 0, 9, 3, 1);
    uw->entries[9] = save_btn;
    
    g_signal_connect(fetch_btn, "clicked", G_CALLBACK(on_update_fetch), uw);
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_update_save), uw);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    g_free(uw);
    gtk_widget_destroy(dialog);
}

//   DELETE CITIZEN  
static void on_delete_confirm(GtkWidget *widget, gpointer data) {
    GtkWidget **widgets = (GtkWidget **)data;
    const char *nid = gtk_entry_get_text(GTK_ENTRY(widgets[0]));
    GtkWidget *dialog = widgets[1];
    
    if(strlen(nid) == 0) {
        show_message(dialog, "Error", "Please enter an NID!", GTK_MESSAGE_ERROR);
        return;
    }
    
    GtkWidget *confirm = gtk_message_dialog_new(GTK_WINDOW(dialog),
                                                GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                GTK_MESSAGE_QUESTION,
                                                GTK_BUTTONS_YES_NO,
                                                "Are you sure you want to delete citizen with NID: %s?", nid);
    int resp = gtk_dialog_run(GTK_DIALOG(confirm));
    gtk_widget_destroy(confirm);
    
    if(resp == GTK_RESPONSE_YES) {
        if(delete_citizen_db(nid)) {
            show_message(dialog, "Success", "Citizen deleted successfully!", GTK_MESSAGE_INFO);
            log_activity(nid, "DELETED");
            gtk_entry_set_text(GTK_ENTRY(widgets[0]), "");
        } else {
            show_message(dialog, "Error", "Failed to delete citizen!", GTK_MESSAGE_ERROR);
        }
    }
}

static void on_delete_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Delete Citizen",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 150);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(content), hbox, TRUE, TRUE, 0);
    
    GtkWidget *label = gtk_label_new("Enter NID to delete:");
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
    
    GtkWidget *del_btn = gtk_button_new_with_label("Delete");
    gtk_box_pack_start(GTK_BOX(hbox), del_btn, FALSE, FALSE, 0);
    
    static GtkWidget *widgets[2];
    widgets[0] = entry;
    widgets[1] = dialog;
    g_signal_connect(del_btn, "clicked", G_CALLBACK(on_delete_confirm), widgets);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

//   AUDIT LOGS  
static void on_audit_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Audit Logs",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 700, 500);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    GtkListStore *store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    GtkWidget *treeview = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    g_object_unref(store);
    
    const char *titles[] = {"NID", "Activity", "Timestamp"};
    for(int i = 0; i < 3; i++) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(titles[i], renderer, "text", i, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
    }
    
    char *sql = "SELECT nid, timestamp, activity_type FROM audit_logs ORDER BY timestamp DESC;";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        while(sqlite3_step(stmt) == SQLITE_ROW) {
            GtkTreeIter iter;
            gtk_list_store_append(store, &iter);
            time_t ts = (time_t)sqlite3_column_int64(stmt, 1);
            char ts_str[26];
            strncpy(ts_str, ctime(&ts), 25);
            ts_str[24] = '\0';
            
            gtk_list_store_set(store, &iter,
                0, sqlite3_column_text(stmt, 0),
                1, sqlite3_column_text(stmt, 2),
                2, ts_str,
                -1);
        }
        sqlite3_finalize(stmt);
    }
    
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), treeview);
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 0);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}
//   NID APPLICATION GUIDE
static void on_nid_guide_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("নতুন NID আবেদন নির্দেশিকা",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);

    gtk_window_set_default_size(GTK_WINDOW(dialog), 600, 500);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 0);

    GtkWidget *label = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_label_set_yalign(GTK_LABEL(label), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);

    const char *guide_text =
        "নতুন জাতীয় পরিচয়পত্র (NID) আবেদন করার জন্য প্রয়োজনীয় তথ্য ও ডকুমেন্টঃ\n\n"

        "১। আবেদনকারীর পূর্ণ নাম\n"
        "২। জন্ম তারিখ\n"
        "৩। পিতা ও মাতার নাম\n"
        "৪। বর্তমান ঠিকানা\n"
        "৫। স্থায়ী ঠিকানা\n"
        "৬। জন্ম নিবন্ধন সনদ নম্বর\n"
        "৭। মোবাইল নম্বর\n"
        "৮। রক্তের গ্রুপ (যদি জানা থাকে)\n"
        "৯। শিক্ষাগত তথ্য (যদি থাকে)\n"
        "১০। নাগরিকত্ব সংক্রান্ত তথ্য\n\n"

        "প্রয়োজনীয় ডকুমেন্টঃ\n\n"
        "• জন্ম নিবন্ধন সনদ\n"
        "• পিতা/মাতার NID কপি\n"
        "• শিক্ষাগত সনদ (যদি থাকে)\n"
        "• ঠিকানার প্রমাণপত্র\n"
        "• পাসপোর্ট সাইজের ছবি\n\n"

        "বায়োমেট্রিক তথ্যঃ\n\n"
        "• আবেদনকারীর ছবি\n"
        "• আঙুলের ছাপ\n"
        "• স্বাক্ষর\n\n"

        "যোগ্যতাঃ\n\n"
        "• আবেদনকারীর বয়স ১৮ বছর বা তার বেশি হতে হবে।\n"
        "• সঠিক ও বৈধ তথ্য প্রদান করতে হবে।\n"
        "• ভুল বা ভুয়া তথ্য দিলে আবেদন বাতিল হতে পারে।\n\n"

        "নোটঃ\n"
        "NID আবেদন করার আগে সকল তথ্য ও ডকুমেন্ট সঠিকভাবে প্রস্তুত রাখা উচিত।";

    gtk_label_set_text(GTK_LABEL(label), guide_text);

    gtk_container_add(GTK_CONTAINER(scroll), label);

    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}


//   QR VERIFICATION SYSTEM
static void on_qr_generate_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget **widgets = (GtkWidget **)data;
    GtkWidget *entry = widgets[0];
    GtkWidget *dialog = widgets[1];

    const char *nid = gtk_entry_get_text(GTK_ENTRY(entry));

    if(strlen(nid) == 0) {
        show_message(dialog, "Error", "Please enter an NID!", GTK_MESSAGE_ERROR);
        return;
    }

    char *sql = "SELECT nid, name, dob, gender, blood_group, is_active FROM citizens WHERE nid = ?;";
    sqlite3_stmt *stmt;

    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        show_message(dialog, "Error", "Database error!", GTK_MESSAGE_ERROR);
        return;
    }

    sqlite3_bind_text(stmt, 1, nid, -1, SQLITE_STATIC);

    if(sqlite3_step(stmt) == SQLITE_ROW) {
        const char *db_nid = (const char*)sqlite3_column_text(stmt, 0);
        const char *name = (const char*)sqlite3_column_text(stmt, 1);
        const char *dob = (const char*)sqlite3_column_text(stmt, 2);
        const char *gender = (const char*)sqlite3_column_text(stmt, 3);
        const char *blood = (const char*)sqlite3_column_text(stmt, 4);
        int active = sqlite3_column_int(stmt, 5);

        char qr_text[512];

        snprintf(qr_text, sizeof(qr_text),
                 "National ID Verification\n"
                 "NID: %s\n"
                 "Name: %s\n"
                 "DOB: %s\n"
                 "Gender: %s\n"
                 "Blood Group: %s\n"
                 "Status: %s\n"
                 "Verified By: NID Management System",
                 db_nid, name, dob, gender, blood,
                 active ? "Active" : "Inactive");

        QRcode *qr = QRcode_encodeString(qr_text, 0, QR_ECLEVEL_Q, QR_MODE_8, 1);

        if(qr == NULL) {
            show_message(dialog, "Error", "Failed to generate QR code!", GTK_MESSAGE_ERROR);
            sqlite3_finalize(stmt);
            return;
        }

        int scale = 8;
        int size = qr->width * scale;

        GdkPixbuf *pixbuf = gdk_pixbuf_new(GDK_COLORSPACE_RGB, FALSE, 8, size, size);
        int rowstride = gdk_pixbuf_get_rowstride(pixbuf);
        guchar *pixels = gdk_pixbuf_get_pixels(pixbuf);

        for(int y = 0; y < size; y++) {
            for(int x = 0; x < size; x++) {
                int qr_x = x / scale;
                int qr_y = y / scale;
                int qr_index = qr_y * qr->width + qr_x;

                int color = (qr->data[qr_index] & 1) ? 0 : 255;

                guchar *p = pixels + y * rowstride + x * 3;
                p[0] = color;
                p[1] = color;
                p[2] = color;
            }
        }

        GtkWidget *qr_dialog = gtk_dialog_new_with_buttons("QR Verification Code",
                                                           GTK_WINDOW(dialog),
                                                           GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                           "Close", GTK_RESPONSE_CLOSE,
                                                           NULL);

        GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(qr_dialog));
        gtk_container_set_border_width(GTK_CONTAINER(content), 15);

        GtkWidget *info = gtk_label_new("মোবাইল দিয়ে QR code scan করলে citizen verification information দেখা যাবে।");
        gtk_box_pack_start(GTK_BOX(content), info, FALSE, FALSE, 10);

        GtkWidget *image = gtk_image_new_from_pixbuf(pixbuf);
        gtk_box_pack_start(GTK_BOX(content), image, TRUE, TRUE, 10);

        gtk_widget_show_all(qr_dialog);
        gtk_dialog_run(GTK_DIALOG(qr_dialog));
        gtk_widget_destroy(qr_dialog);

        g_object_unref(pixbuf);
        QRcode_free(qr);

        log_activity(db_nid, "QR GENERATED");

    } else {
        show_message(dialog, "Not Found", "Citizen with this NID not found!", GTK_MESSAGE_WARNING);
    }

    sqlite3_finalize(stmt);
}


static void on_qr_verify_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("QR Verification",
                                                    GTK_WINDOW(data),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Close", GTK_RESPONSE_CLOSE,
                                                    NULL);

    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 180);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(content), hbox, TRUE, TRUE, 0);

    GtkWidget *label = gtk_label_new("Enter NID:");
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    GtkWidget *entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);

    GtkWidget *qr_btn = gtk_button_new_with_label("Generate QR");
    gtk_box_pack_start(GTK_BOX(hbox), qr_btn, FALSE, FALSE, 0);

    static GtkWidget *widgets[2];
    widgets[0] = entry;
    widgets[1] = dialog;

    g_signal_connect(qr_btn, "clicked", G_CALLBACK(on_qr_generate_clicked), widgets);

    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}
//   MAIN  
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    
    apply_css();

    if(!init_db()) {
        fprintf(stderr, "Failed to initialize database!\n");
        return 1;
    }
    
    OpenSSL_add_all_algorithms();
    
    // Check/create admin
    char *check_admin = "SELECT COUNT(*) FROM users WHERE username = 'mdnaim';";
    sqlite3_stmt *stmt; 
    int admin_exists = 0; 
    if(sqlite3_prepare_v2(db, check_admin, -1, &stmt, 0) == SQLITE_OK) {
        if(sqlite3_step(stmt) == SQLITE_ROW) {
            admin_exists = sqlite3_column_int(stmt, 0); 
        } 
        sqlite3_finalize(stmt); 
    } 
    
    if(!admin_exists) {
        SystemUser admin; 
        strcpy(admin.username, "mdnaim");
        generate_salt(admin.salt);  
        derive_key("mdnaim2004@", admin.salt, admin.password_hash);
        admin.role = ADMIN;
        admin.failed_attempts = 0;
        admin.last_login = 0;
        char *insert_sql = "INSERT INTO users VALUES (?,?,?,?,?,?);";
        if(sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, admin.username, -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 2, admin.password_hash, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 3, admin.salt, SALT_LEN, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 4, admin.role);
            sqlite3_bind_int(stmt, 5, admin.failed_attempts);
            sqlite3_bind_int64(stmt, 6, admin.last_login);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    login_window = create_login_window();
    dashboard_window = create_dashboard_window();
    
    gtk_widget_show_all(login_window);
    gtk_main();
    
    sqlite3_close(db);
    EVP_cleanup();
    return 0;
}