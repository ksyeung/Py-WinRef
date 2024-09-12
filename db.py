import sqlite3
import pandas as pd
import configparser
import argparse
import os
import re
import csv

# General config functions

def print_config(config_file, config):
    print(f"{config_file} created with default values:")
    for section in config.sections():
        print(f"[{section}]")
        for key, value in config.items(section):
            print(f"{key} = {value}")
    if config.defaults():
        print("[DEFAULT]")
        for key, value in config.defaults().items():
            print(f"{key} = {value}")

def load_config(config_file, defaults):
    config = configparser.ConfigParser()
    if not os.path.exists(config_file):
        config['DEFAULT'] = defaults
        with open(config_file, 'w') as configfile:
            config.write(configfile)
        print_config(config_file, config)
    config.read(config_file)
    return config

def parse_args():
    parser = argparse.ArgumentParser(
        description="Process various CSV files into SQLite DB and optionally look up a hash."
    )
    parser.add_argument('--rds_path', type=str, help='Path to the RDS DB file')
    parser.add_argument('--vwr_path', type=str, help='Path to the Vanilla Windows reference CSV')
    parser.add_argument('--loldrivers_path', type=str, help='Path to the LOLDrivers CSV')
    parser.add_argument('--lolbas_path', type=str, help='Path to the LOLBas CSV')
    parser.add_argument('--autoruns_path', type=str, help='Path to the Autoruns CSV')
    parser.add_argument('--hash', type=str, help='Hash to look up in the database')
    parser.add_argument('--compare_autoruns', action='store_true', help='Compare Autoruns entries to loldrivers and vanilla windows reference tables')
    parser.add_argument('--autoruns_loldrivers_csv', type=str, help='Output CSV file for Autoruns entries matching LOLDrivers')
    parser.add_argument('--autoruns_not_in_vwr_csv', type=str, help='Output CSV file for Autoruns entries not in VanillaWindowsReference')
    parser.add_argument('--autoruns_not_in_file_csv', type=str, help='Output CSV file for Autoruns entries not in FILE table of RDS DB')
    return parser.parse_args()

def set_default_config():
    return {
        'rds_path': 'RDS_2024.03.1_modern_minimal.db',
        'vwr_path': 'W11_22H2_Pro_20230321_22621.1413.csv',
        'loldrivers_path': r'.\\LOLDrivers\\loldrivers.io\\content\\drivers_table.csv',
        'lolbas_path': 'lolbas.csv',
        'autoruns_path': ''
    }

def get_config_values(config, args):
    """Get values from config (or override with values from args)."""
    return {
        'rds_path': args.rds_path or config['DEFAULT']['rds_path'],
        'vwr_path': args.vwr_path or config['DEFAULT']['vwr_path'],
        'loldrivers_path': args.loldrivers_path or config['DEFAULT']['loldrivers_path'],
        'lolbas_path': args.lolbas_path or config['DEFAULT']['lolbas_path'],
        'autoruns_path': args.autoruns_path or config['DEFAULT']['autoruns_path']
    }

# DB-specific functions

def create_connection(db_file):
    try:
        return sqlite3.connect(db_file)
    except sqlite3.Error as e:
        print(f"Error connecting to {db_file}: {e}")
        return None

def create_table(conn, table_name, table_schema):
    try:
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({table_schema})")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating table {table_name}: {e}")

def insert_data_from_csv(conn, file, table_name, preprocess_func=None, has_header=True):
    """Insert data from a CSV file into a SQLite table."""
    try:
        # Read the CSV file, handling files with or without headers
        if has_header:
            df = pd.read_csv(file, header=0)
        else:
            df = pd.read_csv(file, header=None)
            # If no header, assign these column names (for LOLDrivers)
            df.columns = ['Driver_Name', 'SHA_256', 'Category', 'Date']

        if df.empty:
            print(f"No data found in {file}. Skipping insertion.")
            return

        df = clean_column_names(df)
        if preprocess_func:
            df = preprocess_func(df)
        if df.empty:
            print(f"Data is empty after preprocessing for {file}. Skipping.")
            return

        # Add a source_file column to track file source
        df['source_file'] = file

        # Insert the DataFrame into the SQLite table
        df.to_sql(table_name, conn, if_exists='append', index=False)
    except Exception as e:
        print(f"Error processing file {file}: {e}")

# Processing functions for different datasets

def process_table(db_file, csv_path, table_name, table_schema, preprocess_func=None, has_header=True):
    conn = create_connection(db_file)
    if conn:
        create_table(conn, table_name, table_schema)
        insert_data_from_csv(conn, csv_path, table_name, preprocess_func, has_header)
        conn.close()

def process_vanilla_windows_reference(db_file, csv_path):
    """Process the VanillaWindowsReference table."""
    table_schema = '''
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        DirectoryName TEXT,
        Name TEXT,
        FullName TEXT,
        Length INTEGER,
        CreationTimeUtc TIMESTAMP,
        LastAccessTimeUtc TIMESTAMP,
        LastWriteTimeUtc TIMESTAMP,
        Attributes TEXT,
        MD5 TEXT,
        SHA1 TEXT,
        SHA256 TEXT,
        Sddl TEXT,
        source_file TEXT
    '''
    process_table(db_file, csv_path, 'VanillaWindowsReference', table_schema)

def preprocess_loldrivers(df):
    """Parse the LOLDrivers data to extract Driver_Name and SHA_256 values."""
    df['Driver_Name'] = df['Driver_Name'].apply(lambda x: re.sub(r'\[|\]\(.*?\)', '', x))
    df['SHA_256'] = df['SHA_256'].apply(lambda x: re.sub(r'\[|\]\(.*?\)', '', x))
    return df

def process_loldrivers(db_file, csv_path, has_header=False):
    table_schema = '''
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        Driver_Name TEXT,
        SHA_256 TEXT,
        Category TEXT,
        Date TIMESTAMP,
        source_file TEXT
    '''
    process_table(db_file, csv_path, 'LOLDrivers', table_schema, preprocess_func=preprocess_loldrivers, has_header=has_header)

def process_autoruns(db_file, csv_path):
    table_schema = '''
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Time TIMESTAMP,
        Entry_Location TEXT,
        Entry TEXT,
        Enabled TEXT,
        Category TEXT,
        Profile TEXT,
        Description TEXT,
        Signer TEXT,
        Company TEXT,
        Image_Path TEXT,
        Version TEXT,
        Launch_String TEXT,
        MD5 TEXT,
        SHA_1 TEXT,
        PESHA_1 TEXT,
        PESHA_256 TEXT,
        SHA_256 TEXT,
        IMP TEXT,
        PS_Computer_Name TEXT,
        source_file TEXT
    '''
    process_table(db_file, csv_path, 'AutoRuns', table_schema)

def clean_column_names(df):
    """Clean column names to conform to SQLite's allowed charset."""
    df.columns = df.columns.str.replace(' ', '_', regex=True)
    df.columns = df.columns.str.replace('-', '_', regex=True)
    df.columns = df.columns.str.replace('&', '_', regex=True)
    return df

def process_lolbas(db_file, csv_path):
    table_schema = '''
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Filename TEXT,
        Description TEXT,
        Author TEXT,
        Date TIMESTAMP,
        Command TEXT,
        Command_Description TEXT,
        Command_Usecase TEXT,
        Command_Category TEXT,
        Command_Privileges TEXT,
        MITRE_ATT_CK_technique TEXT,
        Operating_System TEXT,
        Paths TEXT,
        Detections TEXT,
        Resources TEXT,
        Acknowledgements TEXT,
        URL TEXT,
        Tags TEXT,
        source_file TEXT
    '''
    process_table(db_file, csv_path, 'LOLBas', table_schema)

def index_exists(cursor, index_name):
    cursor.execute("PRAGMA index_list('FILE')")
    return any(index[1] == index_name for index in cursor.fetchall())

def create_indices(cursor):
    """Create indices for the FILE table in the RDS db."""
    indexes = ['sha256', 'sha1', 'md5']
    for idx in indexes:
        if not index_exists(cursor, f'idx_{idx}'):
            print(f"Creating index for {idx.upper()}...")
            cursor.execute(f"CREATE INDEX idx_{idx} ON FILE ({idx});")
        else:
            print(f"Index for {idx.upper()} column already exists.")

def process_all_tables(db_file, paths):
    process_vanilla_windows_reference(db_file, paths['vwr_path'])
    process_loldrivers(db_file, paths['loldrivers_path'])
    process_lolbas(db_file, paths['lolbas_path'])
    if paths['autoruns_path']:
        process_autoruns(db_file, paths['autoruns_path'])

def identify_hash_algorithm(hash_value):
    hash_length = len(hash_value)
    if hash_length == 32:
        return 'MD5'
    elif hash_length == 40:
        return 'SHA1'
    elif hash_length == 64:
        return 'SHA256'
    else:
        return None  # Invalid hash

def lookup_hash_in_db(conn, hash_value, db_name):
    """Search for the hash in the relevant tables in a chosen db."""
    found_records = {}

    hash_type = identify_hash_algorithm(hash_value)

    if not hash_type:
        print(f"Invalid length for hash: {hash_value}")
        return found_records

    # Only search in LOLDrivers and VanillaWindowsReference tables in the non-RDS db
    if db_name == 'winref.sqlite':
        # Search in LOLDrivers (SHA256 only)
        try:
            query = "SELECT * FROM LOLDrivers WHERE SHA_256 = ?"
            result = conn.execute(query, (hash_value,)).fetchall()
            if result:
                found_records['LOLDrivers'] = result
        except sqlite3.Error as e:
            print(f"Error searching in LOLDrivers in {db_name}: {e}")

        # Search in VanillaWindowsReference (SHA256, SHA1, MD5)
        try:
            query = """
                SELECT * FROM VanillaWindowsReference WHERE 
                SHA256 = ? OR SHA1 = ? OR MD5 = ?
            """
            result = conn.execute(query, (hash_value, hash_value, hash_value)).fetchall()
            if result:
                found_records['VanillaWindowsReference'] = result
        except sqlite3.Error as e:
            print(f"Error searching in VanillaWindowsReference in {db_name}: {e}")

    if db_name != 'winref.sqlite':
        try:
            query = """
                SELECT * FROM FILE WHERE 
                sha256 = ? OR sha1 = ? OR md5 = ?
            """
            result = conn.execute(query, (hash_value, hash_value, hash_value)).fetchall()
            if result:
                found_records['FILE'] = result
        except sqlite3.Error as e:
            print(f"Error searching in FILE in {db_name}: {e}")

    return found_records

def search_in_both_databases(rds_path, hash_value):
    """Search for the hash in both winref.sqlite and the db at rds_path."""
    found_records = {}

    winref_db = 'winref.sqlite'
    conn_winref = create_connection(winref_db)
    if conn_winref:
        found_in_winref = lookup_hash_in_db(conn_winref, hash_value, winref_db)
        found_records.update(found_in_winref)
        conn_winref.close()

    conn_rds = create_connection(rds_path)
    if conn_rds:
        found_in_rds = lookup_hash_in_db(conn_rds, hash_value, rds_path)
        found_records.update(found_in_rds)
        conn_rds.close()

    return found_records

def compare_autoruns_entries(db_file, rds_path, output_paths):
    """Compare AutoRuns entries to LOLDrivers and VWR tables."""
    conn_winref = create_connection(db_file)
    conn_rds = create_connection(rds_path)
    if not conn_winref or not conn_rds:
        print("Error connecting to databases.")
        return

    cursor_winref = conn_winref.cursor()
    cursor_rds = conn_rds.cursor()

    """ Get Autoruns entries where the Enabled value is 'enabled' and Image_Path \
        does not start with 'File not found:'"""
    query_autoruns = """
        SELECT * FROM AutoRuns
        WHERE LOWER(Enabled) = 'enabled' AND Image_Path NOT LIKE 'File not found:%'
    """
    cursor_winref.execute(query_autoruns)
    autoruns_entries = cursor_winref.fetchall()

    # Get column names for Autoruns table
    autoruns_columns = [description[0] for description in cursor_winref.description]

    # Lists to store results for CSV export
    autoruns_loldrivers_matches = []
    autoruns_not_in_vwr = []
    autoruns_not_in_file = []

    for entry in autoruns_entries:
        entry_dict = dict(zip(autoruns_columns, entry))
        hashes = {
            'MD5': entry_dict.get('MD5'),
            'SHA1': entry_dict.get('SHA_1'),
            'SHA256': entry_dict.get('SHA_256')
        }

        found_in_loldrivers = False
        # Check hashes in LOLDrivers table
        for hash_type, hash_value in hashes.items():
            if hash_value:
                query_loldrivers = "SELECT * FROM LOLDrivers WHERE SHA_256 = ?"
                cursor_winref.execute(query_loldrivers, (hash_value,))
                loldrivers_result = cursor_winref.fetchall()
                if loldrivers_result:
                    found_in_loldrivers = True
                    print(f"\nAutoruns entry matching LOLDrivers:")
                    print(f"Autoruns Entry: {entry_dict}")
                    print(f"Matching LOLDrivers Entries:")
                    loldrivers_columns = [desc[0] for desc in cursor_winref.description]
                    for loldriver in loldrivers_result:
                        loldriver_dict = dict(zip(loldrivers_columns, loldriver))
                        print(loldriver_dict)
                    # Store for CSV export
                    autoruns_loldrivers_matches.append({
                        'Autoruns Entry': entry_dict,
                        'Matching LOLDrivers Entries': [dict(zip(loldrivers_columns, lr)) for lr in loldrivers_result]
                    })
                    break  # Stop after first matching hash

        # If not found in LOLDrivers, check in the VWR table
        if not found_in_loldrivers:
            found_in_vwr = False
            for hash_type, hash_value in hashes.items():
                if hash_value:
                    query_vwr = f"SELECT * FROM VanillaWindowsReference WHERE {hash_type} = ?"
                    cursor_winref.execute(query_vwr, (hash_value,))
                    vwr_result = cursor_winref.fetchall()
                    if vwr_result:
                        found_in_vwr = True
                        break  # Stop after first found

            if not found_in_vwr:
                print(f"\nAutoruns entry with hashes not in VanillaWindowsReference:")
                print(f"Autoruns Entry: {entry_dict}")
                autoruns_not_in_vwr.append(entry_dict)

        # Check the FILE table of rds_path database
        found_in_file = False
        for hash_type, hash_value in hashes.items():
            if hash_value:
                query_file = f"SELECT * FROM FILE WHERE {hash_type.lower()} = ?"
                cursor_rds.execute(query_file, (hash_value,))
                file_result = cursor_rds.fetchall()
                if file_result:
                    found_in_file = True
                    break  # Stop after first found

        if not found_in_file:
            print(f"\nAutoruns entry with hashes not in FILE table of {rds_path}:")
            print(f"Autoruns Entry: {entry_dict}")
            autoruns_not_in_file.append(entry_dict)

    conn_winref.close()
    conn_rds.close()

    # Export results to CSV files
    if output_paths['autoruns_loldrivers_csv'] and autoruns_loldrivers_matches:
        with open(output_paths['autoruns_loldrivers_csv'], 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = autoruns_columns + ['Matching LOLDrivers Entries']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in autoruns_loldrivers_matches:
                row = item['Autoruns Entry']
                row['Matching LOLDrivers Entries'] = item['Matching LOLDrivers Entries']
                writer.writerow(row)

    if output_paths['autoruns_not_in_vwr_csv'] and autoruns_not_in_vwr:
        df_not_in_vwr = pd.DataFrame(autoruns_not_in_vwr)
        df_not_in_vwr.to_csv(output_paths['autoruns_not_in_vwr_csv'], index=False)

    if output_paths['autoruns_not_in_file_csv'] and autoruns_not_in_file:
        df_not_in_file = pd.DataFrame(autoruns_not_in_file)
        df_not_in_file.to_csv(output_paths['autoruns_not_in_file_csv'], index=False)

def main():
    """Main function to initialize the script."""
    config_file = 'conf.ini'
    config = load_config(config_file, set_default_config())
    args = parse_args()
    paths = get_config_values(config, args)

    db_file = 'winref.sqlite'
    process_all_tables(db_file, paths)

    if args.hash:
        hash_value = args.hash
        print(f"Looking up hash {hash_value} in both databases...")
        found_records = search_in_both_databases(paths['rds_path'], hash_value)

        if found_records:
            print(f"Hash {hash_value} found in the following tables:")
            for table, records in found_records.items():
                print(f"\nTable: {table}")
                for record in records:
                    print(record)
        else:
            print(f"Hash {hash_value} not found in any table.")
    else:
        conn = create_connection(paths['rds_path'])
        if conn:
            cursor = conn.cursor()
            create_indices(cursor)
            conn.commit()
            conn.close()

    if args.compare_autoruns:
        print("\nComparing Autoruns entries to loldrivers and vanilla windows reference tables...")
        output_paths = {
            'autoruns_loldrivers_csv': args.autoruns_loldrivers_csv,
            'autoruns_not_in_vwr_csv': args.autoruns_not_in_vwr_csv,
            'autoruns_not_in_file_csv': args.autoruns_not_in_file_csv
        }
        compare_autoruns_entries(db_file, paths['rds_path'], output_paths)

if __name__ == '__main__':
    main()
